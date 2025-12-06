using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace HotelWifiPortal.Services.WiFi
{
    /// <summary>
    /// MikroTik Authentication Methods:
    /// 1. Hotspot Login API - Direct login via MikroTik hotspot API
    /// 2. MAC Binding - Create IP binding with type=bypassed
    /// 3. Hotspot User - Create hotspot user then redirect
    /// 4. RADIUS - MikroTik queries RADIUS server (handled by RadiusServer)
    /// </summary>
    public class MikrotikAuthService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<MikrotikAuthService> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        
        public MikrotikAuthService(
            IServiceProvider serviceProvider,
            ILogger<MikrotikAuthService> logger,
            IHttpClientFactory httpClientFactory)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

        /// <summary>
        /// Get MikroTik settings from database
        /// </summary>
        public async Task<WifiControllerSettings?> GetMikrotikSettingsAsync()
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            
            return await dbContext.WifiControllerSettings
                .FirstOrDefaultAsync(s => s.ControllerType == "Mikrotik" && s.IsEnabled);
        }

        /// <summary>
        /// Method 1: Authenticate via MikroTik Hotspot Login API
        /// This is what happens when you POST to /login on MikroTik hotspot
        /// </summary>
        public async Task<MikrotikAuthResult> AuthenticateViaHotspotLoginAsync(
            string clientIp, 
            string macAddress, 
            string username, 
            string password,
            string? linkLogin = null)
        {
            var result = new MikrotikAuthResult { Method = "HotspotLogin" };
            
            try
            {
                var settings = await GetMikrotikSettingsAsync();
                if (settings == null)
                {
                    result.Success = false;
                    result.Error = "MikroTik not configured";
                    return result;
                }

                // MikroTik hotspot login endpoint
                var hotspotIp = settings.IpAddress;
                var loginUrl = linkLogin ?? $"http://{hotspotIp}/login";
                
                _logger.LogInformation("[MikroTik] Hotspot login attempt: User={User}, MAC={Mac}, IP={Ip}, URL={Url}", 
                    username, macAddress, clientIp, loginUrl);

                var handler = new HttpClientHandler
                {
                    AllowAutoRedirect = false,
                    ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
                };
                
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
                
                // POST form data to hotspot login
                var formData = new Dictionary<string, string>
                {
                    { "username", username },
                    { "password", password },
                    { "dst", "http://www.google.com" }
                };

                var content = new FormUrlEncodedContent(formData);
                var response = await client.PostAsync(loginUrl, content);

                _logger.LogInformation("[MikroTik] Hotspot login response: Status={Status}, Location={Location}", 
                    response.StatusCode, 
                    response.Headers.Location?.ToString() ?? "none");

                // MikroTik redirects to success page or original URL on success
                if (response.StatusCode == HttpStatusCode.Redirect || 
                    response.StatusCode == HttpStatusCode.Found ||
                    response.StatusCode == HttpStatusCode.OK)
                {
                    var location = response.Headers.Location?.ToString() ?? "";
                    
                    if (location.Contains("status") || location.Contains("dst") || 
                        !location.Contains("error") && !location.Contains("login"))
                    {
                        result.Success = true;
                        result.RedirectUrl = location;
                        _logger.LogInformation("[MikroTik] Hotspot login SUCCESS for {User}", username);
                    }
                    else
                    {
                        result.Success = false;
                        result.Error = "Login rejected by hotspot";
                        _logger.LogWarning("[MikroTik] Hotspot login REJECTED: {Location}", location);
                    }
                }
                else
                {
                    result.Success = false;
                    result.Error = $"Unexpected response: {response.StatusCode}";
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                _logger.LogError(ex, "[MikroTik] Hotspot login ERROR");
            }

            return result;
        }

        /// <summary>
        /// Method 2: Create MAC binding to bypass hotspot authentication
        /// This grants immediate internet access without hotspot login
        /// </summary>
        public async Task<MikrotikAuthResult> AuthenticateViaMacBindingAsync(
            string clientIp,
            string macAddress,
            string comment)
        {
            var result = new MikrotikAuthResult { Method = "MacBinding" };
            
            try
            {
                var settings = await GetMikrotikSettingsAsync();
                if (settings == null)
                {
                    result.Success = false;
                    result.Error = "MikroTik not configured";
                    return result;
                }

                _logger.LogInformation("[MikroTik] Creating MAC binding: MAC={Mac}, IP={Ip}", macAddress, clientIp);

                var client = CreateApiClient(settings);
                var baseUrl = GetBaseUrl(settings);
                
                // First, remove any existing binding for this MAC
                await RemoveExistingBindingAsync(client, baseUrl, macAddress);

                // Create new IP binding with type=bypassed
                var binding = new
                {
                    mac_address = macAddress.Replace(":", "-").ToUpper(),
                    type = "bypassed",
                    comment = comment,
                    address = clientIp // Optional: bind to specific IP
                };

                var json = JsonSerializer.Serialize(binding);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var response = await client.PutAsync($"{baseUrl}/rest/ip/hotspot/ip-binding", content);
                var responseBody = await response.Content.ReadAsStringAsync();
                
                _logger.LogInformation("[MikroTik] MAC binding response: Status={Status}, Body={Body}", 
                    response.StatusCode, responseBody);

                if (response.IsSuccessStatusCode)
                {
                    result.Success = true;
                    result.Message = "MAC binding created - internet access granted";
                    _logger.LogInformation("[MikroTik] MAC binding SUCCESS for {Mac}", macAddress);
                }
                else
                {
                    result.Success = false;
                    result.Error = $"Failed to create binding: {responseBody}";
                    _logger.LogWarning("[MikroTik] MAC binding FAILED: {Error}", responseBody);
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                _logger.LogError(ex, "[MikroTik] MAC binding ERROR");
            }

            return result;
        }

        /// <summary>
        /// Method 3: Create hotspot user then authenticate
        /// </summary>
        public async Task<MikrotikAuthResult> AuthenticateViaHotspotUserAsync(
            string clientIp,
            string macAddress,
            string username,
            string password,
            int? downloadLimit = null,
            int? uploadLimit = null,
            long? quotaBytes = null)
        {
            var result = new MikrotikAuthResult { Method = "HotspotUser" };
            
            try
            {
                var settings = await GetMikrotikSettingsAsync();
                if (settings == null)
                {
                    result.Success = false;
                    result.Error = "MikroTik not configured";
                    return result;
                }

                _logger.LogInformation("[MikroTik] Creating hotspot user: User={User}, MAC={Mac}", username, macAddress);

                var client = CreateApiClient(settings);
                var baseUrl = GetBaseUrl(settings);

                // Remove existing user if exists
                await RemoveExistingUserAsync(client, baseUrl, username);

                // Build rate limit string if provided
                string? rateLimit = null;
                if (downloadLimit.HasValue && uploadLimit.HasValue)
                {
                    rateLimit = $"{uploadLimit}k/{downloadLimit}k";
                }

                // Create hotspot user
                var user = new Dictionary<string, object>
                {
                    { "name", username },
                    { "password", password },
                    { "mac-address", macAddress.Replace(":", "-").ToUpper() },
                    { "comment", $"Guest - Created {DateTime.UtcNow:yyyy-MM-dd HH:mm}" }
                };

                if (!string.IsNullOrEmpty(rateLimit))
                {
                    user["limit-bytes-total"] = quotaBytes ?? 0;
                    // Rate limit is set via user profile or queue
                }

                var json = JsonSerializer.Serialize(user);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var response = await client.PutAsync($"{baseUrl}/rest/ip/hotspot/user", content);
                var responseBody = await response.Content.ReadAsStringAsync();
                
                _logger.LogInformation("[MikroTik] Hotspot user response: Status={Status}", response.StatusCode);

                if (response.IsSuccessStatusCode)
                {
                    result.Success = true;
                    result.Username = username;
                    result.Password = password;
                    result.Message = "Hotspot user created";
                    
                    // Generate login URL for redirect
                    result.RedirectUrl = $"http://{settings.IpAddress}/login?username={Uri.EscapeDataString(username)}&password={Uri.EscapeDataString(password)}";
                    
                    _logger.LogInformation("[MikroTik] Hotspot user SUCCESS: {User}", username);
                }
                else
                {
                    result.Success = false;
                    result.Error = $"Failed to create user: {responseBody}";
                    _logger.LogWarning("[MikroTik] Hotspot user FAILED: {Error}", responseBody);
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                _logger.LogError(ex, "[MikroTik] Hotspot user ERROR");
            }

            return result;
        }

        /// <summary>
        /// Method 4: RADIUS mode - just verify settings, actual auth handled by RADIUS server
        /// </summary>
        public async Task<MikrotikAuthResult> PrepareForRadiusAuthAsync(
            string macAddress,
            string username,
            Guest guest)
        {
            var result = new MikrotikAuthResult { Method = "RADIUS" };
            
            try
            {
                _logger.LogInformation("[MikroTik-RADIUS] Preparing RADIUS auth: User={User}, MAC={Mac}", username, macAddress);

                // In RADIUS mode, MikroTik handles the authentication
                // Our RADIUS server (RadiusServer.cs) will respond to the request
                // Here we just return success and let the normal flow continue
                
                result.Success = true;
                result.Username = username;
                result.Message = "RADIUS authentication prepared - MikroTik will query RADIUS server";
                
                // The redirect URL should go back to MikroTik hotspot
                var settings = await GetMikrotikSettingsAsync();
                if (settings != null)
                {
                    result.RedirectUrl = $"http://{settings.IpAddress}/login";
                }
                
                _logger.LogInformation("[MikroTik-RADIUS] Ready for RADIUS auth: {User}", username);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                _logger.LogError(ex, "[MikroTik-RADIUS] Preparation ERROR");
            }

            return result;
        }

        /// <summary>
        /// Comprehensive authentication that tries multiple methods
        /// </summary>
        public async Task<MikrotikAuthResult> AuthenticateGuestAsync(
            Guest guest,
            string clientIp,
            string macAddress,
            string? linkLogin = null,
            string? preferredMethod = null)
        {
            var username = guest.RoomNumber;
            var password = guest.ReservationNumber;
            
            _logger.LogInformation("[MikroTik] === Starting authentication ===");
            _logger.LogInformation("[MikroTik] Guest: Room={Room}, Name={Name}", guest.RoomNumber, guest.GuestName);
            _logger.LogInformation("[MikroTik] Client: IP={Ip}, MAC={Mac}", clientIp, macAddress);
            _logger.LogInformation("[MikroTik] Preferred Method: {Method}", preferredMethod ?? "auto");

            // Get bandwidth profile
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            
            var profile = await dbContext.BandwidthProfiles
                .FirstOrDefaultAsync(p => p.IsActive && p.IsDefault);
            
            int? downloadKbps = profile?.DownloadSpeedKbps;
            int? uploadKbps = profile?.UploadSpeedKbps;
            long? quotaBytes = guest.TotalQuotaBytes - guest.UsedQuotaBytes;

            MikrotikAuthResult result;

            // Try methods in order of preference
            var methods = GetAuthMethodOrder(preferredMethod);
            
            foreach (var method in methods)
            {
                _logger.LogInformation("[MikroTik] Trying method: {Method}", method);
                
                result = method switch
                {
                    "MacBinding" => await AuthenticateViaMacBindingAsync(clientIp, macAddress, $"Room {guest.RoomNumber} - {guest.GuestName}"),
                    "HotspotUser" => await AuthenticateViaHotspotUserAsync(clientIp, macAddress, username, password, downloadKbps, uploadKbps, quotaBytes),
                    "HotspotLogin" => await AuthenticateViaHotspotLoginAsync(clientIp, macAddress, username, password, linkLogin),
                    "RADIUS" => await PrepareForRadiusAuthAsync(macAddress, username, guest),
                    _ => new MikrotikAuthResult { Success = false, Error = $"Unknown method: {method}" }
                };

                if (result.Success)
                {
                    _logger.LogInformation("[MikroTik] === Authentication SUCCESS via {Method} ===", method);
                    return result;
                }
                
                _logger.LogWarning("[MikroTik] Method {Method} failed: {Error}", method, result.Error);
            }

            // All methods failed
            _logger.LogError("[MikroTik] === All authentication methods FAILED ===");
            return new MikrotikAuthResult
            {
                Success = false,
                Error = "All authentication methods failed",
                Method = "None"
            };
        }

        /// <summary>
        /// Remove user from hotspot (on checkout)
        /// </summary>
        public async Task<bool> RemoveGuestAsync(string macAddress, string? username = null)
        {
            try
            {
                var settings = await GetMikrotikSettingsAsync();
                if (settings == null) return false;

                var client = CreateApiClient(settings);
                var baseUrl = GetBaseUrl(settings);

                _logger.LogInformation("[MikroTik] Removing guest: MAC={Mac}, User={User}", macAddress, username);

                // Remove MAC binding
                await RemoveExistingBindingAsync(client, baseUrl, macAddress);

                // Remove hotspot user if username provided
                if (!string.IsNullOrEmpty(username))
                {
                    await RemoveExistingUserAsync(client, baseUrl, username);
                }

                // Disconnect active session
                await DisconnectActiveSessionAsync(client, baseUrl, macAddress);

                _logger.LogInformation("[MikroTik] Guest removed: {Mac}", macAddress);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[MikroTik] Error removing guest");
                return false;
            }
        }

        #region Private Helpers

        private List<string> GetAuthMethodOrder(string? preferredMethod)
        {
            var methods = new List<string> { "MacBinding", "HotspotUser", "HotspotLogin", "RADIUS" };
            
            if (!string.IsNullOrEmpty(preferredMethod) && methods.Contains(preferredMethod))
            {
                methods.Remove(preferredMethod);
                methods.Insert(0, preferredMethod);
            }
            
            return methods;
        }

        private HttpClient CreateApiClient(WifiControllerSettings settings)
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => 
                    settings.IgnoreSslErrors || errors == System.Net.Security.SslPolicyErrors.None
            };
            
            var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            
            if (!string.IsNullOrEmpty(settings.Username) && !string.IsNullOrEmpty(settings.Password))
            {
                var credentials = Convert.ToBase64String(
                    Encoding.ASCII.GetBytes($"{settings.Username}:{settings.Password}"));
                client.DefaultRequestHeaders.Authorization = 
                    new AuthenticationHeaderValue("Basic", credentials);
            }
            
            return client;
        }

        private string GetBaseUrl(WifiControllerSettings settings)
        {
            var protocol = settings.UseHttps ? "https" : "http";
            var port = settings.Port.HasValue ? $":{settings.Port}" : "";
            return $"{protocol}://{settings.IpAddress}{port}";
        }

        private async Task RemoveExistingBindingAsync(HttpClient client, string baseUrl, string macAddress)
        {
            try
            {
                var mac = macAddress.Replace(":", "-").ToUpper();
                var response = await client.GetAsync($"{baseUrl}/rest/ip/hotspot/ip-binding");
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var bindings = JsonSerializer.Deserialize<JsonElement[]>(content);
                    
                    if (bindings != null)
                    {
                        foreach (var binding in bindings)
                        {
                            if (binding.TryGetProperty("mac-address", out var macProp) &&
                                macProp.GetString()?.Equals(mac, StringComparison.OrdinalIgnoreCase) == true &&
                                binding.TryGetProperty(".id", out var idProp))
                            {
                                var id = idProp.GetString();
                                await client.DeleteAsync($"{baseUrl}/rest/ip/hotspot/ip-binding/{id}");
                                _logger.LogDebug("[MikroTik] Removed existing binding: {Id}", id);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[MikroTik] Error removing existing binding");
            }
        }

        private async Task RemoveExistingUserAsync(HttpClient client, string baseUrl, string username)
        {
            try
            {
                var response = await client.GetAsync($"{baseUrl}/rest/ip/hotspot/user");
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var users = JsonSerializer.Deserialize<JsonElement[]>(content);
                    
                    if (users != null)
                    {
                        foreach (var user in users)
                        {
                            if (user.TryGetProperty("name", out var nameProp) &&
                                nameProp.GetString()?.Equals(username, StringComparison.OrdinalIgnoreCase) == true &&
                                user.TryGetProperty(".id", out var idProp))
                            {
                                var id = idProp.GetString();
                                await client.DeleteAsync($"{baseUrl}/rest/ip/hotspot/user/{id}");
                                _logger.LogDebug("[MikroTik] Removed existing user: {Id}", id);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[MikroTik] Error removing existing user");
            }
        }

        private async Task DisconnectActiveSessionAsync(HttpClient client, string baseUrl, string macAddress)
        {
            try
            {
                var mac = macAddress.Replace(":", "-").ToUpper();
                var response = await client.GetAsync($"{baseUrl}/rest/ip/hotspot/active");
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var sessions = JsonSerializer.Deserialize<JsonElement[]>(content);
                    
                    if (sessions != null)
                    {
                        foreach (var session in sessions)
                        {
                            if (session.TryGetProperty("mac-address", out var macProp) &&
                                macProp.GetString()?.Equals(mac, StringComparison.OrdinalIgnoreCase) == true &&
                                session.TryGetProperty(".id", out var idProp))
                            {
                                var id = idProp.GetString();
                                await client.DeleteAsync($"{baseUrl}/rest/ip/hotspot/active/{id}");
                                _logger.LogDebug("[MikroTik] Disconnected session: {Id}", id);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[MikroTik] Error disconnecting session");
            }
        }

        #endregion
    }

    public class MikrotikAuthResult
    {
        public bool Success { get; set; }
        public string Method { get; set; } = "";
        public string? Message { get; set; }
        public string? Error { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? RedirectUrl { get; set; }
    }
}
