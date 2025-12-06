using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Services.Radius;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace HotelWifiPortal.Services.WiFi
{
    /// <summary>
    /// MikroTik RouterOS Controller
    /// Supports both direct API and RADIUS-based authentication
    /// Compatible with RouterOS v6.x and v7.x
    /// </summary>
    public class MikrotikController : WifiControllerBase
    {
        private readonly HttpClient _httpClient;
        private readonly IServiceProvider? _serviceProvider;
        private string? _sessionToken;

        public override string ControllerType => "Mikrotik";

        public MikrotikController(
            WifiControllerSettings settings,
            ILogger<MikrotikController> logger,
            IHttpClientFactory httpClientFactory,
            IServiceProvider? serviceProvider = null)
            : base(settings, logger)
        {
            _serviceProvider = serviceProvider;

            var handler = new HttpClientHandler();
            if (_settings.IgnoreSslErrors)
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            }

            _httpClient = new HttpClient(handler)
            {
                BaseAddress = new Uri(BuildUrl("")),
                Timeout = TimeSpan.FromSeconds(30)
            };

            // Basic authentication for RouterOS REST API
            if (!string.IsNullOrEmpty(_settings.Username) && !string.IsNullOrEmpty(_settings.Password))
            {
                var credentials = Convert.ToBase64String(
                    Encoding.ASCII.GetBytes($"{_settings.Username}:{_settings.Password}"));
                _httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Basic", credentials);
            }

            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public override async Task<bool> TestConnectionAsync()
        {
            try
            {
                // RouterOS REST API endpoint (v6.45+ and v7.x)
                var response = await _httpClient.GetAsync("/rest/system/resource");

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation("MikroTik connection successful: {Response}", content);
                    return true;
                }

                // Try alternative endpoint for older versions
                response = await _httpClient.GetAsync("/rest/system/identity");
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik connection test failed");
                return false;
            }
        }

        /// <summary>
        /// Authenticate user - when using RADIUS, this is handled by RadiusServer
        /// This method is for direct hotspot user creation (non-RADIUS mode)
        /// </summary>
        public override async Task<bool> AuthenticateUserAsync(string macAddress, string username, string? password = null)
        {
            try
            {
                var formattedMac = FormatMacAddress(macAddress);

                _logger.LogInformation("MikroTik: Authenticating MAC {Mac} for user {User}", formattedMac, username);

                // Method 1: Add to Hotspot Active (bypass authentication)
                var bindingResult = await AddHotspotBindingAsync(formattedMac, username);
                if (bindingResult)
                {
                    _logger.LogInformation("MikroTik: Added hotspot binding for MAC {Mac}", formattedMac);
                    return true;
                }

                // Method 2: Create hotspot user and authenticate
                var userResult = await CreateHotspotUserAsync(username, password ?? macAddress, formattedMac);
                if (userResult)
                {
                    _logger.LogInformation("MikroTik: Created hotspot user for {User}", username);
                    return true;
                }

                _logger.LogWarning("MikroTik: Authentication failed for MAC {Mac}", formattedMac);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik authenticate error");
                return false;
            }
        }

        /// <summary>
        /// Add MAC to hotspot IP bindings (MAC-based bypass)
        /// </summary>
        private async Task<bool> AddHotspotBindingAsync(string macAddress, string comment)
        {
            try
            {
                var data = new
                {
                    mac_address = macAddress,
                    type = "bypassed",
                    comment = $"HotelWiFi: {comment}"
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PutAsync("/rest/ip/hotspot/ip-binding", content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding hotspot binding");
                return false;
            }
        }

        /// <summary>
        /// Create a hotspot user for authentication
        /// </summary>
        private async Task<bool> CreateHotspotUserAsync(string username, string password, string macAddress)
        {
            try
            {
                // Check if user already exists
                var existingResponse = await _httpClient.GetAsync($"/rest/ip/hotspot/user?name={username}");
                if (existingResponse.IsSuccessStatusCode)
                {
                    var existingContent = await existingResponse.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(existingContent) && existingContent != "[]")
                    {
                        // User exists, update it
                        var users = JsonSerializer.Deserialize<JsonElement>(existingContent);
                        if (users.ValueKind == JsonValueKind.Array && users.GetArrayLength() > 0)
                        {
                            var userId = users[0].GetProperty(".id").GetString();
                            return await UpdateHotspotUserAsync(userId!, password, macAddress);
                        }
                    }
                }

                // Create new user
                var data = new
                {
                    name = username,
                    password = password,
                    mac_address = macAddress,
                    comment = "HotelWiFi Guest"
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PutAsync("/rest/ip/hotspot/user", content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating hotspot user");
                return false;
            }
        }

        private async Task<bool> UpdateHotspotUserAsync(string userId, string password, string macAddress)
        {
            try
            {
                var data = new
                {
                    password = password,
                    mac_address = macAddress
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PatchAsync($"/rest/ip/hotspot/user/{userId}", content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating hotspot user");
                return false;
            }
        }

        public override async Task<bool> DisconnectUserAsync(string macAddress)
        {
            try
            {
                var formattedMac = FormatMacAddress(macAddress);

                // Try RADIUS CoA disconnect first
                if (_serviceProvider != null)
                {
                    var radiusServer = _serviceProvider.GetService<RadiusServer>();
                    if (radiusServer != null && !string.IsNullOrEmpty(_settings.IpAddress))
                    {
                        var coaResult = await radiusServer.DisconnectUserAsync(_settings.IpAddress, formattedMac);
                        if (coaResult)
                        {
                            _logger.LogInformation("MikroTik: Disconnected via CoA MAC {Mac}", formattedMac);
                            return true;
                        }
                    }
                }

                // Fallback: Remove from hotspot active
                var response = await _httpClient.GetAsync("/rest/ip/hotspot/active");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var sessions = JsonSerializer.Deserialize<JsonElement>(content);

                    if (sessions.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var session in sessions.EnumerateArray())
                        {
                            if (session.TryGetProperty("mac-address", out var mac) &&
                                mac.GetString()?.Equals(formattedMac, StringComparison.OrdinalIgnoreCase) == true)
                            {
                                var sessionId = session.GetProperty(".id").GetString();
                                var deleteResponse = await _httpClient.DeleteAsync($"/rest/ip/hotspot/active/{sessionId}");

                                if (deleteResponse.IsSuccessStatusCode)
                                {
                                    _logger.LogInformation("MikroTik: Removed active session for MAC {Mac}", formattedMac);
                                    return true;
                                }
                            }
                        }
                    }
                }

                // Also remove IP binding if exists
                await RemoveHotspotBindingAsync(formattedMac);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik disconnect error");
                return false;
            }
        }

        private async Task RemoveHotspotBindingAsync(string macAddress)
        {
            try
            {
                var response = await _httpClient.GetAsync("/rest/ip/hotspot/ip-binding");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var bindings = JsonSerializer.Deserialize<JsonElement>(content);

                    if (bindings.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var binding in bindings.EnumerateArray())
                        {
                            if (binding.TryGetProperty("mac-address", out var mac) &&
                                mac.GetString()?.Equals(macAddress, StringComparison.OrdinalIgnoreCase) == true)
                            {
                                var bindingId = binding.GetProperty(".id").GetString();
                                await _httpClient.DeleteAsync($"/rest/ip/hotspot/ip-binding/{bindingId}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing hotspot binding");
            }
        }

        public override async Task<List<WifiClientInfo>> GetConnectedClientsAsync()
        {
            var clients = new List<WifiClientInfo>();

            try
            {
                // Get active hotspot sessions
                var response = await _httpClient.GetAsync("/rest/ip/hotspot/active");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var sessions = JsonSerializer.Deserialize<JsonElement>(content);

                    if (sessions.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var session in sessions.EnumerateArray())
                        {
                            clients.Add(new WifiClientInfo
                            {
                                MacAddress = session.TryGetProperty("mac-address", out var mac) ? mac.GetString() ?? "" : "",
                                IpAddress = session.TryGetProperty("address", out var ip) ? ip.GetString() : null,
                                Username = session.TryGetProperty("user", out var user) ? user.GetString() : null,
                                BytesReceived = session.TryGetProperty("bytes-in", out var rx) ? ParseBytes(rx.GetString()) : 0,
                                BytesSent = session.TryGetProperty("bytes-out", out var tx) ? ParseBytes(tx.GetString()) : 0,
                                Uptime = session.TryGetProperty("uptime", out var uptime) ? uptime.GetString() : null,
                                Status = "Connected"
                            });
                        }
                    }
                }

                // Also get wireless clients
                var wirelessResponse = await _httpClient.GetAsync("/rest/interface/wireless/registration-table");
                if (wirelessResponse.IsSuccessStatusCode)
                {
                    var content = await wirelessResponse.Content.ReadAsStringAsync();
                    var registrations = JsonSerializer.Deserialize<JsonElement>(content);

                    if (registrations.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var reg in registrations.EnumerateArray())
                        {
                            var mac = reg.TryGetProperty("mac-address", out var m) ? m.GetString() ?? "" : "";

                            // Update existing client or add new
                            var existing = clients.FirstOrDefault(c =>
                                c.MacAddress.Equals(mac, StringComparison.OrdinalIgnoreCase));

                            if (existing != null)
                            {
                                existing.SignalStrength = reg.TryGetProperty("signal-strength", out var sig)
                                    ? ParseSignalStrength(sig.GetString()) : null;
                                existing.SSID = reg.TryGetProperty("interface", out var iface) ? iface.GetString() : null;
                            }
                            else
                            {
                                clients.Add(new WifiClientInfo
                                {
                                    MacAddress = mac,
                                    SignalStrength = reg.TryGetProperty("signal-strength", out var sig)
                                        ? ParseSignalStrength(sig.GetString()) : null,
                                    SSID = reg.TryGetProperty("interface", out var iface) ? iface.GetString() : null,
                                    Status = "Connected"
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik get clients error");
            }

            return clients;
        }

        public override async Task<WifiClientInfo?> GetClientInfoAsync(string macAddress)
        {
            var clients = await GetConnectedClientsAsync();
            var formattedMac = FormatMacAddress(macAddress);

            return clients.FirstOrDefault(c =>
                FormatMacAddress(c.MacAddress).Equals(formattedMac, StringComparison.OrdinalIgnoreCase));
        }

        public override async Task<bool> SetBandwidthLimitAsync(string macAddress, int downloadKbps, int uploadKbps)
        {
            try
            {
                // Try RADIUS CoA first
                if (_serviceProvider != null)
                {
                    var radiusServer = _serviceProvider.GetService<RadiusServer>();
                    if (radiusServer != null && !string.IsNullOrEmpty(_settings.IpAddress))
                    {
                        var coaResult = await radiusServer.UpdateRateLimitAsync(
                            _settings.IpAddress, FormatMacAddress(macAddress), downloadKbps, uploadKbps);
                        if (coaResult)
                        {
                            return true;
                        }
                    }
                }

                // Fallback: Create/update queue rule
                var formattedMac = FormatMacAddress(macAddress);
                var queueName = $"hotel-{formattedMac.Replace(":", "")}";

                // Get client IP
                var client = await GetClientInfoAsync(macAddress);
                if (client?.IpAddress == null)
                {
                    _logger.LogWarning("Cannot set bandwidth limit: client IP not found");
                    return false;
                }

                // Check if queue exists
                var existingResponse = await _httpClient.GetAsync($"/rest/queue/simple?name={queueName}");
                var queueExists = false;
                string? queueId = null;

                if (existingResponse.IsSuccessStatusCode)
                {
                    var content = await existingResponse.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(content) && content != "[]")
                    {
                        var queues = JsonSerializer.Deserialize<JsonElement>(content);
                        if (queues.ValueKind == JsonValueKind.Array && queues.GetArrayLength() > 0)
                        {
                            queueExists = true;
                            queueId = queues[0].GetProperty(".id").GetString();
                        }
                    }
                }

                var queueData = new
                {
                    name = queueName,
                    target = client.IpAddress,
                    max_limit = $"{uploadKbps}k/{downloadKbps}k",
                    comment = $"HotelWiFi: {macAddress}"
                };

                var queueContent = new StringContent(JsonSerializer.Serialize(queueData), Encoding.UTF8, "application/json");

                if (queueExists && queueId != null)
                {
                    await _httpClient.PatchAsync($"/rest/queue/simple/{queueId}", queueContent);
                }
                else
                {
                    await _httpClient.PutAsync("/rest/queue/simple", queueContent);
                }

                _logger.LogInformation("MikroTik: Set bandwidth limit for MAC {Mac}: {Down}k/{Up}k",
                    formattedMac, downloadKbps, uploadKbps);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik set bandwidth limit error");
                return false;
            }
        }

        public override async Task<bool> RemoveBandwidthLimitAsync(string macAddress)
        {
            try
            {
                var formattedMac = FormatMacAddress(macAddress);
                var queueName = $"hotel-{formattedMac.Replace(":", "")}";

                var response = await _httpClient.GetAsync($"/rest/queue/simple?name={queueName}");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var queues = JsonSerializer.Deserialize<JsonElement>(content);

                    if (queues.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var queue in queues.EnumerateArray())
                        {
                            var queueId = queue.GetProperty(".id").GetString();
                            await _httpClient.DeleteAsync($"/rest/queue/simple/{queueId}");
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik remove bandwidth limit error");
                return false;
            }
        }

        public override async Task<ClientUsageInfo?> GetClientUsageAsync(string macAddress)
        {
            var clientInfo = await GetClientInfoAsync(macAddress);
            if (clientInfo == null) return null;

            return new ClientUsageInfo
            {
                MacAddress = macAddress,
                TotalBytesUsed = clientInfo.BytesReceived + clientInfo.BytesSent,
                BytesDownloaded = clientInfo.BytesReceived,
                BytesUploaded = clientInfo.BytesSent
            };
        }

        public override async Task<bool> BlockClientAsync(string macAddress)
        {
            try
            {
                var formattedMac = FormatMacAddress(macAddress);

                // Disconnect first
                await DisconnectUserAsync(macAddress);

                // Add to blocked list (IP binding with type=blocked)
                var data = new
                {
                    mac_address = formattedMac,
                    type = "blocked",
                    comment = "HotelWiFi: Blocked"
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PutAsync("/rest/ip/hotspot/ip-binding", content);

                _logger.LogInformation("MikroTik: Blocked MAC {Mac}", formattedMac);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik block client error");
                return false;
            }
        }

        public override async Task<bool> UnblockClientAsync(string macAddress)
        {
            try
            {
                var formattedMac = FormatMacAddress(macAddress);

                // Remove blocked binding
                var response = await _httpClient.GetAsync("/rest/ip/hotspot/ip-binding");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var bindings = JsonSerializer.Deserialize<JsonElement>(content);

                    if (bindings.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var binding in bindings.EnumerateArray())
                        {
                            if (binding.TryGetProperty("mac-address", out var mac) &&
                                mac.GetString()?.Equals(formattedMac, StringComparison.OrdinalIgnoreCase) == true &&
                                binding.TryGetProperty("type", out var type) &&
                                type.GetString() == "blocked")
                            {
                                var bindingId = binding.GetProperty(".id").GetString();
                                await _httpClient.DeleteAsync($"/rest/ip/hotspot/ip-binding/{bindingId}");
                                _logger.LogInformation("MikroTik: Unblocked MAC {Mac}", formattedMac);
                                return true;
                            }
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik unblock client error");
                return false;
            }
        }

        /// <summary>
        /// Get hotspot server status
        /// </summary>
        public async Task<object?> GetHotspotStatusAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync("/rest/ip/hotspot");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<JsonElement>(content);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting hotspot status");
            }
            return null;
        }

        private string FormatMacAddress(string mac)
        {
            var cleanMac = mac.Replace(":", "").Replace("-", "").Replace(".", "").ToUpper();
            if (cleanMac.Length == 12)
            {
                return string.Join(":", Enumerable.Range(0, 6).Select(i => cleanMac.Substring(i * 2, 2)));
            }
            return mac.ToUpper();
        }

        private long ParseBytes(string? value)
        {
            if (string.IsNullOrEmpty(value)) return 0;

            // MikroTik may return values like "1234" or "1.2 KiB" or "1.2 MiB"
            value = value.Trim();

            if (long.TryParse(value, out var bytes))
                return bytes;

            var multiplier = 1L;
            if (value.EndsWith("KiB", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024;
                value = value[..^3].Trim();
            }
            else if (value.EndsWith("MiB", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024 * 1024;
                value = value[..^3].Trim();
            }
            else if (value.EndsWith("GiB", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1024 * 1024 * 1024;
                value = value[..^3].Trim();
            }

            if (double.TryParse(value, out var num))
                return (long)(num * multiplier);

            return 0;
        }

        private int? ParseSignalStrength(string? value)
        {
            if (string.IsNullOrEmpty(value)) return null;

            // Format: "-65dBm@1Mbps" or just "-65"
            var dbm = value.Split('@')[0].Replace("dBm", "").Trim();
            if (int.TryParse(dbm, out var signal))
                return signal;

            return null;
        }
    }
}