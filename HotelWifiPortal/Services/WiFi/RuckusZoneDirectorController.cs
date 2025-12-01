using HotelWifiPortal.Models.Entities;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;

namespace HotelWifiPortal.Services.WiFi
{
    /// <summary>
    /// Ruckus ZoneDirector Controller for ZD 3000/3050/5000 series
    /// Supports Hotspot (WISPr) and Guest Pass authentication
    /// </summary>
    public class RuckusZoneDirectorController : WifiControllerBase
    {
        private readonly HttpClient _httpClient;
        private readonly IHttpClientFactory _httpClientFactory;
        private string? _sessionCookie;
        private DateTime _sessionExpiry = DateTime.MinValue;

        public override string ControllerType => "RuckusZD";

        public RuckusZoneDirectorController(
            WifiControllerSettings settings,
            ILogger<RuckusZoneDirectorController> logger,
            IHttpClientFactory httpClientFactory)
            : base(settings, logger)
        {
            _httpClientFactory = httpClientFactory;

            // Create HttpClient with custom handler for SSL
            var handler = new HttpClientHandler();
            if (_settings.IgnoreSslErrors)
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            }
            handler.CookieContainer = new CookieContainer();
            handler.UseCookies = true;

            _httpClient = new HttpClient(handler)
            {
                BaseAddress = new Uri(BuildUrl("")),
                Timeout = TimeSpan.FromSeconds(30)
            };
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        /// <summary>
        /// Login to ZoneDirector admin interface
        /// </summary>
        private async Task<bool> LoginAsync()
        {
            try
            {
                // ZoneDirector login endpoint
                var loginUrl = "/admin/login.jsp";

                var loginData = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", _settings.Username ?? "admin"),
                    new KeyValuePair<string, string>("password", _settings.Password ?? ""),
                    new KeyValuePair<string, string>("ok", "Log In")
                });

                var response = await _httpClient.PostAsync(loginUrl, loginData);

                if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Redirect)
                {
                    // Check for session cookie
                    if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
                    {
                        _sessionCookie = cookies.FirstOrDefault();
                        _sessionExpiry = DateTime.UtcNow.AddMinutes(30);
                        _logger.LogInformation("Ruckus ZD login successful");
                        return true;
                    }

                    // Some versions use different redirect behavior
                    _sessionExpiry = DateTime.UtcNow.AddMinutes(30);
                    return true;
                }

                _logger.LogWarning("Ruckus ZD login failed: {Status}", response.StatusCode);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD login error");
                return false;
            }
        }

        private async Task EnsureLoggedInAsync()
        {
            if (DateTime.UtcNow >= _sessionExpiry)
            {
                await LoginAsync();
            }
        }

        public override async Task<bool> TestConnectionAsync()
        {
            try
            {
                await EnsureLoggedInAsync();

                // Test by fetching system info
                var response = await _httpClient.GetAsync("/admin/_cmdstat.jsp?cat=dashboard&type=system");

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Ruckus ZD connection test successful");
                    return true;
                }

                // Alternative endpoint
                response = await _httpClient.GetAsync("/admin/status.jsp");
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD connection test failed");
                return false;
            }
        }

        /// <summary>
        /// Authenticate user via ZoneDirector Hotspot/WISPr
        /// This is called after guest logs in via the captive portal
        /// </summary>
        public override async Task<bool> AuthenticateUserAsync(string macAddress, string username, string? password = null)
        {
            try
            {
                await EnsureLoggedInAsync();

                var formattedMac = FormatMacAddress(macAddress);

                _logger.LogInformation("Authenticating MAC {Mac} for user {User} on Ruckus ZD", formattedMac, username);

                // Method 1: Create a temporary Guest Pass for the MAC
                var guestPassCreated = await CreateGuestPassAsync(formattedMac, username);
                if (guestPassCreated)
                {
                    _logger.LogInformation("Guest pass created for MAC {Mac}", formattedMac);
                    return true;
                }

                // Method 2: Add to allowed MAC list (if Guest Pass fails)
                var macAdded = await AddToAllowedMacListAsync(formattedMac, username);
                if (macAdded)
                {
                    _logger.LogInformation("MAC {Mac} added to allowed list", formattedMac);
                    return true;
                }

                // Method 3: Use WISPr authentication callback (for external captive portal)
                var wisprAuth = await WisprAuthenticateAsync(formattedMac, username, password);
                if (wisprAuth)
                {
                    _logger.LogInformation("WISPr authentication successful for MAC {Mac}", formattedMac);
                    return true;
                }

                _logger.LogWarning("All authentication methods failed for MAC {Mac}", formattedMac);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD authenticate error for MAC {Mac}", macAddress);
                return false;
            }
        }

        /// <summary>
        /// Create a Guest Pass for the specified MAC address
        /// </summary>
        private async Task<bool> CreateGuestPassAsync(string macAddress, string guestName)
        {
            try
            {
                // ZoneDirector Guest Pass creation endpoint
                var url = "/admin/_cmdstat.jsp";

                // Guest pass parameters - valid for 24 hours or until checkout
                var data = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("cat", "guestpass"),
                    new KeyValuePair<string, string>("action", "create"),
                    new KeyValuePair<string, string>("type", "single"),
                    new KeyValuePair<string, string>("guest_name", guestName),
                    new KeyValuePair<string, string>("duration", "1440"), // 24 hours in minutes
                    new KeyValuePair<string, string>("duration_unit", "minutes"),
                    new KeyValuePair<string, string>("max_devices", "5"),
                    new KeyValuePair<string, string>("wlan", _settings.DefaultSSID ?? "Guest"),
                    new KeyValuePair<string, string>("remarks", $"Hotel WiFi - MAC: {macAddress}"),
                    new KeyValuePair<string, string>("key", macAddress.Replace(":", "").Replace("-", "").ToUpper()) // Use MAC as pass key
                });

                var response = await _httpClient.PostAsync(url, data);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    // Check for success indicators in response
                    if (!content.Contains("error") && !content.Contains("failed"))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Create guest pass failed");
                return false;
            }
        }

        /// <summary>
        /// Add MAC to the allowed/whitelist for hotspot bypass
        /// </summary>
        private async Task<bool> AddToAllowedMacListAsync(string macAddress, string description)
        {
            try
            {
                var url = "/admin/_cmdstat.jsp";

                var data = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("cat", "hotspot"),
                    new KeyValuePair<string, string>("action", "add-whitelist"),
                    new KeyValuePair<string, string>("mac", macAddress),
                    new KeyValuePair<string, string>("description", description)
                });

                var response = await _httpClient.PostAsync(url, data);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Add to MAC whitelist failed");
                return false;
            }
        }

        /// <summary>
        /// WISPr authentication - notify ZD that client is authorized
        /// This is the standard method for external captive portals
        /// </summary>
        private async Task<bool> WisprAuthenticateAsync(string macAddress, string username, string? password)
        {
            try
            {
                // WISPr login URL format for ZoneDirector
                // This URL is typically provided by ZD in the captive portal redirect
                var loginUrl = $"/login";

                var formData = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", username),
                    new KeyValuePair<string, string>("password", password ?? macAddress), // Use MAC as password if not provided
                    new KeyValuePair<string, string>("dst", "http://www.google.com"),
                    new KeyValuePair<string, string>("popup", "false")
                });

                var response = await _httpClient.PostAsync(loginUrl, formData);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    // Check WISPr response
                    if (content.Contains("loginSucceeded") || content.Contains("success"))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "WISPr authentication failed");
                return false;
            }
        }

        public override async Task<bool> DisconnectUserAsync(string macAddress)
        {
            try
            {
                await EnsureLoggedInAsync();

                var formattedMac = FormatMacAddress(macAddress);

                // Delete guest pass for this MAC
                var url = "/admin/_cmdstat.jsp";
                var data = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("cat", "guestpass"),
                    new KeyValuePair<string, string>("action", "delete"),
                    new KeyValuePair<string, string>("key", formattedMac.Replace(":", "").Replace("-", ""))
                });

                await _httpClient.PostAsync(url, data);

                // Also try to disconnect the client directly
                data = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("cat", "client"),
                    new KeyValuePair<string, string>("action", "disconnect"),
                    new KeyValuePair<string, string>("mac", formattedMac)
                });

                var response = await _httpClient.PostAsync(url, data);

                _logger.LogInformation("Disconnect user MAC {Mac}: {Success}", formattedMac, response.IsSuccessStatusCode);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD disconnect error");
                return false;
            }
        }

        public override async Task<List<WifiClientInfo>> GetConnectedClientsAsync()
        {
            var clients = new List<WifiClientInfo>();

            try
            {
                await EnsureLoggedInAsync();

                // Fetch client list from ZoneDirector
                var url = "/admin/_cmdstat.jsp?cat=client&type=all";
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();

                    // Parse the response - ZD returns either JSON or HTML table
                    try
                    {
                        var jsonDoc = JsonDocument.Parse(content);
                        if (jsonDoc.RootElement.TryGetProperty("client", out var clientArray))
                        {
                            foreach (var client in clientArray.EnumerateArray())
                            {
                                clients.Add(ParseClientFromJson(client));
                            }
                        }
                    }
                    catch
                    {
                        // Try HTML parsing if JSON fails
                        clients = ParseClientsFromHtml(content);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD get clients error");
            }

            return clients;
        }

        private WifiClientInfo ParseClientFromJson(JsonElement client)
        {
            return new WifiClientInfo
            {
                MacAddress = client.TryGetProperty("mac", out var mac) ? mac.GetString() ?? "" : "",
                IpAddress = client.TryGetProperty("ip", out var ip) ? ip.GetString() : null,
                Hostname = client.TryGetProperty("hostname", out var host) ? host.GetString() : null,
                Username = client.TryGetProperty("user", out var user) ? user.GetString() : null,
                SSID = client.TryGetProperty("wlan", out var ssid) ? ssid.GetString() : null,
                AccessPoint = client.TryGetProperty("ap", out var ap) ? ap.GetString() : null,
                BytesReceived = client.TryGetProperty("rx_bytes", out var rx) ? rx.GetInt64() : 0,
                BytesSent = client.TryGetProperty("tx_bytes", out var tx) ? tx.GetInt64() : 0,
                SignalStrength = client.TryGetProperty("signal", out var signal) ? signal.GetInt32() : null,
                Status = "Connected"
            };
        }

        private List<WifiClientInfo> ParseClientsFromHtml(string html)
        {
            var clients = new List<WifiClientInfo>();

            // Basic HTML parsing for client table
            var macPattern = new Regex(@"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})");
            var ipPattern = new Regex(@"(\d{1,3}\.){3}\d{1,3}");

            var macMatches = macPattern.Matches(html);
            var ipMatches = ipPattern.Matches(html);

            for (int i = 0; i < macMatches.Count; i++)
            {
                clients.Add(new WifiClientInfo
                {
                    MacAddress = macMatches[i].Value,
                    IpAddress = i < ipMatches.Count ? ipMatches[i].Value : null,
                    Status = "Connected"
                });
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
                await EnsureLoggedInAsync();

                // ZoneDirector uses rate limiting profiles
                // This would need to assign client to a specific rate profile
                var url = "/admin/_cmdstat.jsp";
                var data = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("cat", "ratelimit"),
                    new KeyValuePair<string, string>("action", "set"),
                    new KeyValuePair<string, string>("mac", FormatMacAddress(macAddress)),
                    new KeyValuePair<string, string>("downlink", downloadKbps.ToString()),
                    new KeyValuePair<string, string>("uplink", uploadKbps.ToString())
                });

                var response = await _httpClient.PostAsync(url, data);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD set bandwidth limit error");
                return false;
            }
        }

        public override async Task<bool> RemoveBandwidthLimitAsync(string macAddress)
        {
            return await SetBandwidthLimitAsync(macAddress, 0, 0);
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
                await EnsureLoggedInAsync();

                var formattedMac = FormatMacAddress(macAddress);

                var url = "/admin/_cmdstat.jsp";
                var data = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("cat", "client"),
                    new KeyValuePair<string, string>("action", "block"),
                    new KeyValuePair<string, string>("mac", formattedMac)
                });

                var response = await _httpClient.PostAsync(url, data);

                _logger.LogInformation("Block client MAC {Mac}: {Success}", formattedMac, response.IsSuccessStatusCode);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD block client error");
                return false;
            }
        }

        public override async Task<bool> UnblockClientAsync(string macAddress)
        {
            try
            {
                await EnsureLoggedInAsync();

                var formattedMac = FormatMacAddress(macAddress);

                var url = "/admin/_cmdstat.jsp";
                var data = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("cat", "client"),
                    new KeyValuePair<string, string>("action", "unblock"),
                    new KeyValuePair<string, string>("mac", formattedMac)
                });

                var response = await _httpClient.PostAsync(url, data);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus ZD unblock client error");
                return false;
            }
        }

        /// <summary>
        /// Format MAC address to standard format (XX:XX:XX:XX:XX:XX)
        /// </summary>
        private string FormatMacAddress(string mac)
        {
            var cleanMac = mac.Replace(":", "").Replace("-", "").Replace(".", "").ToUpper();
            if (cleanMac.Length == 12)
            {
                return string.Join(":", Enumerable.Range(0, 6).Select(i => cleanMac.Substring(i * 2, 2)));
            }
            return mac.ToUpper();
        }
    }
}