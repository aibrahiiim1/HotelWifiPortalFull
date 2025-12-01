using HotelWifiPortal.Models.Entities;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace HotelWifiPortal.Services.WiFi
{
    public class RuckusController : WifiControllerBase
    {
        private readonly HttpClient _httpClient;
        private string? _sessionToken;

        public override string ControllerType => "Ruckus";

        public RuckusController(WifiControllerSettings settings, ILogger<RuckusController> logger, IHttpClientFactory httpClientFactory)
            : base(settings, logger)
        {
            _httpClient = httpClientFactory.CreateClient("RuckusClient");
            
            if (_settings.IgnoreSslErrors)
            {
                // Note: In production, properly configure SSL
            }
        }

        private async Task<bool> LoginAsync()
        {
            try
            {
                var loginUrl = BuildUrl("/api/public/v5_0/session");
                var loginData = new
                {
                    username = _settings.Username,
                    password = _settings.Password
                };

                var content = new StringContent(JsonSerializer.Serialize(loginData), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(loginUrl, content);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var result = JsonSerializer.Deserialize<JsonElement>(responseBody);
                    
                    if (result.TryGetProperty("serviceTicket", out var ticket))
                    {
                        _sessionToken = ticket.GetString();
                        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _sessionToken);
                        return true;
                    }
                }

                _logger.LogWarning("Ruckus login failed: {Status}", response.StatusCode);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus login error");
                return false;
            }
        }

        public override async Task<bool> TestConnectionAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(_sessionToken))
                {
                    if (!await LoginAsync())
                        return false;
                }

                var url = BuildUrl("/api/public/v5_0/system/systemSummary");
                var response = await _httpClient.GetAsync(url);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus connection test failed");
                return false;
            }
        }

        public override async Task<bool> AuthenticateUserAsync(string macAddress, string username, string? password = null)
        {
            try
            {
                if (string.IsNullOrEmpty(_sessionToken) && !await LoginAsync())
                    return false;

                // Ruckus ZD uses RADIUS or local user database
                // This would typically trigger MAC authentication or add to allowed list
                var url = BuildUrl("/api/public/v5_0/rkszones/wlan/authenticateUser");
                var data = new
                {
                    mac = macAddress.Replace(":", "-").ToUpper(),
                    userName = username,
                    action = "authorize"
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(url, content);

                _logger.LogInformation("Ruckus auth for MAC {Mac}: {Success}", macAddress, response.IsSuccessStatusCode);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus authenticate error");
                return false;
            }
        }

        public override async Task<bool> DisconnectUserAsync(string macAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(_sessionToken) && !await LoginAsync())
                    return false;

                var url = BuildUrl($"/api/public/v5_0/clients/{macAddress.Replace(":", "-").ToUpper()}/disconnect");
                var response = await _httpClient.DeleteAsync(url);

                _logger.LogInformation("Ruckus disconnect MAC {Mac}: {Success}", macAddress, response.IsSuccessStatusCode);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus disconnect error");
                return false;
            }
        }

        public override async Task<List<WifiClientInfo>> GetConnectedClientsAsync()
        {
            var clients = new List<WifiClientInfo>();

            try
            {
                if (string.IsNullOrEmpty(_sessionToken) && !await LoginAsync())
                    return clients;

                var url = BuildUrl("/api/public/v5_0/clients");
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var result = JsonSerializer.Deserialize<JsonElement>(responseBody);

                    if (result.TryGetProperty("list", out var list))
                    {
                        foreach (var client in list.EnumerateArray())
                        {
                            clients.Add(new WifiClientInfo
                            {
                                MacAddress = client.GetProperty("mac").GetString() ?? "",
                                IpAddress = client.TryGetProperty("ipAddress", out var ip) ? ip.GetString() : null,
                                Hostname = client.TryGetProperty("hostName", out var host) ? host.GetString() : null,
                                Username = client.TryGetProperty("userName", out var user) ? user.GetString() : null,
                                SSID = client.TryGetProperty("ssid", out var ssid) ? ssid.GetString() : null,
                                AccessPoint = client.TryGetProperty("apName", out var ap) ? ap.GetString() : null,
                                BytesReceived = client.TryGetProperty("rxBytes", out var rx) ? rx.GetInt64() : 0,
                                BytesSent = client.TryGetProperty("txBytes", out var tx) ? tx.GetInt64() : 0,
                                SignalStrength = client.TryGetProperty("rssi", out var rssi) ? rssi.GetInt32() : null,
                                Status = "Connected"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus get clients error");
            }

            return clients;
        }

        public override async Task<WifiClientInfo?> GetClientInfoAsync(string macAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(_sessionToken) && !await LoginAsync())
                    return null;

                var url = BuildUrl($"/api/public/v5_0/clients/{macAddress.Replace(":", "-").ToUpper()}");
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var client = JsonSerializer.Deserialize<JsonElement>(responseBody);

                    return new WifiClientInfo
                    {
                        MacAddress = client.GetProperty("mac").GetString() ?? "",
                        IpAddress = client.TryGetProperty("ipAddress", out var ip) ? ip.GetString() : null,
                        Hostname = client.TryGetProperty("hostName", out var host) ? host.GetString() : null,
                        Username = client.TryGetProperty("userName", out var user) ? user.GetString() : null,
                        SSID = client.TryGetProperty("ssid", out var ssid) ? ssid.GetString() : null,
                        BytesReceived = client.TryGetProperty("rxBytes", out var rx) ? rx.GetInt64() : 0,
                        BytesSent = client.TryGetProperty("txBytes", out var tx) ? tx.GetInt64() : 0,
                        Status = "Connected"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus get client info error");
            }

            return null;
        }

        public override async Task<bool> SetBandwidthLimitAsync(string macAddress, int downloadKbps, int uploadKbps)
        {
            try
            {
                if (string.IsNullOrEmpty(_sessionToken) && !await LoginAsync())
                    return false;

                var url = BuildUrl($"/api/public/v5_0/clients/{macAddress.Replace(":", "-").ToUpper()}/rateLimit");
                var data = new
                {
                    downlinkRateLimiting = new { rateLimitKbps = downloadKbps },
                    uplinkRateLimiting = new { rateLimitKbps = uploadKbps }
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PutAsync(url, content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus set bandwidth limit error");
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
                if (string.IsNullOrEmpty(_sessionToken) && !await LoginAsync())
                    return false;

                var url = BuildUrl("/api/public/v5_0/blockClient/clientMac");
                var data = new { mac = macAddress.Replace(":", "-").ToUpper() };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(url, content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus block client error");
                return false;
            }
        }

        public override async Task<bool> UnblockClientAsync(string macAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(_sessionToken) && !await LoginAsync())
                    return false;

                var url = BuildUrl($"/api/public/v5_0/blockClient/clientMac/{macAddress.Replace(":", "-").ToUpper()}");
                var response = await _httpClient.DeleteAsync(url);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ruckus unblock client error");
                return false;
            }
        }
    }
}
