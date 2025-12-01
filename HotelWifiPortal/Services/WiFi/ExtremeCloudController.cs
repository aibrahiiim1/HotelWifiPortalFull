using HotelWifiPortal.Models.Entities;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace HotelWifiPortal.Services.WiFi
{
    public class ExtremeCloudController : WifiControllerBase
    {
        private readonly HttpClient _httpClient;
        private string? _accessToken;
        private DateTime _tokenExpiry = DateTime.MinValue;

        public override string ControllerType => "ExtremeCloud";

        public ExtremeCloudController(WifiControllerSettings settings, ILogger<ExtremeCloudController> logger, IHttpClientFactory httpClientFactory)
            : base(settings, logger)
        {
            _httpClient = httpClientFactory.CreateClient("ExtremeCloudClient");
        }

        private async Task<bool> GetAccessTokenAsync()
        {
            try
            {
                if (!string.IsNullOrEmpty(_accessToken) && DateTime.UtcNow < _tokenExpiry)
                    return true;

                var tokenUrl = !string.IsNullOrEmpty(_settings.ApiUrl) 
                    ? $"{_settings.ApiUrl}/oauth/token" 
                    : BuildUrl("/oauth/token");

                var tokenRequest = new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", _settings.Username ?? "" },
                    { "client_secret", _settings.Password ?? "" }
                };

                var content = new FormUrlEncodedContent(tokenRequest);
                var response = await _httpClient.PostAsync(tokenUrl, content);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var result = JsonSerializer.Deserialize<JsonElement>(responseBody);

                    if (result.TryGetProperty("access_token", out var token))
                    {
                        _accessToken = token.GetString();
                        var expiresIn = result.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;
                        _tokenExpiry = DateTime.UtcNow.AddSeconds(expiresIn - 60);
                        
                        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
                        return true;
                    }
                }

                _logger.LogWarning("ExtremeCloud token request failed: {Status}", response.StatusCode);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud token error");
                return false;
            }
        }

        private string GetApiUrl(string path)
        {
            return !string.IsNullOrEmpty(_settings.ApiUrl)
                ? $"{_settings.ApiUrl}{path}"
                : BuildUrl(path);
        }

        public override async Task<bool> TestConnectionAsync()
        {
            try
            {
                if (!await GetAccessTokenAsync())
                    return false;

                var url = GetApiUrl("/xapi/v1/account/home");
                var response = await _httpClient.GetAsync(url);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud connection test failed");
                return false;
            }
        }

        public override async Task<bool> AuthenticateUserAsync(string macAddress, string username, string? password = null)
        {
            try
            {
                if (!await GetAccessTokenAsync())
                    return false;

                // ExtremeCloud IQ uses cloud-based authentication
                // This typically involves adding MAC to an allowed list or user group
                var url = GetApiUrl("/xapi/v1/clients/authorize");
                var data = new
                {
                    macAddress = FormatMacAddress(macAddress),
                    userName = username,
                    userGroup = "Hotel-Guests"
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(url, content);

                _logger.LogInformation("ExtremeCloud auth for MAC {Mac}: {Success}", macAddress, response.IsSuccessStatusCode);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud authenticate error");
                return false;
            }
        }

        public override async Task<bool> DisconnectUserAsync(string macAddress)
        {
            try
            {
                if (!await GetAccessTokenAsync())
                    return false;

                var url = GetApiUrl($"/xapi/v1/clients/{FormatMacAddress(macAddress)}/disconnect");
                var response = await _httpClient.PostAsync(url, null);

                _logger.LogInformation("ExtremeCloud disconnect MAC {Mac}: {Success}", macAddress, response.IsSuccessStatusCode);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud disconnect error");
                return false;
            }
        }

        public override async Task<List<WifiClientInfo>> GetConnectedClientsAsync()
        {
            var clients = new List<WifiClientInfo>();

            try
            {
                if (!await GetAccessTokenAsync())
                    return clients;

                var url = GetApiUrl("/xapi/v1/clients?connected=true");
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var result = JsonSerializer.Deserialize<JsonElement>(responseBody);

                    if (result.TryGetProperty("data", out var data))
                    {
                        foreach (var client in data.EnumerateArray())
                        {
                            clients.Add(new WifiClientInfo
                            {
                                MacAddress = client.TryGetProperty("macAddress", out var mac) ? mac.GetString() ?? "" : "",
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
                _logger.LogError(ex, "ExtremeCloud get clients error");
            }

            return clients;
        }

        public override async Task<WifiClientInfo?> GetClientInfoAsync(string macAddress)
        {
            try
            {
                if (!await GetAccessTokenAsync())
                    return null;

                var url = GetApiUrl($"/xapi/v1/clients/{FormatMacAddress(macAddress)}");
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    var client = JsonSerializer.Deserialize<JsonElement>(responseBody);

                    return new WifiClientInfo
                    {
                        MacAddress = client.TryGetProperty("macAddress", out var mac) ? mac.GetString() ?? "" : "",
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
                _logger.LogError(ex, "ExtremeCloud get client info error");
            }

            return null;
        }

        public override async Task<bool> SetBandwidthLimitAsync(string macAddress, int downloadKbps, int uploadKbps)
        {
            try
            {
                if (!await GetAccessTokenAsync())
                    return false;

                var url = GetApiUrl($"/xapi/v1/clients/{FormatMacAddress(macAddress)}/rateLimit");
                var data = new
                {
                    downloadRateKbps = downloadKbps,
                    uploadRateKbps = uploadKbps
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PutAsync(url, content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud set bandwidth limit error");
                return false;
            }
        }

        public override async Task<bool> RemoveBandwidthLimitAsync(string macAddress)
        {
            try
            {
                if (!await GetAccessTokenAsync())
                    return false;

                var url = GetApiUrl($"/xapi/v1/clients/{FormatMacAddress(macAddress)}/rateLimit");
                var response = await _httpClient.DeleteAsync(url);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud remove bandwidth limit error");
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
                if (!await GetAccessTokenAsync())
                    return false;

                var url = GetApiUrl($"/xapi/v1/clients/{FormatMacAddress(macAddress)}/block");
                var response = await _httpClient.PostAsync(url, null);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud block client error");
                return false;
            }
        }

        public override async Task<bool> UnblockClientAsync(string macAddress)
        {
            try
            {
                if (!await GetAccessTokenAsync())
                    return false;

                var url = GetApiUrl($"/xapi/v1/clients/{FormatMacAddress(macAddress)}/unblock");
                var response = await _httpClient.PostAsync(url, null);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ExtremeCloud unblock client error");
                return false;
            }
        }

        private string FormatMacAddress(string mac)
        {
            // ExtremeCloud typically uses XX:XX:XX:XX:XX:XX format
            return mac.Replace("-", ":").ToUpper();
        }
    }
}
