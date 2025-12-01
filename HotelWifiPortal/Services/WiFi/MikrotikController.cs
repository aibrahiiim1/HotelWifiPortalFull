using HotelWifiPortal.Models.Entities;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace HotelWifiPortal.Services.WiFi
{
    public class MikrotikController : WifiControllerBase
    {
        private readonly HttpClient _httpClient;

        public override string ControllerType => "Mikrotik";

        public MikrotikController(WifiControllerSettings settings, ILogger<MikrotikController> logger, IHttpClientFactory httpClientFactory)
            : base(settings, logger)
        {
            _httpClient = httpClientFactory.CreateClient("MikrotikClient");

            // Basic auth for MikroTik REST API
            var authString = $"{_settings.Username}:{_settings.Password}";
            var base64Auth = Convert.ToBase64String(Encoding.ASCII.GetBytes(authString));
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", base64Auth);
        }

        public override async Task<bool> TestConnectionAsync()
        {
            try
            {
                var url = BuildUrl("/rest/system/resource");
                var response = await _httpClient.GetAsync(url);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik connection test failed");
                return false;
            }
        }

        public override async Task<bool> AuthenticateUserAsync(string macAddress, string username, string? password = null)
        {
            try
            {
                // Add user to Hotspot active users or IP bindings
                var formattedMac = FormatMacAddress(macAddress);

                // Option 1: Add to hotspot active (for hotspot-enabled setups)
                var url = BuildUrl("/rest/ip/hotspot/active/add");
                var data = new
                {
                    user = username,
                    mac_address = formattedMac,
                    comment = $"WiFi Portal - {username}"
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(url, content);

                if (!response.IsSuccessStatusCode)
                {
                    // Option 2: Add to IP bindings for bypass
                    url = BuildUrl("/rest/ip/hotspot/ip-binding/add");
                    var bindingData = new
                    {
                        mac_address = formattedMac,
                        type = "bypassed",
                        comment = $"WiFi Portal - {username}"
                    };
                    content = new StringContent(JsonSerializer.Serialize(bindingData), Encoding.UTF8, "application/json");
                    response = await _httpClient.PostAsync(url, content);
                }

                _logger.LogInformation("MikroTik auth for MAC {Mac}: {Success}", macAddress, response.IsSuccessStatusCode);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik authenticate error");
                return false;
            }
        }

        public override async Task<bool> DisconnectUserAsync(string macAddress)
        {
            try
            {
                var formattedMac = FormatMacAddress(macAddress);

                // Find and remove from hotspot active
                var url = BuildUrl($"/rest/ip/hotspot/active?mac-address={formattedMac}");
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var sessions = JsonSerializer.Deserialize<JsonElement[]>(content);

                    if (sessions != null)
                    {
                        foreach (var session in sessions)
                        {
                            if (session.TryGetProperty(".id", out var idProp))
                            {
                                var deleteUrl = BuildUrl($"/rest/ip/hotspot/active/{idProp.GetString()}");
                                await _httpClient.DeleteAsync(deleteUrl);
                            }
                        }
                    }
                }

                // Also remove from IP bindings
                url = BuildUrl($"/rest/ip/hotspot/ip-binding?mac-address={formattedMac}");
                response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var bindings = JsonSerializer.Deserialize<JsonElement[]>(content);

                    if (bindings != null)
                    {
                        foreach (var binding in bindings)
                        {
                            if (binding.TryGetProperty(".id", out var idProp))
                            {
                                var deleteUrl = BuildUrl($"/rest/ip/hotspot/ip-binding/{idProp.GetString()}");
                                await _httpClient.DeleteAsync(deleteUrl);
                            }
                        }
                    }
                }

                _logger.LogInformation("MikroTik disconnect MAC {Mac}", macAddress);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik disconnect error");
                return false;
            }
        }

        public override async Task<List<WifiClientInfo>> GetConnectedClientsAsync()
        {
            var clients = new List<WifiClientInfo>();

            try
            {
                // Get hotspot active users
                var url = BuildUrl("/rest/ip/hotspot/active");
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var sessions = JsonSerializer.Deserialize<JsonElement[]>(content);

                    if (sessions != null)
                    {
                        foreach (var session in sessions)
                        {
                            clients.Add(new WifiClientInfo
                            {
                                MacAddress = session.TryGetProperty("mac-address", out var mac) ? mac.GetString() ?? "" : "",
                                IpAddress = session.TryGetProperty("address", out var ip) ? ip.GetString() : null,
                                Username = session.TryGetProperty("user", out var user) ? user.GetString() : null,
                                BytesReceived = session.TryGetProperty("bytes-in", out var bytesIn) ? ParseBytes(bytesIn.GetString()) : 0,
                                BytesSent = session.TryGetProperty("bytes-out", out var bytesOut) ? ParseBytes(bytesOut.GetString()) : 0,
                                Status = "Connected"
                            });
                        }
                    }
                }

                // Also get wireless registrations
                url = BuildUrl("/rest/interface/wireless/registration-table");
                response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var registrations = JsonSerializer.Deserialize<JsonElement[]>(content);

                    if (registrations != null)
                    {
                        foreach (var reg in registrations)
                        {
                            var mac = reg.TryGetProperty("mac-address", out var macProp) ? macProp.GetString() ?? "" : "";
                            if (!clients.Any(c => c.MacAddress.Equals(mac, StringComparison.OrdinalIgnoreCase)))
                            {
                                clients.Add(new WifiClientInfo
                                {
                                    MacAddress = mac,
                                    SSID = reg.TryGetProperty("interface", out var iface) ? iface.GetString() : null,
                                    SignalStrength = reg.TryGetProperty("signal-strength", out var signal) ? ParseSignal(signal.GetString()) : null,
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
            return clients.FirstOrDefault(c => c.MacAddress.Equals(FormatMacAddress(macAddress), StringComparison.OrdinalIgnoreCase));
        }

        public override async Task<bool> SetBandwidthLimitAsync(string macAddress, int downloadKbps, int uploadKbps)
        {
            try
            {
                var formattedMac = FormatMacAddress(macAddress);
                var queueName = $"wifi-{formattedMac.Replace(":", "")}";

                // First, get the IP address for this MAC
                var clientInfo = await GetClientInfoAsync(macAddress);
                if (clientInfo?.IpAddress == null)
                {
                    _logger.LogWarning("Cannot set bandwidth - no IP found for MAC {Mac}", macAddress);
                    return false;
                }

                // Check if queue exists
                var url = BuildUrl($"/rest/queue/simple?name={queueName}");
                var response = await _httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();
                var existing = JsonSerializer.Deserialize<JsonElement[]>(content);

                var queueData = new
                {
                    name = queueName,
                    target = clientInfo.IpAddress,
                    max_limit = $"{uploadKbps}k/{downloadKbps}k",
                    comment = $"WiFi Portal limit for {formattedMac}"
                };

                var jsonContent = new StringContent(JsonSerializer.Serialize(queueData), Encoding.UTF8, "application/json");

                if (existing != null && existing.Length > 0 && existing[0].TryGetProperty(".id", out var idProp))
                {
                    // Update existing
                    url = BuildUrl($"/rest/queue/simple/{idProp.GetString()}");
                    response = await _httpClient.PatchAsync(url, jsonContent);
                }
                else
                {
                    // Create new
                    url = BuildUrl("/rest/queue/simple/add");
                    response = await _httpClient.PostAsync(url, jsonContent);
                }

                return response.IsSuccessStatusCode;
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
                var queueName = $"wifi-{formattedMac.Replace(":", "")}";

                var url = BuildUrl($"/rest/queue/simple?name={queueName}");
                var response = await _httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();
                var existing = JsonSerializer.Deserialize<JsonElement[]>(content);

                if (existing != null && existing.Length > 0 && existing[0].TryGetProperty(".id", out var idProp))
                {
                    url = BuildUrl($"/rest/queue/simple/{idProp.GetString()}");
                    response = await _httpClient.DeleteAsync(url);
                    return response.IsSuccessStatusCode;
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

                // Add to access list with deny
                var url = BuildUrl("/rest/interface/wireless/access-list/add");
                var data = new
                {
                    mac_address = formattedMac,
                    authentication = "no",
                    comment = "WiFi Portal - Blocked"
                };

                var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(url, content);

                // Also disconnect
                await DisconnectUserAsync(macAddress);

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

                var url = BuildUrl($"/rest/interface/wireless/access-list?mac-address={formattedMac}");
                var response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var entries = JsonSerializer.Deserialize<JsonElement[]>(content);

                    if (entries != null)
                    {
                        foreach (var entry in entries)
                        {
                            if (entry.TryGetProperty(".id", out var idProp))
                            {
                                var deleteUrl = BuildUrl($"/rest/interface/wireless/access-list/{idProp.GetString()}");
                                await _httpClient.DeleteAsync(deleteUrl);
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

        private string FormatMacAddress(string mac)
        {
            // MikroTik uses XX:XX:XX:XX:XX:XX format
            mac = mac.Replace("-", ":").ToUpper();
            return mac;
        }

        private long ParseBytes(string? bytesStr)
        {
            if (string.IsNullOrEmpty(bytesStr)) return 0;
            if (long.TryParse(bytesStr, out var bytes)) return bytes;
            return 0;
        }

        private int? ParseSignal(string? signalStr)
        {
            if (string.IsNullOrEmpty(signalStr)) return null;
            // Signal might be like "-65dBm"
            signalStr = signalStr.Replace("dBm", "").Replace("@", " ").Split(' ')[0];
            if (int.TryParse(signalStr, out var signal)) return signal;
            return null;
        }
    }
}