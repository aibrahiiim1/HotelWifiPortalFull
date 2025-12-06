using HotelWifiPortal.Models.Entities;

namespace HotelWifiPortal.Services.WiFi
{
    // Interface for all WiFi controllers
    public interface IWifiController
    {
        string ControllerType { get; }
        Task<bool> TestConnectionAsync();
        Task<bool> AuthenticateUserAsync(string macAddress, string username, string? password = null);
        Task<bool> DisconnectUserAsync(string macAddress);
        Task<List<WifiClientInfo>> GetConnectedClientsAsync();
        Task<WifiClientInfo?> GetClientInfoAsync(string macAddress);
        Task<bool> SetBandwidthLimitAsync(string macAddress, int downloadKbps, int uploadKbps);
        Task<bool> RemoveBandwidthLimitAsync(string macAddress);
        Task<ClientUsageInfo?> GetClientUsageAsync(string macAddress);
        Task<bool> BlockClientAsync(string macAddress);
        Task<bool> UnblockClientAsync(string macAddress);
    }

    public class WifiClientInfo
    {
        public string MacAddress { get; set; } = string.Empty;
        public string? IpAddress { get; set; }
        public string? Hostname { get; set; }
        public string? Username { get; set; }
        public string? SSID { get; set; }
        public string? AccessPoint { get; set; }
        public DateTime? ConnectedSince { get; set; }
        public string? Uptime { get; set; }
        public long BytesReceived { get; set; }
        public long BytesSent { get; set; }
        public int? SignalStrength { get; set; }
        public string? Status { get; set; }
    }

    public class ClientUsageInfo
    {
        public string MacAddress { get; set; } = string.Empty;
        public long TotalBytesUsed { get; set; }
        public long BytesDownloaded { get; set; }
        public long BytesUploaded { get; set; }
        public TimeSpan SessionDuration { get; set; }
    }

    // Base abstract class for WiFi controllers
    public abstract class WifiControllerBase : IWifiController
    {
        protected readonly ILogger _logger;
        protected readonly WifiControllerSettings _settings;

        public abstract string ControllerType { get; }

        protected WifiControllerBase(WifiControllerSettings settings, ILogger logger)
        {
            _settings = settings;
            _logger = logger;
        }

        public abstract Task<bool> TestConnectionAsync();
        public abstract Task<bool> AuthenticateUserAsync(string macAddress, string username, string? password = null);
        public abstract Task<bool> DisconnectUserAsync(string macAddress);
        public abstract Task<List<WifiClientInfo>> GetConnectedClientsAsync();
        public abstract Task<WifiClientInfo?> GetClientInfoAsync(string macAddress);
        public abstract Task<bool> SetBandwidthLimitAsync(string macAddress, int downloadKbps, int uploadKbps);
        public abstract Task<bool> RemoveBandwidthLimitAsync(string macAddress);
        public abstract Task<ClientUsageInfo?> GetClientUsageAsync(string macAddress);
        public abstract Task<bool> BlockClientAsync(string macAddress);
        public abstract Task<bool> UnblockClientAsync(string macAddress);

        protected string BuildUrl(string path)
        {
            var protocol = _settings.UseHttps ? "https" : "http";
            var port = _settings.Port.HasValue ? $":{_settings.Port}" : "";
            return $"{protocol}://{_settings.IpAddress}{port}{path}";
        }
    }
}