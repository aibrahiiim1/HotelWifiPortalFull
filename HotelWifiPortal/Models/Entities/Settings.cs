using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelWifiPortal.Models.Entities
{
    // System settings
    public class SystemSetting
    {
        [Key]
        [MaxLength(100)]
        public string Key { get; set; } = string.Empty;
        
        public string? Value { get; set; }
        
        [MaxLength(50)]
        public string? Category { get; set; }
        
        [MaxLength(500)]
        public string? Description { get; set; }
        
        [MaxLength(50)]
        public string ValueType { get; set; } = "string"; // string, int, bool, json
        
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
    
    // WiFi Controller settings
    public class WifiControllerSettings
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(50)]
        public string ControllerType { get; set; } = string.Empty; // Ruckus, RuckusZD, Mikrotik, ExtremeCloud
        
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [MaxLength(200)]
        public string? IpAddress { get; set; }
        
        public int? Port { get; set; }
        
        [MaxLength(100)]
        public string? Username { get; set; }
        
        [MaxLength(200)]
        public string? Password { get; set; }
        
        [MaxLength(500)]
        public string? ApiKey { get; set; }
        
        [MaxLength(500)]
        public string? ApiUrl { get; set; }
        
        // MikroTik Hotspot settings
        [MaxLength(100)]
        public string? HotspotServer { get; set; }
        
        [MaxLength(100)]
        public string? UserProfile { get; set; }
        
        // Default SSID for guest authentication - not stored in DB
        [NotMapped]
        public string? DefaultSSID { get; set; }
        
        // SSL/TLS
        public bool UseHttps { get; set; } = false;  // Default to HTTP
        public bool IgnoreSslErrors { get; set; } = true;  // Default to ignore SSL errors
        
        // Status
        public bool IsEnabled { get; set; } = true;  // Default to enabled
        public bool IsDefault { get; set; }
        public DateTime? LastConnectionTest { get; set; }
        
        [MaxLength(50)]
        public string? ConnectionStatus { get; set; }
        
        // Additional settings as JSON
        public string? AdditionalSettings { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
    
    // PMS Settings (FIAS)
    public class PmsSettings
    {
        [Key]
        public int Id { get; set; }
        
        [MaxLength(50)]
        public string PmsType { get; set; } = "Protel"; // Protel, Opera, Other
        
        [MaxLength(100)]
        public string Name { get; set; } = "PMS Connection";
        
        // FIAS Server settings
        public int ListenPort { get; set; } = 5008;
        
        [MaxLength(50)]
        public string ListenIpAddress { get; set; } = "0.0.0.0";
        
        [MaxLength(10)]
        public string InterfaceType { get; set; } = "WW";
        
        [MaxLength(20)]
        public string Version { get; set; } = "1.0";
        
        [MaxLength(20)]
        public string CharacterSet { get; set; } = "UTF-8";
        
        public int DecimalPoint { get; set; } = 2;
        
        // Operation mode
        public bool IsEnabled { get; set; } = true;
        public bool IsPmsModeEnabled { get; set; } = true; // vs Standalone mode
        
        // Posting settings
        public bool AutoPostCharges { get; set; } = true;
        
        [MaxLength(10)]
        public string PostingCurrency { get; set; } = "USD";
        
        [MaxLength(50)]
        public string? PostingRevenueCenter { get; set; }
        
        [MaxLength(100)]
        public string? PostingDescription { get; set; } = "WiFi Internet Access";
        
        // Connection status
        public bool IsConnected { get; set; }
        public DateTime? LastConnectionTime { get; set; }
        public DateTime? LastMessageTime { get; set; }
        
        [MaxLength(50)]
        public string? ClientIpAddress { get; set; }
        
        public int MessagesSent { get; set; }
        public int MessagesReceived { get; set; }
        
        // Posting identifier option
        public bool PostByReservationNumber { get; set; } = false; // false = by Room, true = by Reservation#
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
    
    // Admin users (for local login without PMS)
    public class AdminUser
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(200)]
        public string PasswordHash { get; set; } = string.Empty;
        
        [MaxLength(200)]
        public string? Email { get; set; }
        
        [MaxLength(100)]
        public string? FullName { get; set; }
        
        [MaxLength(50)]
        public string Role { get; set; } = "Admin"; // SuperAdmin, Admin, Manager, Viewer
        
        public bool IsActive { get; set; } = true;
        
        public DateTime? LastLogin { get; set; }
        
        [MaxLength(50)]
        public string? LastLoginIp { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }
    
    // Local guest users (for standalone mode)
    public class LocalUser
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(200)]
        public string PasswordHash { get; set; } = string.Empty;
        
        [MaxLength(200)]
        public string? FullName { get; set; }
        
        [MaxLength(200)]
        public string? Email { get; set; }
        
        [MaxLength(50)]
        public string? Phone { get; set; }
        
        [MaxLength(50)]
        public string UserType { get; set; } = "Guest"; // Guest, Manager, Visitor, Staff
        
        // Optional room assignment
        [MaxLength(50)]
        public string? RoomNumber { get; set; }
        
        // Quota and usage
        public long QuotaBytes { get; set; }
        public long UsedQuotaBytes { get; set; }
        
        // Speed limits (Kbps)
        public int? DownloadSpeedKbps { get; set; }
        public int? UploadSpeedKbps { get; set; }
        
        // Device limits
        public int MaxDevices { get; set; } = 3;
        public int CurrentDevices { get; set; } = 0;
        
        // Alias for views expecting QuotaGB
        [NotMapped]
        public double QuotaGB 
        { 
            get => QuotaBytes / 1073741824.0;
            set => QuotaBytes = (long)(value * 1073741824);
        }
        
        [NotMapped]
        public double UsedQuotaGB => UsedQuotaBytes / 1073741824.0;
        
        [NotMapped]
        public double RemainingQuotaGB => Math.Max(0, QuotaGB - UsedQuotaGB);
        
        [NotMapped]
        public bool IsQuotaExceeded => QuotaBytes > 0 && UsedQuotaBytes >= QuotaBytes;
        
        // Validity
        public DateTime? ValidFrom { get; set; }
        public DateTime? ValidUntil { get; set; }
        
        public bool IsActive { get; set; } = true;
        
        public DateTime? LastLogin { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }

    // Blocked MAC addresses
    public class BlockedMac
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(50)]
        public string MacAddress { get; set; } = string.Empty;
        
        [MaxLength(500)]
        public string? Reason { get; set; }
        
        [MaxLength(50)]
        public string? BlockedBy { get; set; } // Username who blocked
        
        [MaxLength(50)]
        public string? RoomNumber { get; set; } // Room when blocked (optional)
        
        [MaxLength(100)]
        public string? GuestName { get; set; } // Guest name when blocked (optional)
        
        public bool IsActive { get; set; } = true;
        
        public DateTime BlockedAt { get; set; } = DateTime.UtcNow;
        
        public DateTime? UnblockedAt { get; set; }
        
        [MaxLength(50)]
        public string? UnblockedBy { get; set; }
    }
}
