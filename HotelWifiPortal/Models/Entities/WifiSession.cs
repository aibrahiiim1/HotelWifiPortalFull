using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelWifiPortal.Models.Entities
{
    public class WifiSession
    {
        [Key]
        public int Id { get; set; }

        public int GuestId { get; set; }

        [MaxLength(50)]
        public string RoomNumber { get; set; } = string.Empty;

        [MaxLength(100)]
        public string? GuestName { get; set; }

        [Required]
        [MaxLength(50)]
        public string MacAddress { get; set; } = string.Empty;

        [MaxLength(50)]
        public string? IpAddress { get; set; }

        [MaxLength(100)]
        public string? DeviceName { get; set; }

        [MaxLength(50)]
        public string? DeviceType { get; set; }

        // Session status
        [MaxLength(20)]
        public string Status { get; set; } = "Active"; // Active, Disconnected, Blocked, Expired

        public DateTime SessionStart { get; set; } = DateTime.UtcNow;
        public DateTime? SessionEnd { get; set; }
        public DateTime LastActivity { get; set; } = DateTime.UtcNow;

        // Usage tracking
        public long BytesUsed { get; set; }
        public long BytesUploaded { get; set; }
        public long BytesDownloaded { get; set; }

        // Speed limiting
        public int? SpeedLimitKbps { get; set; }
        public int? BandwidthProfileId { get; set; }

        // WiFi Controller info
        [MaxLength(50)]
        public string? ControllerType { get; set; } // Ruckus, Mikrotik, ExtremeCloud

        [MaxLength(100)]
        public string? AccessPointName { get; set; }

        [MaxLength(100)]
        public string? SSID { get; set; }

        // Navigation properties
        public virtual Guest? Guest { get; set; }
        public virtual BandwidthProfile? BandwidthProfile { get; set; }

        [NotMapped]
        public double BytesUsedMB => BytesUsed / (1024.0 * 1024.0);

        [NotMapped]
        public double BytesUsedGB => BytesUsed / (1024.0 * 1024.0 * 1024.0);

        [NotMapped]
        public TimeSpan? SessionDuration => SessionEnd.HasValue
            ? SessionEnd.Value - SessionStart
            : DateTime.UtcNow - SessionStart;

        [NotMapped]
        public bool IsActive => Status == "Active" && !SessionEnd.HasValue;
    }
}