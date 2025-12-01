using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelWifiPortal.Models.Entities
{
    public class UsageLog
    {
        [Key]
        public int Id { get; set; }

        public int? GuestId { get; set; }
        public int? WifiSessionId { get; set; }

        [MaxLength(50)]
        public string? RoomNumber { get; set; }

        [MaxLength(50)]
        public string? MacAddress { get; set; }

        // Usage data
        public long BytesUsed { get; set; }
        public long BytesUploaded { get; set; }
        public long BytesDownloaded { get; set; }

        // Time period
        public DateTime PeriodStart { get; set; }
        public DateTime PeriodEnd { get; set; }

        // Alias for views expecting Timestamp
        [NotMapped]
        public DateTime Timestamp { get => PeriodStart; set => PeriodStart = value; }

        // Additional properties for display
        [NotMapped]
        public string? GuestName { get; set; }

        [NotMapped]
        public int? SessionDuration { get; set; } // In minutes

        [MaxLength(20)]
        public string PeriodType { get; set; } = "Hourly"; // Hourly, Daily, Session

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Navigation
        public virtual Guest? Guest { get; set; }
        public virtual WifiSession? WifiSession { get; set; }
    }

    // System logs
    public class SystemLog
    {
        [Key]
        public int Id { get; set; }

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [MaxLength(20)]
        public string Level { get; set; } = "INFO"; // INFO, WARN, ERROR, DEBUG

        [MaxLength(100)]
        public string? Source { get; set; }

        [MaxLength(100)]
        public string? Category { get; set; } // PMS, WiFi, Auth, Payment, System

        [Required]
        public string Message { get; set; } = string.Empty;

        public string? Details { get; set; }

        // Not stored in DB - for display only
        [NotMapped]
        public string? StackTrace { get; set; }

        public string? RawData { get; set; }

        [MaxLength(50)]
        public string? UserId { get; set; }

        [MaxLength(50)]
        public string? IpAddress { get; set; }
    }
}