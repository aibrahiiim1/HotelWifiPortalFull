using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelWifiPortal.Models.Entities
{
    // Free quota packages based on stay length
    public class BandwidthPackage
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [MaxLength(500)]
        public string? Description { get; set; }
        
        // Stay length conditions (in days)
        public int MinStayDays { get; set; }
        public int? MaxStayDays { get; set; } // null = unlimited
        
        // Quota in GB
        public double QuotaGB { get; set; }
        
        // Speed limits (in Kbps)
        public int? SpeedLimitKbps { get; set; }
        public int? DownloadSpeedKbps { get; set; }
        public int? UploadSpeedKbps { get; set; }
        
        // Maximum devices allowed per guest with this package
        public int MaxDevices { get; set; } = 3;
        
        // Display
        [MaxLength(20)]
        public string BadgeColor { get; set; } = "primary"; // primary, success, warning, danger, info
        
        [MaxLength(50)]
        public string? Icon { get; set; }
        
        public int SortOrder { get; set; }
        
        // Alias for views using DisplayOrder
        [NotMapped]
        public int DisplayOrder { get => SortOrder; set => SortOrder = value; }
        
        public bool IsActive { get; set; } = true;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        
        [NotMapped]
        public long QuotaBytes => (long)(QuotaGB * 1024 * 1024 * 1024);
        
        // Helper to get effective download speed (use specific or generic)
        [NotMapped]
        public int? EffectiveDownloadKbps => DownloadSpeedKbps ?? SpeedLimitKbps;
        
        // Helper to get effective upload speed (use specific or generic or same as download)
        [NotMapped]
        public int? EffectiveUploadKbps => UploadSpeedKbps ?? SpeedLimitKbps;
    }
    
    // Paid packages for purchase
    public class PaidPackage
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [MaxLength(500)]
        public string? Description { get; set; }
        
        [MaxLength(50)]
        public string PackageType { get; set; } = "TimeBased"; // TimeBased, DataBased, RestOfStay
        
        // Price
        [Column(TypeName = "decimal(18,2)")]
        public decimal Price { get; set; }
        
        [MaxLength(10)]
        public string Currency { get; set; } = "USD";
        
        // Duration (for time-based packages)
        public int? DurationHours { get; set; }
        public int? DurationDays { get; set; }
        
        // Data quota (for data-based packages)
        public double? QuotaGB { get; set; }
        
        // Speed limits (in Kbps)
        public int? SpeedLimitKbps { get; set; }
        public int? DownloadSpeedKbps { get; set; }
        public int? UploadSpeedKbps { get; set; }
        
        // Maximum devices allowed per guest with this package
        public int MaxDevices { get; set; } = 5;
        
        // Display
        [MaxLength(20)]
        public string BadgeColor { get; set; } = "success";
        
        [MaxLength(50)]
        public string? Icon { get; set; }
        
        public int SortOrder { get; set; }
        
        // Alias for views using DisplayOrder
        [NotMapped]
        public int DisplayOrder { get => SortOrder; set => SortOrder = value; }
        
        public bool IsActive { get; set; } = true;
        public bool IsFeatured { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        
        [NotMapped]
        public long? QuotaBytes => QuotaGB.HasValue ? (long)(QuotaGB.Value * 1024 * 1024 * 1024) : null;
        
        // Helper to get effective download speed
        [NotMapped]
        public int? EffectiveDownloadKbps => DownloadSpeedKbps ?? SpeedLimitKbps;
        
        // Helper to get effective upload speed
        [NotMapped]
        public int? EffectiveUploadKbps => UploadSpeedKbps ?? SpeedLimitKbps;
    }
    
    // Bandwidth/Speed profiles for rooms or devices
    public class BandwidthProfile
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [MaxLength(500)]
        public string? Description { get; set; }
        
        // Speed limits in Kbps
        public int DownloadSpeedKbps { get; set; }
        public int UploadSpeedKbps { get; set; }
        
        // Apply to specific rooms (comma-separated) or leave empty for all
        public string? ApplyToRooms { get; set; }
        
        // Apply to VIP levels (comma-separated) - not stored in DB
        [NotMapped]
        public string? ApplyToVipLevels { get; set; }
        
        // Maximum devices per room
        public int? MaxDevicesPerRoom { get; set; }
        
        // Priority (higher = more priority)
        public int Priority { get; set; } = 0;
        
        public bool IsDefault { get; set; }
        public bool IsActive { get; set; } = true;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        
        // Navigation
        public virtual ICollection<WifiSession> WifiSessions { get; set; } = new List<WifiSession>();
        
        [NotMapped]
        public double DownloadSpeedMbps => DownloadSpeedKbps / 1024.0;
        
        [NotMapped]
        public double UploadSpeedMbps => UploadSpeedKbps / 1024.0;
    }
}
