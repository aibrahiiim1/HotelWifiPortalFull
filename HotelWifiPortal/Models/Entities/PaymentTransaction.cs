using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelWifiPortal.Models.Entities
{
    public class PaymentTransaction
    {
        [Key]
        public int Id { get; set; }

        public int GuestId { get; set; }
        public int PaidPackageId { get; set; }

        [MaxLength(50)]
        public string RoomNumber { get; set; } = string.Empty;

        [MaxLength(100)]
        public string ReservationNumber { get; set; } = string.Empty;

        [MaxLength(200)]
        public string? GuestName { get; set; }

        // Transaction details
        [Required]
        [MaxLength(100)]
        public string TransactionId { get; set; } = Guid.NewGuid().ToString("N");

        [MaxLength(100)]
        public string PackageName { get; set; } = string.Empty;

        [Column(TypeName = "decimal(18,2)")]
        public decimal Amount { get; set; }

        [MaxLength(10)]
        public string Currency { get; set; } = "USD";

        // Status
        [MaxLength(50)]
        public string Status { get; set; } = "Pending"; // Pending, Completed, Failed, Refunded, PostedToPMS

        // PMS Posting
        public bool PostedToPMS { get; set; }
        public DateTime? PostedToPMSAt { get; set; }

        [MaxLength(100)]
        public string? PMSPostingId { get; set; }

        public string? PMSResponse { get; set; }

        // Package details snapshot
        public int? DurationHours { get; set; }
        public int? DurationDays { get; set; }
        public double? QuotaGB { get; set; }

        // Time-based package tracking
        public DateTime? ActivatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }

        [MaxLength(50)]
        public string PackageType { get; set; } = "DataBased"; // DataBased, TimeBased, RestOfStay

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? CompletedAt { get; set; }

        // Navigation
        public virtual Guest? Guest { get; set; }
        public virtual PaidPackage? PaidPackage { get; set; }

        // Computed properties
        [NotMapped]
        public bool IsExpired => ExpiresAt.HasValue && DateTime.UtcNow > ExpiresAt.Value;

        [NotMapped]
        public bool IsActive => Status == "Completed" && !IsExpired;

        [NotMapped]
        public TimeSpan? RemainingTime => ExpiresAt.HasValue && !IsExpired
            ? ExpiresAt.Value - DateTime.UtcNow
            : null;

        [NotMapped]
        public string RemainingTimeDisplay
        {
            get
            {
                if (!ExpiresAt.HasValue) return "N/A";
                if (IsExpired) return "Expired";

                var remaining = ExpiresAt.Value - DateTime.UtcNow;
                if (remaining.TotalDays >= 1)
                    return $"{(int)remaining.TotalDays}d {remaining.Hours}h";
                if (remaining.TotalHours >= 1)
                    return $"{(int)remaining.TotalHours}h {remaining.Minutes}m";
                return $"{remaining.Minutes}m";
            }
        }
    }

    /// <summary>
    /// Tracks active paid packages for a guest with expiry
    /// </summary>
    public class GuestPaidPackage
    {
        [Key]
        public int Id { get; set; }

        public int GuestId { get; set; }
        public int PaidPackageId { get; set; }
        public int? TransactionId { get; set; }

        [MaxLength(50)]
        public string RoomNumber { get; set; } = string.Empty;

        [MaxLength(100)]
        public string PackageName { get; set; } = string.Empty;

        [MaxLength(50)]
        public string PackageType { get; set; } = "DataBased"; // DataBased, TimeBased, RestOfStay

        // Quota tracking
        public long QuotaBytes { get; set; }
        public long UsedBytes { get; set; }

        // Speed limits
        public int? DownloadSpeedKbps { get; set; }
        public int? UploadSpeedKbps { get; set; }

        // Time-based tracking
        public DateTime ActivatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? ExpiresAt { get; set; }

        // Status
        [MaxLength(50)]
        public string Status { get; set; } = "Active"; // Active, Expired, Exhausted, Cancelled

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation
        public virtual Guest? Guest { get; set; }
        public virtual PaidPackage? PaidPackage { get; set; }
        public virtual PaymentTransaction? Transaction { get; set; }

        // Computed properties
        [NotMapped]
        public bool IsExpired => ExpiresAt.HasValue && DateTime.UtcNow > ExpiresAt.Value;

        [NotMapped]
        public bool IsQuotaExhausted => QuotaBytes > 0 && UsedBytes >= QuotaBytes;

        [NotMapped]
        public bool IsActive => Status == "Active" && !IsExpired && !IsQuotaExhausted;

        [NotMapped]
        public double QuotaGB => QuotaBytes / 1073741824.0;

        [NotMapped]
        public double UsedGB => UsedBytes / 1073741824.0;

        [NotMapped]
        public double RemainingGB => Math.Max(0, QuotaGB - UsedGB);

        [NotMapped]
        public int QuotaPercentUsed => QuotaBytes > 0 ? (int)((UsedBytes * 100) / QuotaBytes) : 0;

        [NotMapped]
        public TimeSpan? RemainingTime => ExpiresAt.HasValue && !IsExpired
            ? ExpiresAt.Value - DateTime.UtcNow
            : null;

        [NotMapped]
        public string RemainingTimeDisplay
        {
            get
            {
                if (PackageType == "RestOfStay") return "Rest of Stay";
                if (PackageType == "DataBased") return "Data-based";
                if (!ExpiresAt.HasValue) return "N/A";
                if (IsExpired) return "Expired";

                var remaining = ExpiresAt.Value - DateTime.UtcNow;
                if (remaining.TotalDays >= 1)
                    return $"{(int)remaining.TotalDays}d {remaining.Hours}h";
                if (remaining.TotalHours >= 1)
                    return $"{(int)remaining.TotalHours}h {remaining.Minutes}m";
                return $"{remaining.Minutes}m";
            }
        }
    }
}