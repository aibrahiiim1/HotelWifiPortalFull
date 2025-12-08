using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelWifiPortal.Models.Entities
{
    public class Guest
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(50)]
        public string RoomNumber { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string ReservationNumber { get; set; } = string.Empty;

        [MaxLength(200)]
        public string GuestName { get; set; } = string.Empty;

        [MaxLength(10)]
        public string Language { get; set; } = "EN";

        public DateTime ArrivalDate { get; set; }
        public DateTime DepartureDate { get; set; }

        [Column(TypeName = "decimal(18,2)")]
        public decimal Balance { get; set; }

        [MaxLength(50)]
        public string Status { get; set; } = "checked-in";

        [MaxLength(50)]
        public string? VipStatus { get; set; }

        [MaxLength(200)]
        public string? Email { get; set; }

        [MaxLength(50)]
        public string? Phone { get; set; }

        public string? Notes { get; set; }

        // WiFi Related
        public long FreeQuotaBytes { get; set; }
        public long UsedQuotaBytes { get; set; }
        public long PaidQuotaBytes { get; set; }
        public bool HasPurchasedPackage { get; set; }

        public DateTime? LastWifiLogin { get; set; }
        public DateTime? QuotaResetDate { get; set; }

        // Assigned bandwidth profile (for speed limits)
        public int? BandwidthProfileId { get; set; }

        // WiFi Password System
        // WifiPassword is the actual password used for WiFi authentication
        // PasswordResetRequired = true means guest must set a new password on first login
        [MaxLength(20)]
        public string? WifiPassword { get; set; }

        public bool PasswordResetRequired { get; set; } = true; // Default: require password reset on first login

        public DateTime? PasswordSetAt { get; set; } // When the password was last set

        // Source: PMS or Local
        [MaxLength(20)]
        public string Source { get; set; } = "PMS";

        // For local authentication (Standalone mode)
        [MaxLength(100)]
        public string? LocalPassword { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        // Navigation properties
        public virtual ICollection<WifiSession> WifiSessions { get; set; } = new List<WifiSession>();
        public virtual ICollection<PaymentTransaction> PaymentTransactions { get; set; } = new List<PaymentTransaction>();
        public virtual ICollection<UsageLog> UsageLogs { get; set; } = new List<UsageLog>();

        // Calculated properties
        [NotMapped]
        public int StayLength => (DepartureDate.Date - ArrivalDate.Date).Days;

        [NotMapped]
        public long TotalQuotaBytes => FreeQuotaBytes + PaidQuotaBytes;

        [NotMapped]
        public long RemainingQuotaBytes => Math.Max(0, TotalQuotaBytes - UsedQuotaBytes);

        [NotMapped]
        public double UsedQuotaGB => UsedQuotaBytes / (1024.0 * 1024.0 * 1024.0);

        [NotMapped]
        public double RemainingQuotaGB => RemainingQuotaBytes / (1024.0 * 1024.0 * 1024.0);

        [NotMapped]
        public double TotalQuotaGB => TotalQuotaBytes / (1024.0 * 1024.0 * 1024.0);

        [NotMapped]
        public bool IsQuotaExhausted => RemainingQuotaBytes <= 0;

        // Aliases for view compatibility
        [NotMapped]
        public DateTime CheckInDate { get => ArrivalDate; set => ArrivalDate = value; }

        [NotMapped]
        public DateTime CheckOutDate { get => DepartureDate; set => DepartureDate = value; }

        [NotMapped]
        public bool AcceptedTerms { get; set; }

        [NotMapped]
        public DateTime? FirstLoginAt { get => LastWifiLogin; set => LastWifiLogin = value; }

        [NotMapped]
        public string? CurrentPackage { get; set; }

        /// <summary>
        /// Check if guest needs to set a new password
        /// </summary>
        [NotMapped]
        public bool NeedsPasswordReset => PasswordResetRequired || string.IsNullOrEmpty(WifiPassword);
    }
}