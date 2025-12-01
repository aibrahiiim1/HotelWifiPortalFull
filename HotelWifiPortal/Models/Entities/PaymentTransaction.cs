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
        public double? QuotaGB { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? CompletedAt { get; set; }
        
        // Navigation
        public virtual Guest? Guest { get; set; }
        public virtual PaidPackage? PaidPackage { get; set; }
    }
}
