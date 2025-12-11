using HotelWifiPortal.Models.Entities;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelWifiPortal.Models.ViewModels
{
    // Admin Guest Edit ViewModel
    public class GuestEditViewModel
    {
        public Guest Guest { get; set; } = new();
        
        // For dropdowns
        public List<SelectListItem> FreePackages { get; set; } = new();
        public List<SelectListItem> BandwidthProfiles { get; set; } = new();
        
        // Selected values
        public int? SelectedFreePackageId { get; set; }
        public int? SelectedBandwidthProfileId { get; set; }
        
        // Manual quota override
        public double TotalQuotaGB { get; set; }
        
        // Reset usage option
        public bool ResetUsage { get; set; }
    }

    // Portal ViewModels
    public class GuestLoginViewModel
    {
        [Required(ErrorMessage = "Room number is required")]
        [Display(Name = "Room Number")]
        public string RoomNumber { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [Display(Name = "Reservation Number / Password")]
        public string Password { get; set; } = string.Empty;

        // Client info from MikroTik redirect
        public string? MacAddress { get; set; }
        public string? ClientIp { get; set; }
        public string? ReturnUrl { get; set; }
        public string? LinkLogin { get; set; }      // MikroTik login URL
        public string? LinkOrig { get; set; }       // Original destination
        public string? SSID { get; set; }
        
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// ViewModel for guest to set their WiFi password on first login
    /// </summary>
    public class SetPasswordViewModel
    {
        public int GuestId { get; set; }
        public string RoomNumber { get; set; } = string.Empty;
        public string GuestName { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "Password is required")]
        [MinLength(5, ErrorMessage = "Password must be at least 5 digits")]
        [MaxLength(20, ErrorMessage = "Password cannot exceed 20 digits")]
        [RegularExpression(@"^\d+$", ErrorMessage = "Password must contain only numbers (no letters or special characters)")]
        [Display(Name = "New WiFi Password")]
        public string NewPassword { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "Please confirm your password")]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;
        
        // Pass through MikroTik parameters
        public string? MacAddress { get; set; }
        public string? ClientIp { get; set; }
        public string? LinkLogin { get; set; }
        public string? LinkOrig { get; set; }
        
        public string? ErrorMessage { get; set; }
    }

    public class GuestDashboardViewModel
    {
        public Guest Guest { get; set; } = new();
        public BandwidthPackage? CurrentPackage { get; set; }
        public double UsedQuotaGB { get; set; }
        public double TotalQuotaGB { get; set; }
        public double RemainingQuotaGB { get; set; }
        public int UsagePercentage { get; set; }
        public bool IsQuotaExhausted { get; set; }
        public List<WifiSession> ActiveSessions { get; set; } = new();
        public List<PaidPackage> AvailablePackages { get; set; } = new();
    }

    public class PaywallViewModel
    {
        public Guest Guest { get; set; } = new();
        public double UsedQuotaGB { get; set; }
        public double TotalQuotaGB { get; set; }
        public double RemainingQuotaGB { get; set; }
        public int UsagePercentage { get; set; }
        public List<PaidPackage> AvailablePackages { get; set; } = new();
        public string? ErrorMessage { get; set; }
    }

    public class PurchaseConfirmViewModel
    {
        public Guest Guest { get; set; } = new();
        public PaidPackage Package { get; set; } = new();
        public PaymentTransaction? Transaction { get; set; }
    }

    // Admin ViewModels
    public class AdminLoginViewModel
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        public bool RememberMe { get; set; }
        public string? ReturnUrl { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class AdminDashboardViewModel
    {
        // Stats
        public int TotalGuests { get; set; }
        public int CheckedInGuests { get; set; }
        public int ActiveSessions { get; set; }
        public decimal TodayRevenue { get; set; }
        public decimal MonthRevenue { get; set; }

        // PMS Status
        public bool PmsConnected { get; set; }
        public string PmsStatus { get; set; } = "disconnected";
        public int MessagesSent { get; set; }
        public int MessagesReceived { get; set; }
        
        // Pending PMS Postings
        public int PendingPmsPostings { get; set; }
        public decimal PendingPmsAmount { get; set; }

        // WiFi Controller Status
        public List<WifiControllerStatus> WifiControllers { get; set; } = new();

        // Recent Activity
        public List<Guest> RecentGuests { get; set; } = new();
        public List<WifiSession> RecentSessions { get; set; } = new();
        public List<PaymentTransaction> RecentTransactions { get; set; } = new();
        public List<SystemLog> RecentLogs { get; set; } = new();
    }

    public class WifiControllerStatus
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public bool IsConnected { get; set; }
        public string Status { get; set; } = "unknown";
    }

    public class GuestListViewModel
    {
        public List<Guest> Guests { get; set; } = new();
        public string? SearchTerm { get; set; }
        public string? StatusFilter { get; set; }
        public int TotalCount { get; set; }
        public int PageNumber { get; set; } = 1;
        public int PageSize { get; set; } = 20;
        public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
    }

    public class SessionListViewModel
    {
        public List<WifiSession> Sessions { get; set; } = new();
        public string? StatusFilter { get; set; }
        public string? RoomFilter { get; set; }
        public int TotalCount { get; set; }
        public int PageNumber { get; set; } = 1;
        public int PageSize { get; set; } = 20;
    }

    public class PackageEditViewModel
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;

        [MaxLength(500)]
        public string? Description { get; set; }

        public int MinStayDays { get; set; }
        public int? MaxStayDays { get; set; }

        [Range(0, 1000)]
        public double QuotaGB { get; set; }

        // Speed limits
        public int? SpeedLimitKbps { get; set; }
        public int? DownloadSpeedKbps { get; set; }
        public int? UploadSpeedKbps { get; set; }
        
        // Max devices
        [Range(1, 20)]
        public int MaxDevices { get; set; } = 3;
        
        // Sharing options
        public bool SharedUsage { get; set; } = true;
        public bool SharedBandwidth { get; set; } = true;

        [MaxLength(20)]
        public string BadgeColor { get; set; } = "primary";

        public int SortOrder { get; set; }
        
        // Alias for views that use DisplayOrder
        public int DisplayOrder { get => SortOrder; set => SortOrder = value; }
        
        public bool IsActive { get; set; } = true;
    }

    public class PaidPackageEditViewModel
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;

        [MaxLength(500)]
        public string? Description { get; set; }

        [MaxLength(50)]
        public string PackageType { get; set; } = "TimeBased";

        [Range(0.01, 10000)]
        public decimal Price { get; set; }

        [MaxLength(10)]
        public string Currency { get; set; } = "USD";

        public int? DurationHours { get; set; }
        public int? DurationDays { get; set; }
        public double? QuotaGB { get; set; }
        
        // Speed limits
        public int? SpeedLimitKbps { get; set; }
        public int? DownloadSpeedKbps { get; set; }
        public int? UploadSpeedKbps { get; set; }
        
        // Max devices
        [Range(1, 20)]
        public int MaxDevices { get; set; } = 5;
        
        // Sharing options
        public bool SharedUsage { get; set; } = true;
        public bool SharedBandwidth { get; set; } = true;

        [MaxLength(20)]
        public string BadgeColor { get; set; } = "success";

        public int SortOrder { get; set; }
        
        // Alias for views that use DisplayOrder
        public int DisplayOrder { get => SortOrder; set => SortOrder = value; }
        
        public bool IsActive { get; set; } = true;
        public bool IsFeatured { get; set; }
    }

    public class BandwidthProfileEditViewModel
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;

        [MaxLength(500)]
        public string? Description { get; set; }

        [Range(64, 1000000)]
        public int DownloadSpeedKbps { get; set; }

        [Range(64, 1000000)]
        public int UploadSpeedKbps { get; set; }

        public string? ApplyToRooms { get; set; }
        public string? ApplyToVipLevels { get; set; }
        public int? MaxDevicesPerRoom { get; set; }
        public int Priority { get; set; }
        public bool IsDefault { get; set; }
        public bool IsActive { get; set; } = true;
    }

    public class WifiSettingsViewModel
    {
        public int Id { get; set; }

        [MaxLength(50)]
        public string ControllerType { get; set; } = string.Empty;

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

        public bool UseHttps { get; set; } = false;  // Default to HTTP
        public bool IgnoreSslErrors { get; set; } = true;  // Default to ignore
        public bool IsEnabled { get; set; } = true;  // Default to enabled
        public bool IsDefault { get; set; } = false;
        
        // Status (read-only, for display)
        public string? ConnectionStatus { get; set; }
        public DateTime? LastConnectionTest { get; set; }
    }

    public class PmsSettingsViewModel
    {
        public int Id { get; set; }

        [MaxLength(50)]
        public string PmsType { get; set; } = "Protel";

        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = "PMS Connection";

        [Range(1, 65535)]
        public int ListenPort { get; set; } = 5008;

        [MaxLength(50)]
        public string ListenIpAddress { get; set; } = "0.0.0.0";

        public bool IsEnabled { get; set; } = true;
        public bool IsPmsModeEnabled { get; set; } = true;
        public bool AutoPostCharges { get; set; } = true;
        public bool PostByReservationNumber { get; set; } = false;

        [MaxLength(10)]
        public string PostingCurrency { get; set; } = "USD";

        [MaxLength(100)]
        public string? PostingDescription { get; set; }

        // Status (read-only)
        public bool IsConnected { get; set; }
        public DateTime? LastConnectionTime { get; set; }
        public int MessagesSent { get; set; }
        public int MessagesReceived { get; set; }
        public string? ClientIpAddress { get; set; }
    }

    public class AdminUserEditViewModel
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Username { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
        public string? Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string? ConfirmPassword { get; set; }

        [MaxLength(200)]
        [EmailAddress]
        public string? Email { get; set; }

        [MaxLength(100)]
        public string? FullName { get; set; }

        [Required]
        public string Role { get; set; } = "Admin";

        public bool IsActive { get; set; } = true;
    }

    public class LocalUserEditViewModel
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Username { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        public string? Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string? ConfirmPassword { get; set; }

        [MaxLength(200)]
        public string? FullName { get; set; }

        [MaxLength(200)]
        [EmailAddress]
        public string? Email { get; set; }

        [MaxLength(50)]
        public string? Phone { get; set; }

        [MaxLength(50)]
        public string UserType { get; set; } = "Guest"; // Guest, Manager, Visitor, Staff

        [MaxLength(50)]
        public string? RoomNumber { get; set; }

        public double QuotaGB { get; set; }
        
        // Speed limits (Kbps)
        [Display(Name = "Download Speed (Kbps)")]
        public int? DownloadSpeedKbps { get; set; }
        
        [Display(Name = "Upload Speed (Kbps)")]
        public int? UploadSpeedKbps { get; set; }
        
        // Device limits
        [Display(Name = "Max Devices")]
        [Range(1, 10)]
        public int MaxDevices { get; set; } = 3;

        public DateTime? ValidFrom { get; set; }
        public DateTime? ValidUntil { get; set; }

        public bool IsActive { get; set; } = true;
    }
    
    public class BatchLocalUserViewModel
    {
        [Required]
        [MaxLength(50)]
        [Display(Name = "Username Prefix")]
        public string UsernamePrefix { get; set; } = "user";
        
        [Required]
        [Range(1, 100)]
        [Display(Name = "Number of Users")]
        public int Count { get; set; } = 10;
        
        [Required]
        [Range(4, 20)]
        [Display(Name = "Password Length")]
        public int PasswordLength { get; set; } = 8;
        
        [MaxLength(50)]
        public string UserType { get; set; } = "Guest";
        
        public double QuotaGB { get; set; } = 5;
        
        [Display(Name = "Download Speed (Kbps)")]
        public int? DownloadSpeedKbps { get; set; } = 10240;
        
        [Display(Name = "Upload Speed (Kbps)")]
        public int? UploadSpeedKbps { get; set; } = 5120;
        
        [Display(Name = "Max Devices")]
        [Range(1, 10)]
        public int MaxDevices { get; set; } = 3;
        
        public DateTime? ValidFrom { get; set; }
        public DateTime? ValidUntil { get; set; }
        
        public bool IsActive { get; set; } = true;
    }

    public class LogsViewModel
    {
        public List<SystemLog> Logs { get; set; } = new();
        
        // Properties used by the new views
        public string? Level { get; set; }
        public string? Category { get; set; }
        public string? Search { get; set; }
        public int Page { get; set; } = 1;
        
        // Properties for backward compatibility with old code
        public string? LevelFilter { get => Level; set => Level = value; }
        public string? CategoryFilter { get => Category; set => Category = value; }
        public string? SearchTerm { get => Search; set => Search = value; }
        public int PageNumber { get => Page; set => Page = value; }
        
        public DateTime? FromDate { get; set; }
        public DateTime? ToDate { get; set; }
        public int TotalCount { get; set; }
        public int PageSize { get; set; } = 50;
        public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
    }

    public class SystemSettingsViewModel
    {
        public string HotelName { get; set; } = string.Empty;
        
        // Properties used by the new views
        public string? LogoUrl { get; set; }
        public int MaxDevicesPerRoom { get; set; } = 5;
        
        // Properties for backward compatibility with old code
        public string? HotelLogo { get => LogoUrl; set => LogoUrl = value; }
        public int MaxDevicesPerGuest { get => MaxDevicesPerRoom; set => MaxDevicesPerRoom = value; }
        public bool EnableStandaloneMode { get; set; }
        public string DefaultLanguage { get; set; } = "en";
        public string TimeZone { get; set; } = "UTC";
        
        public string? WelcomeMessage { get; set; }
        public string? SupportEmail { get; set; }
        public string? SupportPhone { get; set; }
        public int SessionTimeoutMinutes { get; set; } = 1440;
        
        public int? DefaultBandwidthProfileId { get; set; }
        public List<BandwidthProfile>? BandwidthProfiles { get; set; }
        
        public bool RequireTermsAcceptance { get; set; }
        public bool AllowGuestRegistration { get; set; }
        public bool EnablePaywall { get; set; } = true;
        public bool EnableBandwidthLimiting { get; set; } = true;
        
        /// <summary>
        /// When enabled, guests must set a new WiFi password on first login.
        /// When disabled, guests can login directly with their reservation number.
        /// </summary>
        public bool RequirePasswordResetOnFirstLogin { get; set; } = true;
        
        public string? TermsAndConditions { get; set; }
    }
}
