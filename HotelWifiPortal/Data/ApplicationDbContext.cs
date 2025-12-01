using HotelWifiPortal.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Guests
        public DbSet<Guest> Guests { get; set; }
        
        // WiFi Sessions
        public DbSet<WifiSession> WifiSessions { get; set; }
        
        // Packages
        public DbSet<BandwidthPackage> BandwidthPackages { get; set; }
        public DbSet<PaidPackage> PaidPackages { get; set; }
        public DbSet<BandwidthProfile> BandwidthProfiles { get; set; }
        
        // Transactions
        public DbSet<PaymentTransaction> PaymentTransactions { get; set; }
        
        // Logs
        public DbSet<UsageLog> UsageLogs { get; set; }
        public DbSet<SystemLog> SystemLogs { get; set; }
        
        // Settings
        public DbSet<SystemSetting> SystemSettings { get; set; }
        public DbSet<WifiControllerSettings> WifiControllerSettings { get; set; }
        public DbSet<PmsSettings> PmsSettings { get; set; }
        
        // Users
        public DbSet<AdminUser> AdminUsers { get; set; }
        public DbSet<LocalUser> LocalUsers { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Guest indexes
            modelBuilder.Entity<Guest>()
                .HasIndex(g => g.RoomNumber);
            
            modelBuilder.Entity<Guest>()
                .HasIndex(g => g.ReservationNumber)
                .IsUnique();
            
            modelBuilder.Entity<Guest>()
                .HasIndex(g => g.Status);

            // WifiSession indexes
            modelBuilder.Entity<WifiSession>()
                .HasIndex(s => s.MacAddress);
            
            modelBuilder.Entity<WifiSession>()
                .HasIndex(s => s.Status);
            
            modelBuilder.Entity<WifiSession>()
                .HasIndex(s => s.RoomNumber);

            // PaymentTransaction
            modelBuilder.Entity<PaymentTransaction>()
                .HasIndex(p => p.TransactionId)
                .IsUnique();

            // SystemLog indexes
            modelBuilder.Entity<SystemLog>()
                .HasIndex(l => l.Timestamp);
            
            modelBuilder.Entity<SystemLog>()
                .HasIndex(l => l.Level);
            
            modelBuilder.Entity<SystemLog>()
                .HasIndex(l => l.Category);

            // AdminUser
            modelBuilder.Entity<AdminUser>()
                .HasIndex(u => u.Username)
                .IsUnique();

            // LocalUser
            modelBuilder.Entity<LocalUser>()
                .HasIndex(u => u.Username)
                .IsUnique();

            // Seed default data
            SeedDefaultData(modelBuilder);
        }

        private void SeedDefaultData(ModelBuilder modelBuilder)
        {
            // Default bandwidth packages (free quotas)
            modelBuilder.Entity<BandwidthPackage>().HasData(
                new BandwidthPackage
                {
                    Id = 1,
                    Name = "Short Stay",
                    Description = "For stays less than 7 days",
                    MinStayDays = 0,
                    MaxStayDays = 6,
                    QuotaGB = 3,
                    BadgeColor = "primary",
                    Icon = "bi-clock",
                    SortOrder = 1,
                    IsActive = true
                },
                new BandwidthPackage
                {
                    Id = 2,
                    Name = "Standard Stay",
                    Description = "For stays between 7-10 days",
                    MinStayDays = 7,
                    MaxStayDays = 10,
                    QuotaGB = 5,
                    BadgeColor = "success",
                    Icon = "bi-calendar-check",
                    SortOrder = 2,
                    IsActive = true
                },
                new BandwidthPackage
                {
                    Id = 3,
                    Name = "Extended Stay",
                    Description = "For stays more than 10 days",
                    MinStayDays = 11,
                    MaxStayDays = null,
                    QuotaGB = 8,
                    BadgeColor = "warning",
                    Icon = "bi-calendar-range",
                    SortOrder = 3,
                    IsActive = true
                }
            );

            // Default paid packages
            modelBuilder.Entity<PaidPackage>().HasData(
                new PaidPackage
                {
                    Id = 1,
                    Name = "1-Day Pass",
                    Description = "24 hours of unlimited internet access",
                    PackageType = "TimeBased",
                    Price = 5.00m,
                    Currency = "USD",
                    DurationDays = 1,
                    DurationHours = 24,
                    BadgeColor = "info",
                    Icon = "bi-calendar-day",
                    SortOrder = 1,
                    IsActive = true,
                    IsFeatured = false
                },
                new PaidPackage
                {
                    Id = 2,
                    Name = "Rest of Stay",
                    Description = "Unlimited internet until checkout",
                    PackageType = "RestOfStay",
                    Price = 20.00m,
                    Currency = "USD",
                    BadgeColor = "success",
                    Icon = "bi-infinity",
                    SortOrder = 2,
                    IsActive = true,
                    IsFeatured = true
                },
                new PaidPackage
                {
                    Id = 3,
                    Name = "5GB Data Pack",
                    Description = "Additional 5GB data quota",
                    PackageType = "DataBased",
                    Price = 10.00m,
                    Currency = "USD",
                    QuotaGB = 5,
                    BadgeColor = "primary",
                    Icon = "bi-database-add",
                    SortOrder = 3,
                    IsActive = true,
                    IsFeatured = false
                }
            );

            // Default bandwidth profile
            modelBuilder.Entity<BandwidthProfile>().HasData(
                new BandwidthProfile
                {
                    Id = 1,
                    Name = "Standard",
                    Description = "Default bandwidth profile for all guests",
                    DownloadSpeedKbps = 10240, // 10 Mbps
                    UploadSpeedKbps = 5120,    // 5 Mbps
                    MaxDevicesPerRoom = 5,
                    IsDefault = true,
                    IsActive = true
                },
                new BandwidthProfile
                {
                    Id = 2,
                    Name = "VIP",
                    Description = "High-speed profile for VIP guests",
                    DownloadSpeedKbps = 51200, // 50 Mbps
                    UploadSpeedKbps = 25600,   // 25 Mbps
                    MaxDevicesPerRoom = 10,
                    Priority = 10,
                    IsDefault = false,
                    IsActive = true
                },
                new BandwidthProfile
                {
                    Id = 3,
                    Name = "Limited",
                    Description = "Basic bandwidth for staff/visitors",
                    DownloadSpeedKbps = 2048,  // 2 Mbps
                    UploadSpeedKbps = 1024,    // 1 Mbps
                    MaxDevicesPerRoom = 2,
                    Priority = -10,
                    IsDefault = false,
                    IsActive = true
                }
            );

            // Default PMS settings
            modelBuilder.Entity<PmsSettings>().HasData(
                new PmsSettings
                {
                    Id = 1,
                    PmsType = "Protel",
                    Name = "Protel PMS",
                    ListenPort = 5008,
                    ListenIpAddress = "0.0.0.0",
                    InterfaceType = "WW",
                    Version = "1.0",
                    CharacterSet = "UTF-8",
                    DecimalPoint = 2,
                    IsEnabled = true,
                    IsPmsModeEnabled = true,
                    AutoPostCharges = true,
                    PostingCurrency = "USD",
                    PostingDescription = "WiFi Internet Access"
                }
            );

            // Default admin user (password: admin123)
            modelBuilder.Entity<AdminUser>().HasData(
                new AdminUser
                {
                    Id = 1,
                    Username = "admin",
                    PasswordHash = BCryptHelper.HashPassword("admin123"),
                    Email = "admin@hotel.com",
                    FullName = "System Administrator",
                    Role = "SuperAdmin",
                    IsActive = true
                }
            );

            // System settings
            modelBuilder.Entity<SystemSetting>().HasData(
                new SystemSetting { Key = "HotelName", Value = "Grand Hotel", Category = "General", Description = "Hotel name displayed on portal" },
                new SystemSetting { Key = "HotelLogo", Value = "/images/logo.png", Category = "General", Description = "Hotel logo path" },
                new SystemSetting { Key = "WelcomeMessage", Value = "Welcome to our hotel WiFi!", Category = "Portal", Description = "Welcome message on login page" },
                new SystemSetting { Key = "SupportEmail", Value = "support@hotel.com", Category = "General", Description = "Support email" },
                new SystemSetting { Key = "SupportPhone", Value = "+1-234-567-8900", Category = "General", Description = "Support phone" },
                new SystemSetting { Key = "SessionTimeoutMinutes", Value = "1440", Category = "WiFi", ValueType = "int", Description = "WiFi session timeout in minutes" },
                new SystemSetting { Key = "MaxDevicesPerGuest", Value = "5", Category = "WiFi", ValueType = "int", Description = "Maximum devices per guest" },
                new SystemSetting { Key = "EnableStandaloneMode", Value = "false", Category = "System", ValueType = "bool", Description = "Enable standalone mode without PMS" },
                new SystemSetting { Key = "DefaultLanguage", Value = "en", Category = "General", Description = "Default language" },
                new SystemSetting { Key = "TimeZone", Value = "UTC", Category = "General", Description = "System timezone" }
            );
        }
    }

    // Simple BCrypt helper for password hashing
    public static class BCryptHelper
    {
        public static string HashPassword(string password)
        {
            // Simple hash for seeding - in production use proper BCrypt
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hashedBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password + "HotelWifiSalt"));
            return Convert.ToBase64String(hashedBytes);
        }

        public static bool VerifyPassword(string password, string hash)
        {
            return HashPassword(password) == hash;
        }
    }
}
