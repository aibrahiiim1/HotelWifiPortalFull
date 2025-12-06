using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace HotelWifiPortal.Services
{
    public class AuthService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly QuotaService _quotaService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(ApplicationDbContext dbContext, QuotaService quotaService, ILogger<AuthService> logger)
        {
            _dbContext = dbContext;
            _quotaService = quotaService;
            _logger = logger;
        }

        // Guest authentication (PMS mode)
        public async Task<(bool Success, Guest? Guest, string? Error)> AuthenticateGuestAsync(string roomNumber, string password)
        {
            _logger.LogInformation("=== Guest Authentication Attempt ===");
            _logger.LogInformation("Room: {Room}, Password: {Pass}", roomNumber, password);

            // First, find guest by room number only to see if they exist
            var allGuestsInRoom = await _dbContext.Guests
                .Where(g => g.RoomNumber == roomNumber)
                .ToListAsync();

            _logger.LogInformation("Found {Count} guest(s) in room {Room}", allGuestsInRoom.Count, roomNumber);

            foreach (var g in allGuestsInRoom)
            {
                _logger.LogInformation("  - Guest: {Name}, Status: {Status}, ResNum: {Res}, LocalPwd: {Pwd}, Arrival: {Arr}, Departure: {Dep}",
                    g.GuestName, g.Status, g.ReservationNumber,
                    string.IsNullOrEmpty(g.LocalPassword) ? "(none)" : "(set)",
                    g.ArrivalDate.ToString("yyyy-MM-dd"), g.DepartureDate.ToString("yyyy-MM-dd"));
            }

            // In PMS mode, password is the reservation number or local password
            var guest = await _dbContext.Guests
                .FirstOrDefaultAsync(g =>
                    g.RoomNumber == roomNumber &&
                    (g.Status == "checked-in" || g.Status == "Checked-In" || g.Status == "CheckedIn" || g.Status == "active") &&
                    (g.ReservationNumber == password ||
                     g.ReservationNumber.ToLower() == password.ToLower() ||
                     g.ReservationNumber.EndsWith(password) || // Last N digits
                     g.LocalPassword == password ||
                     (!string.IsNullOrEmpty(g.LocalPassword) && g.LocalPassword.ToLower() == password.ToLower())));

            if (guest == null)
            {
                _logger.LogWarning("Guest authentication failed for room {Room} - no matching guest found", roomNumber);
                _logger.LogWarning("Check: 1) Status must be 'checked-in', 2) Password must match ReservationNumber or LocalPassword");
                return (false, null, "Invalid room number or password. Please check your details and try again.");
            }

            // Check if guest is still within stay dates
            var now = DateTime.Today;
            _logger.LogInformation("Date check - Today: {Today}, Arrival: {Arr}, Departure: {Dep}",
                now.ToString("yyyy-MM-dd"), guest.ArrivalDate.ToString("yyyy-MM-dd"), guest.DepartureDate.ToString("yyyy-MM-dd"));

            if (now < guest.ArrivalDate.Date || now > guest.DepartureDate.Date)
            {
                _logger.LogWarning("Guest {Name} in room {Room} - date check failed", guest.GuestName, roomNumber);
                return (false, null, "Your stay dates do not allow WiFi access at this time.");
            }

            // Ensure quota is assigned
            if (guest.FreeQuotaBytes == 0)
            {
                await _quotaService.AssignFreeQuotaToGuestAsync(guest);
            }

            _logger.LogInformation("Guest authenticated successfully: Room {Room}, Guest {Name}", roomNumber, guest.GuestName);
            return (true, guest, null);
        }

        // Local user authentication (Standalone mode)
        public async Task<(bool Success, LocalUser? User, string? Error)> AuthenticateLocalUserAsync(string username, string password)
        {
            var user = await _dbContext.LocalUsers
                .FirstOrDefaultAsync(u => u.Username == username && u.IsActive);

            if (user == null)
            {
                return (false, null, "Invalid username or password.");
            }

            if (!BCryptHelper.VerifyPassword(password, user.PasswordHash))
            {
                return (false, null, "Invalid username or password.");
            }

            // Check validity period
            var now = DateTime.UtcNow;
            if (user.ValidFrom.HasValue && now < user.ValidFrom.Value)
            {
                return (false, null, "Your account is not yet active.");
            }
            if (user.ValidUntil.HasValue && now > user.ValidUntil.Value)
            {
                return (false, null, "Your account has expired.");
            }

            user.LastLogin = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            return (true, user, null);
        }

        // Admin authentication
        public async Task<(bool Success, AdminUser? User, string? Error)> AuthenticateAdminAsync(string username, string password)
        {
            var user = await _dbContext.AdminUsers
                .FirstOrDefaultAsync(u => u.Username == username && u.IsActive);

            if (user == null)
            {
                _logger.LogWarning("Admin login failed - user not found: {Username}", username);
                return (false, null, "Invalid username or password.");
            }

            if (!BCryptHelper.VerifyPassword(password, user.PasswordHash))
            {
                _logger.LogWarning("Admin login failed - wrong password for {Username}", username);
                return (false, null, "Invalid username or password.");
            }

            user.LastLogin = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Admin login successful: {Username}", username);
            return (true, user, null);
        }

        public ClaimsPrincipal CreateGuestPrincipal(Guest guest)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, guest.Id.ToString()),
                new Claim(ClaimTypes.Name, guest.GuestName),
                new Claim("RoomNumber", guest.RoomNumber),
                new Claim("ReservationNumber", guest.ReservationNumber),
                new Claim(ClaimTypes.Role, "Guest")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            return new ClaimsPrincipal(identity);
        }

        public ClaimsPrincipal CreateAdminPrincipal(AdminUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email ?? ""),
                new Claim("FullName", user.FullName ?? user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            return new ClaimsPrincipal(identity);
        }

        public ClaimsPrincipal CreateLocalUserPrincipal(LocalUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("FullName", user.FullName ?? user.Username),
                new Claim("UserType", user.UserType),
                new Claim(ClaimTypes.Role, "LocalUser")
            };

            if (!string.IsNullOrEmpty(user.RoomNumber))
                claims.Add(new Claim("RoomNumber", user.RoomNumber));

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            return new ClaimsPrincipal(identity);
        }

        // Check operation mode
        public async Task<bool> IsPmsModeEnabledAsync()
        {
            var settings = await _dbContext.PmsSettings.FirstOrDefaultAsync();
            return settings?.IsPmsModeEnabled ?? true;
        }

        public async Task<bool> IsStandaloneModeEnabledAsync()
        {
            var setting = await _dbContext.SystemSettings
                .FirstOrDefaultAsync(s => s.Key == "EnableStandaloneMode");

            return setting?.Value?.ToLower() == "true";
        }
    }
}