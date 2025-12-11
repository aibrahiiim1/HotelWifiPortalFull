using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services.Radius;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Admin
{
    [Route("Admin/[controller]/[action]")]
    [Authorize(Roles = "Admin,SuperAdmin")]
    public class UsersController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly FreeRadiusService _freeRadiusService;
        private readonly ILogger<UsersController> _logger;

        public UsersController(
            ApplicationDbContext dbContext,
            FreeRadiusService freeRadiusService,
            ILogger<UsersController> logger)
        {
            _dbContext = dbContext;
            _freeRadiusService = freeRadiusService;
            _logger = logger;
        }

        // Admin Users
        public async Task<IActionResult> Index()
        {
            var users = await _dbContext.AdminUsers
                .OrderBy(u => u.Username)
                .ToListAsync();

            return View(users);
        }

        public IActionResult Create()
        {
            return View(new AdminUserEditViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(AdminUserEditViewModel model)
        {
            if (string.IsNullOrEmpty(model.Password))
            {
                ModelState.AddModelError("Password", "Password is required for new users.");
                return View(model);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (await _dbContext.AdminUsers.AnyAsync(u => u.Username == model.Username))
            {
                ModelState.AddModelError("Username", "Username already exists.");
                return View(model);
            }

            var user = new AdminUser
            {
                Username = model.Username,
                PasswordHash = BCryptHelper.HashPassword(model.Password),
                Email = model.Email,
                FullName = model.FullName,
                Role = model.Role,
                IsActive = model.IsActive,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.AdminUsers.Add(user);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Admin user created: {Username}", model.Username);
            TempData["Success"] = "User created successfully.";

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(int id)
        {
            var user = await _dbContext.AdminUsers.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var model = new AdminUserEditViewModel
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                FullName = user.FullName,
                Role = user.Role,
                IsActive = user.IsActive
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, AdminUserEditViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            // Remove password validation for edit if not changing
            if (string.IsNullOrEmpty(model.Password))
            {
                ModelState.Remove("Password");
                ModelState.Remove("ConfirmPassword");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _dbContext.AdminUsers.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            // Check for duplicate username
            if (await _dbContext.AdminUsers.AnyAsync(u => u.Username == model.Username && u.Id != id))
            {
                ModelState.AddModelError("Username", "Username already exists.");
                return View(model);
            }

            user.Username = model.Username;
            user.Email = model.Email;
            user.FullName = model.FullName;
            user.Role = model.Role;
            user.IsActive = model.IsActive;
            user.UpdatedAt = DateTime.UtcNow;

            if (!string.IsNullOrEmpty(model.Password))
            {
                user.PasswordHash = BCryptHelper.HashPassword(model.Password);
            }

            await _dbContext.SaveChangesAsync();

            TempData["Success"] = "User updated successfully.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> Delete(int id)
        {
            var user = await _dbContext.AdminUsers.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            // Don't allow deleting the last super admin
            if (user.Role == "SuperAdmin")
            {
                var superAdminCount = await _dbContext.AdminUsers.CountAsync(u => u.Role == "SuperAdmin");
                if (superAdminCount <= 1)
                {
                    TempData["Error"] = "Cannot delete the last Super Admin.";
                    return RedirectToAction(nameof(Index));
                }
            }

            _dbContext.AdminUsers.Remove(user);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Admin user deleted: {Username}", user.Username);
            TempData["Success"] = "User deleted successfully.";

            return RedirectToAction(nameof(Index));
        }

        // Local Users (for standalone mode)
        public async Task<IActionResult> Local()
        {
            var users = await _dbContext.LocalUsers
                .OrderBy(u => u.UserType)
                .ThenBy(u => u.Username)
                .ToListAsync();

            return View(users);
        }

        public IActionResult CreateLocal()
        {
            return View(new LocalUserEditViewModel
            {
                ValidFrom = DateTime.Today,
                ValidUntil = DateTime.Today.AddMonths(1),
                QuotaGB = 5,
                DownloadSpeedKbps = 10240,
                UploadSpeedKbps = 5120,
                MaxDevices = 3
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateLocal(LocalUserEditViewModel model)
        {
            if (string.IsNullOrEmpty(model.Password))
            {
                ModelState.AddModelError("Password", "Password is required.");
                return View(model);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (await _dbContext.LocalUsers.AnyAsync(u => u.Username == model.Username))
            {
                ModelState.AddModelError("Username", "Username already exists.");
                return View(model);
            }

            var user = new LocalUser
            {
                Username = model.Username,
                PasswordHash = model.Password, // Store cleartext for FreeRADIUS (legacy systems need this)
                FullName = model.FullName,
                Email = model.Email,
                Phone = model.Phone,
                UserType = model.UserType,
                RoomNumber = model.RoomNumber,
                QuotaBytes = (long)(model.QuotaGB * 1024 * 1024 * 1024),
                DownloadSpeedKbps = model.DownloadSpeedKbps,
                UploadSpeedKbps = model.UploadSpeedKbps,
                MaxDevices = model.MaxDevices,
                ValidFrom = model.ValidFrom,
                ValidUntil = model.ValidUntil,
                IsActive = model.IsActive,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.LocalUsers.Add(user);
            await _dbContext.SaveChangesAsync();

            // Sync to FreeRADIUS
            try
            {
                await _freeRadiusService.CreateOrUpdateLocalUserAsync(user);
                _logger.LogInformation("Local user synced to FreeRADIUS: {Username}", model.Username);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sync local user to FreeRADIUS: {Username}", model.Username);
                TempData["Warning"] = "User created but failed to sync to FreeRADIUS.";
            }

            _logger.LogInformation("Local user created: {Username} ({Type}), Speed: {Down}k/{Up}k",
                model.Username, model.UserType, model.DownloadSpeedKbps, model.UploadSpeedKbps);
            TempData["Success"] = "Local user created successfully.";

            return RedirectToAction(nameof(Local));
        }

        public async Task<IActionResult> EditLocal(int id)
        {
            var user = await _dbContext.LocalUsers.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var model = new LocalUserEditViewModel
            {
                Id = user.Id,
                Username = user.Username,
                FullName = user.FullName,
                Email = user.Email,
                Phone = user.Phone,
                UserType = user.UserType,
                RoomNumber = user.RoomNumber,
                QuotaGB = user.QuotaBytes / (1024.0 * 1024.0 * 1024.0),
                DownloadSpeedKbps = user.DownloadSpeedKbps,
                UploadSpeedKbps = user.UploadSpeedKbps,
                MaxDevices = user.MaxDevices,
                ValidFrom = user.ValidFrom,
                ValidUntil = user.ValidUntil,
                IsActive = user.IsActive
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditLocal(int id, LocalUserEditViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (string.IsNullOrEmpty(model.Password))
            {
                ModelState.Remove("Password");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _dbContext.LocalUsers.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            user.Username = model.Username;
            user.FullName = model.FullName;
            user.Email = model.Email;
            user.Phone = model.Phone;
            user.UserType = model.UserType;
            user.RoomNumber = model.RoomNumber;
            user.QuotaBytes = (long)(model.QuotaGB * 1024 * 1024 * 1024);
            user.DownloadSpeedKbps = model.DownloadSpeedKbps;
            user.UploadSpeedKbps = model.UploadSpeedKbps;
            user.MaxDevices = model.MaxDevices;
            user.ValidFrom = model.ValidFrom;
            user.ValidUntil = model.ValidUntil;
            user.IsActive = model.IsActive;
            user.UpdatedAt = DateTime.UtcNow;

            if (!string.IsNullOrEmpty(model.Password))
            {
                user.PasswordHash = model.Password; // Store cleartext for FreeRADIUS
            }

            await _dbContext.SaveChangesAsync();

            // Sync to FreeRADIUS
            try
            {
                await _freeRadiusService.CreateOrUpdateLocalUserAsync(user);
                _logger.LogInformation("Local user synced to FreeRADIUS: {Username}", model.Username);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sync local user to FreeRADIUS: {Username}", model.Username);
                TempData["Warning"] = "User updated but failed to sync to FreeRADIUS.";
            }

            TempData["Success"] = "Local user updated successfully.";
            return RedirectToAction(nameof(Local));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteLocal(int id)
        {
            var user = await _dbContext.LocalUsers.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var username = user.Username;

            _dbContext.LocalUsers.Remove(user);
            await _dbContext.SaveChangesAsync();

            // Delete from FreeRADIUS
            try
            {
                await _freeRadiusService.DeleteLocalUserAsync(username);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to delete local user from FreeRADIUS: {Username}", username);
            }

            _logger.LogInformation("Local user deleted: {Username}", username);
            TempData["Success"] = "Local user deleted successfully.";

            return RedirectToAction(nameof(Local));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SyncAllLocalUsers()
        {
            try
            {
                await _freeRadiusService.SyncAllLocalUsersAsync();
                TempData["Success"] = "All local users synced to FreeRADIUS successfully.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to sync local users to FreeRADIUS");
                TempData["Error"] = $"Failed to sync local users: {ex.Message}";
            }

            return RedirectToAction(nameof(Local));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetLocalUsage(int id)
        {
            var user = await _dbContext.LocalUsers.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            user.UsedQuotaBytes = 0;
            user.CurrentDevices = 0;
            user.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            TempData["Success"] = "Usage reset successfully.";
            return RedirectToAction(nameof(Local));
        }

        // Batch user creation
        public IActionResult BatchCreate()
        {
            return View(new BatchLocalUserViewModel
            {
                UsernamePrefix = "guest",
                Count = 10,
                PasswordLength = 8,
                UserType = "Guest",
                QuotaGB = 5,
                DownloadSpeedKbps = 10240,
                UploadSpeedKbps = 5120,
                MaxDevices = 3,
                ValidFrom = DateTime.Today,
                ValidUntil = DateTime.Today.AddMonths(1)
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> BatchCreate(BatchLocalUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (model.Count > 100)
            {
                ModelState.AddModelError("Count", "Maximum 100 users per batch.");
                return View(model);
            }

            var createdUsers = new List<(string Username, string Password)>();
            var random = new Random();
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";

            // Find starting number
            var existingUsers = await _dbContext.LocalUsers
                .Where(u => u.Username.StartsWith(model.UsernamePrefix))
                .Select(u => u.Username)
                .ToListAsync();

            int startNumber = 1;
            foreach (var existingUsername in existingUsers)
            {
                var numPart = existingUsername.Replace(model.UsernamePrefix, "");
                if (int.TryParse(numPart, out int num) && num >= startNumber)
                {
                    startNumber = num + 1;
                }
            }

            for (int i = 0; i < model.Count; i++)
            {
                var username = $"{model.UsernamePrefix}{startNumber + i}";

                // Check if username already exists
                if (await _dbContext.LocalUsers.AnyAsync(u => u.Username == username))
                {
                    startNumber++;
                    i--;
                    continue;
                }

                // Generate random password
                var password = new string(Enumerable.Repeat(chars, model.PasswordLength)
                    .Select(s => s[random.Next(s.Length)]).ToArray());

                var user = new LocalUser
                {
                    Username = username,
                    PasswordHash = BCryptHelper.HashPassword(password),
                    UserType = model.UserType,
                    QuotaBytes = (long)(model.QuotaGB * 1024 * 1024 * 1024),
                    DownloadSpeedKbps = model.DownloadSpeedKbps,
                    UploadSpeedKbps = model.UploadSpeedKbps,
                    MaxDevices = model.MaxDevices,
                    ValidFrom = model.ValidFrom,
                    ValidUntil = model.ValidUntil,
                    IsActive = model.IsActive,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                _dbContext.LocalUsers.Add(user);
                createdUsers.Add((username, password));
            }

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Batch created {Count} local users with prefix {Prefix}",
                createdUsers.Count, model.UsernamePrefix);

            // Store created users for display
            TempData["BatchCreatedUsers"] = System.Text.Json.JsonSerializer.Serialize(createdUsers);
            TempData["Success"] = $"Successfully created {createdUsers.Count} users.";

            return RedirectToAction(nameof(BatchResult));
        }

        public IActionResult BatchResult()
        {
            var usersJson = TempData["BatchCreatedUsers"] as string;
            if (string.IsNullOrEmpty(usersJson))
            {
                return RedirectToAction(nameof(Local));
            }

            var users = System.Text.Json.JsonSerializer.Deserialize<List<(string, string)>>(usersJson);
            return View(users);
        }
    }
}