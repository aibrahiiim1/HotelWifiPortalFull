using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Admin
{
    [Route("Admin/[controller]/[action]")]
    [Authorize(Roles = "Admin,SuperAdmin,Manager")]
    public class PackagesController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<PackagesController> _logger;

        public PackagesController(ApplicationDbContext dbContext, ILogger<PackagesController> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        // Free Bandwidth Packages
        public async Task<IActionResult> Index()
        {
            var packages = await _dbContext.BandwidthPackages
                .OrderBy(p => p.SortOrder)
                .ToListAsync();

            return View(packages);
        }

        public IActionResult Create()
        {
            return View(new PackageEditViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(PackageEditViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var package = new BandwidthPackage
            {
                Name = model.Name,
                Description = model.Description,
                MinStayDays = model.MinStayDays,
                MaxStayDays = model.MaxStayDays,
                QuotaGB = model.QuotaGB,
                SpeedLimitKbps = model.SpeedLimitKbps,
                BadgeColor = model.BadgeColor,
                SortOrder = model.SortOrder,
                IsActive = model.IsActive,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.BandwidthPackages.Add(package);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Bandwidth package created: {Name}", package.Name);
            TempData["Success"] = "Package created successfully.";

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(int id)
        {
            var package = await _dbContext.BandwidthPackages.FindAsync(id);
            if (package == null)
            {
                return NotFound();
            }

            var model = new PackageEditViewModel
            {
                Id = package.Id,
                Name = package.Name,
                Description = package.Description,
                MinStayDays = package.MinStayDays,
                MaxStayDays = package.MaxStayDays,
                QuotaGB = package.QuotaGB,
                SpeedLimitKbps = package.SpeedLimitKbps,
                BadgeColor = package.BadgeColor,
                SortOrder = package.SortOrder,
                IsActive = package.IsActive
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, PackageEditViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var package = await _dbContext.BandwidthPackages.FindAsync(id);
            if (package == null)
            {
                return NotFound();
            }

            package.Name = model.Name;
            package.Description = model.Description;
            package.MinStayDays = model.MinStayDays;
            package.MaxStayDays = model.MaxStayDays;
            package.QuotaGB = model.QuotaGB;
            package.SpeedLimitKbps = model.SpeedLimitKbps;
            package.BadgeColor = model.BadgeColor;
            package.SortOrder = model.SortOrder;
            package.IsActive = model.IsActive;
            package.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            TempData["Success"] = "Package updated successfully.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> Delete(int id)
        {
            var package = await _dbContext.BandwidthPackages.FindAsync(id);
            if (package == null)
            {
                return NotFound();
            }

            _dbContext.BandwidthPackages.Remove(package);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Bandwidth package deleted: {Name}", package.Name);
            TempData["Success"] = "Package deleted successfully.";

            return RedirectToAction(nameof(Index));
        }

        // Paid Packages
        public async Task<IActionResult> Paid()
        {
            var packages = await _dbContext.PaidPackages
                .OrderBy(p => p.SortOrder)
                .ToListAsync();

            return View(packages);
        }

        public IActionResult CreatePaid()
        {
            return View(new PaidPackageEditViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreatePaid(PaidPackageEditViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var package = new PaidPackage
            {
                Name = model.Name,
                Description = model.Description,
                PackageType = model.PackageType,
                Price = model.Price,
                Currency = model.Currency,
                DurationHours = model.DurationHours,
                DurationDays = model.DurationDays,
                QuotaGB = model.QuotaGB,
                SpeedLimitKbps = model.SpeedLimitKbps,
                BadgeColor = model.BadgeColor,
                SortOrder = model.SortOrder,
                IsActive = model.IsActive,
                IsFeatured = model.IsFeatured,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.PaidPackages.Add(package);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Paid package created: {Name}", package.Name);
            TempData["Success"] = "Package created successfully.";

            return RedirectToAction(nameof(Paid));
        }

        public async Task<IActionResult> EditPaid(int id)
        {
            var package = await _dbContext.PaidPackages.FindAsync(id);
            if (package == null)
            {
                return NotFound();
            }

            var model = new PaidPackageEditViewModel
            {
                Id = package.Id,
                Name = package.Name,
                Description = package.Description,
                PackageType = package.PackageType,
                Price = package.Price,
                Currency = package.Currency,
                DurationHours = package.DurationHours,
                DurationDays = package.DurationDays,
                QuotaGB = package.QuotaGB,
                SpeedLimitKbps = package.SpeedLimitKbps,
                BadgeColor = package.BadgeColor,
                SortOrder = package.SortOrder,
                IsActive = package.IsActive,
                IsFeatured = package.IsFeatured
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditPaid(int id, PaidPackageEditViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var package = await _dbContext.PaidPackages.FindAsync(id);
            if (package == null)
            {
                return NotFound();
            }

            package.Name = model.Name;
            package.Description = model.Description;
            package.PackageType = model.PackageType;
            package.Price = model.Price;
            package.Currency = model.Currency;
            package.DurationHours = model.DurationHours;
            package.DurationDays = model.DurationDays;
            package.QuotaGB = model.QuotaGB;
            package.SpeedLimitKbps = model.SpeedLimitKbps;
            package.BadgeColor = model.BadgeColor;
            package.SortOrder = model.SortOrder;
            package.IsActive = model.IsActive;
            package.IsFeatured = model.IsFeatured;
            package.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            TempData["Success"] = "Package updated successfully.";
            return RedirectToAction(nameof(Paid));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> DeletePaid(int id)
        {
            var package = await _dbContext.PaidPackages.FindAsync(id);
            if (package == null)
            {
                return NotFound();
            }

            _dbContext.PaidPackages.Remove(package);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Paid package deleted: {Name}", package.Name);
            TempData["Success"] = "Package deleted successfully.";

            return RedirectToAction(nameof(Paid));
        }

        // Bandwidth Profiles
        public async Task<IActionResult> Profiles()
        {
            var profiles = await _dbContext.BandwidthProfiles
                .OrderByDescending(p => p.IsDefault)
                .ThenBy(p => p.Name)
                .ToListAsync();

            return View(profiles);
        }

        public IActionResult CreateProfile()
        {
            return View(new BandwidthProfileEditViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateProfile(BandwidthProfileEditViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // If setting as default, unset other defaults
            if (model.IsDefault)
            {
                var existingDefault = await _dbContext.BandwidthProfiles
                    .Where(p => p.IsDefault)
                    .ToListAsync();
                
                foreach (var p in existingDefault)
                {
                    p.IsDefault = false;
                }
            }

            var profile = new BandwidthProfile
            {
                Name = model.Name,
                Description = model.Description,
                DownloadSpeedKbps = model.DownloadSpeedKbps,
                UploadSpeedKbps = model.UploadSpeedKbps,
                ApplyToRooms = model.ApplyToRooms,
                MaxDevicesPerRoom = model.MaxDevicesPerRoom,
                Priority = model.Priority,
                IsDefault = model.IsDefault,
                IsActive = model.IsActive,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.BandwidthProfiles.Add(profile);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Bandwidth profile created: {Name}", profile.Name);
            TempData["Success"] = "Profile created successfully.";

            return RedirectToAction(nameof(Profiles));
        }

        public async Task<IActionResult> EditProfile(int id)
        {
            var profile = await _dbContext.BandwidthProfiles.FindAsync(id);
            if (profile == null)
            {
                return NotFound();
            }

            var model = new BandwidthProfileEditViewModel
            {
                Id = profile.Id,
                Name = profile.Name,
                Description = profile.Description,
                DownloadSpeedKbps = profile.DownloadSpeedKbps,
                UploadSpeedKbps = profile.UploadSpeedKbps,
                ApplyToRooms = profile.ApplyToRooms,
                MaxDevicesPerRoom = profile.MaxDevicesPerRoom,
                Priority = profile.Priority,
                IsDefault = profile.IsDefault,
                IsActive = profile.IsActive
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfile(int id, BandwidthProfileEditViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var profile = await _dbContext.BandwidthProfiles.FindAsync(id);
            if (profile == null)
            {
                return NotFound();
            }

            // If setting as default, unset other defaults
            if (model.IsDefault && !profile.IsDefault)
            {
                var existingDefault = await _dbContext.BandwidthProfiles
                    .Where(p => p.IsDefault && p.Id != id)
                    .ToListAsync();
                
                foreach (var p in existingDefault)
                {
                    p.IsDefault = false;
                }
            }

            profile.Name = model.Name;
            profile.Description = model.Description;
            profile.DownloadSpeedKbps = model.DownloadSpeedKbps;
            profile.UploadSpeedKbps = model.UploadSpeedKbps;
            profile.ApplyToRooms = model.ApplyToRooms;
            profile.MaxDevicesPerRoom = model.MaxDevicesPerRoom;
            profile.Priority = model.Priority;
            profile.IsDefault = model.IsDefault;
            profile.IsActive = model.IsActive;
            profile.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            TempData["Success"] = "Profile updated successfully.";
            return RedirectToAction(nameof(Profiles));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> DeleteProfile(int id)
        {
            var profile = await _dbContext.BandwidthProfiles.FindAsync(id);
            if (profile == null)
            {
                return NotFound();
            }

            if (profile.IsDefault)
            {
                TempData["Error"] = "Cannot delete the default profile.";
                return RedirectToAction(nameof(Profiles));
            }

            _dbContext.BandwidthProfiles.Remove(profile);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Bandwidth profile deleted: {Name}", profile.Name);
            TempData["Success"] = "Profile deleted successfully.";

            return RedirectToAction(nameof(Profiles));
        }

        // Transactions
        public async Task<IActionResult> Transactions(string? room, string? status, DateTime? fromDate, DateTime? toDate)
        {
            var query = _dbContext.PaymentTransactions.AsQueryable();

            if (!string.IsNullOrEmpty(room))
            {
                query = query.Where(t => t.RoomNumber.Contains(room));
            }

            if (!string.IsNullOrEmpty(status))
            {
                query = query.Where(t => t.Status == status);
            }

            if (fromDate.HasValue)
            {
                query = query.Where(t => t.CreatedAt >= fromDate.Value);
            }

            if (toDate.HasValue)
            {
                query = query.Where(t => t.CreatedAt <= toDate.Value.AddDays(1));
            }

            var transactions = await query
                .OrderByDescending(t => t.CreatedAt)
                .Take(500)
                .ToListAsync();

            ViewBag.Room = room;
            ViewBag.Status = status;
            ViewBag.FromDate = fromDate?.ToString("yyyy-MM-dd");
            ViewBag.ToDate = toDate?.ToString("yyyy-MM-dd");

            // Stats
            ViewBag.TotalRevenue = transactions.Where(t => t.Status == "Completed").Sum(t => t.Amount);
            ViewBag.TotalTransactions = transactions.Count;
            ViewBag.PostedToPMS = transactions.Count(t => t.PostedToPMS);
            ViewBag.PendingPMS = transactions.Count(t => t.Status == "Completed" && !t.PostedToPMS);

            return View(transactions);
        }
    }
}
