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
    [Authorize(Roles = "Admin,SuperAdmin,Manager")]
    public class PackagesController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<PackagesController> _logger;
        private readonly FreeRadiusService _freeRadiusService;

        public PackagesController(
            ApplicationDbContext dbContext, 
            ILogger<PackagesController> logger,
            FreeRadiusService freeRadiusService)
        {
            _dbContext = dbContext;
            _logger = logger;
            _freeRadiusService = freeRadiusService;
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
                DownloadSpeedKbps = model.DownloadSpeedKbps,
                UploadSpeedKbps = model.UploadSpeedKbps,
                MaxDevices = model.MaxDevices > 0 ? model.MaxDevices : 3,
                SharedUsage = model.SharedUsage,
                SharedBandwidth = model.SharedBandwidth,
                BadgeColor = model.BadgeColor ?? "primary",
                SortOrder = model.SortOrder,
                IsActive = model.IsActive,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.BandwidthPackages.Add(package);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Bandwidth package created: {Name}, DL={DL}kbps, UL={UL}kbps", 
                package.Name, package.DownloadSpeedKbps, package.UploadSpeedKbps);
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
                DownloadSpeedKbps = package.DownloadSpeedKbps,
                UploadSpeedKbps = package.UploadSpeedKbps,
                MaxDevices = package.MaxDevices,
                SharedUsage = package.SharedUsage,
                SharedBandwidth = package.SharedBandwidth,
                BadgeColor = package.BadgeColor,
                SortOrder = package.SortOrder,
                IsActive = package.IsActive
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, PackageEditViewModel model, bool applyImmediately = false)
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

            // Check if bandwidth changed
            bool bandwidthChanged = package.DownloadSpeedKbps != model.DownloadSpeedKbps ||
                                    package.UploadSpeedKbps != model.UploadSpeedKbps ||
                                    package.SpeedLimitKbps != model.SpeedLimitKbps;

            package.Name = model.Name;
            package.Description = model.Description;
            package.MinStayDays = model.MinStayDays;
            package.MaxStayDays = model.MaxStayDays;
            package.QuotaGB = model.QuotaGB;
            package.SpeedLimitKbps = model.SpeedLimitKbps;
            package.DownloadSpeedKbps = model.DownloadSpeedKbps;
            package.UploadSpeedKbps = model.UploadSpeedKbps;
            package.MaxDevices = model.MaxDevices;
            package.SharedUsage = model.SharedUsage;
            package.SharedBandwidth = model.SharedBandwidth;
            package.BadgeColor = model.BadgeColor;
            package.SortOrder = model.SortOrder;
            package.IsActive = model.IsActive;
            package.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            // If bandwidth changed, update all affected guests
            if (bandwidthChanged)
            {
                _logger.LogInformation("Bandwidth changed for package {Name}, syncing affected guests...", package.Name);
                
                // Get new bandwidth values
                int newDownloadKbps = model.DownloadSpeedKbps ?? model.SpeedLimitKbps ?? 10240;
                int newUploadKbps = model.UploadSpeedKbps ?? model.SpeedLimitKbps ?? 5120;
                
                // Find all checked-in guests that match this package's stay length criteria
                var affectedGuests = await _dbContext.Guests
                    .Where(g => (g.Status == "checked-in" || g.Status == "Checked-In" || g.Status == "CheckedIn"))
                    .ToListAsync();

                int updatedCount = 0;
                int coaSuccessCount = 0;
                
                foreach (var guest in affectedGuests)
                {
                    var stayLength = Math.Max(1, (guest.DepartureDate - guest.ArrivalDate).Days);
                    
                    // Check if this guest matches this package
                    if (stayLength >= package.MinStayDays && 
                        (package.MaxStayDays == null || stayLength <= package.MaxStayDays))
                    {
                        // Update FreeRADIUS entry for this guest
                        var success = await _freeRadiusService.CreateOrUpdateUserAsync(guest);
                        if (success)
                        {
                            updatedCount++;
                            _logger.LogInformation("Updated FreeRADIUS for guest Room {Room}", guest.RoomNumber);
                            
                            // If applyImmediately is true, send CoA to update bandwidth in real-time
                            if (applyImmediately)
                            {
                                var coaSuccess = await _freeRadiusService.UpdateBandwidthViaCoAAsync(
                                    guest.RoomNumber, 
                                    newDownloadKbps, 
                                    newUploadKbps);
                                    
                                if (coaSuccess)
                                {
                                    coaSuccessCount++;
                                    _logger.LogInformation("CoA bandwidth update sent for Room {Room}", guest.RoomNumber);
                                }
                            }
                        }
                    }
                }

                if (updatedCount > 0)
                {
                    if (applyImmediately)
                    {
                        TempData["Success"] = $"Package updated. {updatedCount} guest(s) updated in FreeRADIUS. {coaSuccessCount} guest(s) bandwidth updated immediately via CoA.";
                    }
                    else
                    {
                        TempData["Success"] = $"Package updated. {updatedCount} guest(s) updated in FreeRADIUS. Guests will get new speed on next reconnect.";
                    }
                }
                else
                {
                    TempData["Success"] = "Package updated successfully. No active guests matched this package.";
                }
            }
            else
            {
                TempData["Success"] = "Package updated successfully.";
            }

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
                DownloadSpeedKbps = model.DownloadSpeedKbps,
                UploadSpeedKbps = model.UploadSpeedKbps,
                BadgeColor = model.BadgeColor,
                SortOrder = model.SortOrder,
                IsActive = model.IsActive,
                IsFeatured = model.IsFeatured,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.PaidPackages.Add(package);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Paid package created: {Name}, Speed: {Down}k/{Up}k, Quota: {Quota}GB", 
                package.Name, package.DownloadSpeedKbps, package.UploadSpeedKbps, package.QuotaGB);
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
                DownloadSpeedKbps = package.DownloadSpeedKbps,
                UploadSpeedKbps = package.UploadSpeedKbps,
                MaxDevices = package.MaxDevices,
                SharedUsage = package.SharedUsage,
                SharedBandwidth = package.SharedBandwidth,
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
            package.DownloadSpeedKbps = model.DownloadSpeedKbps;
            package.UploadSpeedKbps = model.UploadSpeedKbps;
            package.MaxDevices = model.MaxDevices;
            package.SharedUsage = model.SharedUsage;
            package.SharedBandwidth = model.SharedBandwidth;
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
            ViewBag.TotalRevenue = transactions.Where(t => t.Status == "Completed" || t.Status == "PostedToPMS").Sum(t => t.Amount);
            ViewBag.TotalTransactions = transactions.Count;
            ViewBag.PostedToPMS = transactions.Count(t => t.PostedToPMS);
            ViewBag.PendingPMS = transactions.Count(t => (t.Status == "Completed" || t.Status == "PostedToPMS") && !t.PostedToPMS);

            return View(transactions);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RetryPmsPost(int id)
        {
            var transaction = await _dbContext.PaymentTransactions
                .Include(t => t.Guest)
                .FirstOrDefaultAsync(t => t.Id == id);

            if (transaction == null)
            {
                TempData["Error"] = "Transaction not found.";
                return RedirectToAction(nameof(Transactions));
            }

            if (transaction.PostedToPMS)
            {
                TempData["Warning"] = "Transaction already posted to PMS.";
                return RedirectToAction(nameof(Transactions));
            }

            try
            {
                // Get PMS settings
                var pmsSettings = await _dbContext.PmsSettings.FirstOrDefaultAsync();
                if (pmsSettings?.IsEnabled != true)
                {
                    TempData["Error"] = "PMS integration is not enabled.";
                    return RedirectToAction(nameof(Transactions));
                }

                // Get FIAS server service
                var fiasServer = HttpContext.RequestServices.GetRequiredService<HotelWifiPortal.Services.PMS.FiasSocketServer>();
                
                if (!fiasServer.IsConnected)
                {
                    TempData["Error"] = "Not connected to PMS. Please check FIAS connection.";
                    return RedirectToAction(nameof(Transactions));
                }

                // Post to PMS
                var description = $"WiFi: {transaction.PackageName}";
                await fiasServer.PostChargeAsync(
                    transaction.RoomNumber,
                    transaction.ReservationNumber,
                    transaction.Amount,
                    description,
                    pmsSettings.PostByReservationNumber);

                // Update transaction
                transaction.PostedToPMS = true;
                transaction.PostedToPMSAt = DateTime.UtcNow;
                transaction.Status = "PostedToPMS";
                transaction.PMSPostingId = Guid.NewGuid().ToString("N")[..16];
                transaction.PMSResponse = pmsSettings.PostByReservationNumber 
                    ? $"Success (by Reservation# {transaction.ReservationNumber})" 
                    : $"Success (by Room {transaction.RoomNumber})";
                await _dbContext.SaveChangesAsync();

                var identifier = pmsSettings.PostByReservationNumber 
                    ? $"Reservation# {transaction.ReservationNumber}" 
                    : $"Room {transaction.RoomNumber}";
                    
                _logger.LogInformation("Manually posted transaction {Id} to PMS: {Identifier}, Amount {Amount}",
                    transaction.Id, identifier, transaction.Amount);

                TempData["Success"] = $"Successfully posted ${transaction.Amount:N2} to {identifier} PMS folio.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to post transaction {Id} to PMS", id);
                TempData["Error"] = $"Failed to post to PMS: {ex.Message}";
            }

            return RedirectToAction(nameof(Transactions));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> PostAllPendingToPms()
        {
            var pendingTransactions = await _dbContext.PaymentTransactions
                .Where(t => !t.PostedToPMS && (t.Status == "Completed" || t.Status == "PostedToPMS"))
                .ToListAsync();

            if (!pendingTransactions.Any())
            {
                TempData["Warning"] = "No pending transactions to post.";
                return RedirectToAction(nameof(Transactions));
            }

            var pmsSettings = await _dbContext.PmsSettings.FirstOrDefaultAsync();
            if (pmsSettings?.IsEnabled != true)
            {
                TempData["Error"] = "PMS integration is not enabled.";
                return RedirectToAction(nameof(Transactions));
            }

            var fiasServer = HttpContext.RequestServices.GetRequiredService<HotelWifiPortal.Services.PMS.FiasSocketServer>();
            if (!fiasServer.IsConnected)
            {
                TempData["Error"] = "Not connected to PMS.";
                return RedirectToAction(nameof(Transactions));
            }

            int posted = 0;
            int failed = 0;

            foreach (var transaction in pendingTransactions)
            {
                try
                {
                    await fiasServer.PostChargeAsync(
                        transaction.RoomNumber,
                        transaction.ReservationNumber,
                        transaction.Amount,
                        $"WiFi: {transaction.PackageName}",
                        pmsSettings.PostByReservationNumber);

                    transaction.PostedToPMS = true;
                    transaction.PostedToPMSAt = DateTime.UtcNow;
                    transaction.Status = "PostedToPMS";
                    transaction.PMSPostingId = Guid.NewGuid().ToString("N")[..16];
                    transaction.PMSResponse = pmsSettings.PostByReservationNumber 
                        ? $"Success (by Reservation# {transaction.ReservationNumber})" 
                        : $"Success (by Room {transaction.RoomNumber})";
                    posted++;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to post transaction {Id} to PMS", transaction.Id);
                    failed++;
                }
            }

            await _dbContext.SaveChangesAsync();

            if (failed > 0)
            {
                TempData["Warning"] = $"Posted {posted} transactions. {failed} failed.";
            }
            else
            {
                TempData["Success"] = $"Successfully posted {posted} transactions to PMS.";
            }

            return RedirectToAction(nameof(Transactions));
        }

        public async Task<IActionResult> ExportTransactions(string? room, string? status, DateTime? fromDate, DateTime? toDate)
        {
            var query = _dbContext.PaymentTransactions.AsQueryable();

            if (!string.IsNullOrEmpty(room))
                query = query.Where(t => t.RoomNumber.Contains(room));

            if (!string.IsNullOrEmpty(status))
                query = query.Where(t => t.Status == status);

            if (fromDate.HasValue)
                query = query.Where(t => t.CreatedAt >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(t => t.CreatedAt <= toDate.Value.AddDays(1));

            var transactions = await query.OrderByDescending(t => t.CreatedAt).ToListAsync();

            // Build CSV
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("TransactionID,Date,Time,Room,Guest,ReservationNo,Package,Amount,Currency,Status,PostedToPMS,PostedAt");

            foreach (var t in transactions)
            {
                csv.AppendLine($"\"{t.TransactionId}\",\"{t.CreatedAt:yyyy-MM-dd}\",\"{t.CreatedAt:HH:mm:ss}\",\"{t.RoomNumber}\",\"{t.GuestName}\",\"{t.ReservationNumber}\",\"{t.PackageName}\",{t.Amount},{t.Currency},{t.Status},{t.PostedToPMS},{t.PostedToPMSAt:yyyy-MM-dd HH:mm:ss}");
            }

            var bytes = System.Text.Encoding.UTF8.GetBytes(csv.ToString());
            var fileName = $"WiFiTransactions_{DateTime.Now:yyyyMMdd_HHmmss}.csv";

            return File(bytes, "text/csv", fileName);
        }

        // Payment Reports
        public async Task<IActionResult> Reports(DateTime? fromDate, DateTime? toDate)
        {
            fromDate ??= DateTime.Today.AddDays(-30);
            toDate ??= DateTime.Today;

            var transactions = await _dbContext.PaymentTransactions
                .Where(t => t.CreatedAt >= fromDate.Value && t.CreatedAt <= toDate.Value.AddDays(1))
                .Where(t => t.Status == "Completed" || t.Status == "PostedToPMS")
                .ToListAsync();

            // Daily revenue
            var dailyRevenue = transactions
                .GroupBy(t => t.CreatedAt.Date)
                .Select(g => new { Date = g.Key, Revenue = g.Sum(t => t.Amount), Count = g.Count() })
                .OrderBy(x => x.Date)
                .ToList();

            // Package breakdown
            var packageBreakdown = transactions
                .GroupBy(t => t.PackageName)
                .Select(g => new { Package = g.Key, Revenue = g.Sum(t => t.Amount), Count = g.Count() })
                .OrderByDescending(x => x.Revenue)
                .ToList();

            // Room breakdown (top 10)
            var roomBreakdown = transactions
                .GroupBy(t => t.RoomNumber)
                .Select(g => new { Room = g.Key, Revenue = g.Sum(t => t.Amount), Count = g.Count() })
                .OrderByDescending(x => x.Revenue)
                .Take(10)
                .ToList();

            ViewBag.FromDate = fromDate.Value.ToString("yyyy-MM-dd");
            ViewBag.ToDate = toDate.Value.ToString("yyyy-MM-dd");
            ViewBag.TotalRevenue = transactions.Sum(t => t.Amount);
            ViewBag.TotalTransactions = transactions.Count;
            ViewBag.AverageTransaction = transactions.Any() ? transactions.Average(t => t.Amount) : 0;
            ViewBag.DailyRevenue = dailyRevenue;
            ViewBag.PackageBreakdown = packageBreakdown;
            ViewBag.RoomBreakdown = roomBreakdown;

            return View(transactions);
        }
    }
}
