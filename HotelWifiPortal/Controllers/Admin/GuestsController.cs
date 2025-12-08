using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services;
using HotelWifiPortal.Services.PMS;
using HotelWifiPortal.Services.Radius;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Admin
{
    [Route("Admin/[controller]/[action]")]
    [Authorize(Roles = "Admin,SuperAdmin,Manager,Viewer")]
    public class GuestsController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly QuotaService _quotaService;
        private readonly FiasSocketServer _fiasServer;
        private readonly RadiusServer _radiusServer;
        private readonly ILogger<GuestsController> _logger;

        public GuestsController(
            ApplicationDbContext dbContext,
            QuotaService quotaService,
            FiasSocketServer fiasServer,
            RadiusServer radiusServer,
            ILogger<GuestsController> logger)
        {
            _dbContext = dbContext;
            _quotaService = quotaService;
            _fiasServer = fiasServer;
            _radiusServer = radiusServer;
            _logger = logger;
        }

        public async Task<IActionResult> Index(string? search, string? status, int page = 1)
        {
            var query = _dbContext.Guests.AsQueryable();

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(g =>
                    g.RoomNumber.Contains(search) ||
                    g.GuestName.Contains(search) ||
                    g.ReservationNumber.Contains(search));
            }

            if (!string.IsNullOrEmpty(status))
            {
                query = query.Where(g => g.Status == status);
            }

            var totalCount = await query.CountAsync();
            var pageSize = 20;

            var guests = await query
                .OrderByDescending(g => g.UpdatedAt)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var model = new GuestListViewModel
            {
                Guests = guests,
                SearchTerm = search,
                StatusFilter = status,
                TotalCount = totalCount,
                PageNumber = page,
                PageSize = pageSize
            };

            return View(model);
        }

        public async Task<IActionResult> Details(int id)
        {
            var guest = await _dbContext.Guests
                .Include(g => g.WifiSessions)
                .Include(g => g.PaymentTransactions)
                .FirstOrDefaultAsync(g => g.Id == id);

            if (guest == null)
            {
                return NotFound();
            }

            var package = await _quotaService.GetPackageForStayLengthAsync(guest.StayLength);
            ViewBag.CurrentPackage = package;

            return View(guest);
        }

        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public IActionResult Create()
        {
            return View(new Guest
            {
                ArrivalDate = DateTime.Today,
                DepartureDate = DateTime.Today.AddDays(1),
                Status = "checked-in",
                Source = "Local"
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Create(Guest guest)
        {
            if (string.IsNullOrEmpty(guest.ReservationNumber))
            {
                guest.ReservationNumber = $"LOCAL-{DateTime.Now:yyyyMMddHHmmss}";
            }

            // Check for duplicate reservation
            if (await _dbContext.Guests.AnyAsync(g => g.ReservationNumber == guest.ReservationNumber))
            {
                ModelState.AddModelError("ReservationNumber", "Reservation number already exists.");
                return View(guest);
            }

            guest.Source = "Local";
            guest.CreatedAt = DateTime.UtcNow;
            guest.UpdatedAt = DateTime.UtcNow;

            // Calculate free quota
            guest.FreeQuotaBytes = await _quotaService.CalculateFreeQuotaAsync(guest.StayLength);

            _dbContext.Guests.Add(guest);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Guest created manually: {Name} Room {Room}", guest.GuestName, guest.RoomNumber);
            TempData["Success"] = "Guest created successfully.";

            return RedirectToAction(nameof(Details), new { id = guest.Id });
        }

        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Edit(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                return NotFound();
            }

            // Get free packages for dropdown
            var freePackages = await _dbContext.BandwidthPackages
                .Where(p => p.IsActive)
                .OrderBy(p => p.QuotaGB)
                .Select(p => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
                {
                    Value = p.Id.ToString(),
                    Text = $"{p.Name} ({p.QuotaGB}GB, {(p.SpeedLimitKbps ?? 0) / 1000}Mbps)"
                })
                .ToListAsync();
            freePackages.Insert(0, new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = "", Text = "-- Custom Quota --" });

            // Get bandwidth profiles for dropdown
            var bandwidthProfiles = await _dbContext.BandwidthProfiles
                .Where(p => p.IsActive)
                .OrderBy(p => p.Name)
                .Select(p => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
                {
                    Value = p.Id.ToString(),
                    Text = $"{p.Name} ({p.DownloadSpeedKbps / 1000}Mbps down / {p.UploadSpeedKbps / 1000}Mbps up)"
                })
                .ToListAsync();
            bandwidthProfiles.Insert(0, new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = "", Text = "-- Default Profile --" });

            var model = new GuestEditViewModel
            {
                Guest = guest,
                FreePackages = freePackages,
                BandwidthProfiles = bandwidthProfiles,
                SelectedBandwidthProfileId = guest.BandwidthProfileId,
                TotalQuotaGB = guest.TotalQuotaBytes / 1073741824.0
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Edit(int id, GuestEditViewModel model)
        {
            if (id != model.Guest.Id)
            {
                return NotFound();
            }

            var existingGuest = await _dbContext.Guests.FindAsync(id);
            if (existingGuest == null)
            {
                return NotFound();
            }

            // Update basic info
            existingGuest.RoomNumber = model.Guest.RoomNumber;
            existingGuest.ReservationNumber = model.Guest.ReservationNumber;
            existingGuest.GuestName = model.Guest.GuestName;
            existingGuest.Language = model.Guest.Language;
            existingGuest.ArrivalDate = model.Guest.ArrivalDate;
            existingGuest.DepartureDate = model.Guest.DepartureDate;
            existingGuest.Status = model.Guest.Status;
            existingGuest.VipStatus = model.Guest.VipStatus;
            existingGuest.Email = model.Guest.Email;
            existingGuest.Phone = model.Guest.Phone;
            existingGuest.Notes = model.Guest.Notes;
            existingGuest.LocalPassword = model.Guest.LocalPassword;
            existingGuest.UpdatedAt = DateTime.UtcNow;

            // Handle quota assignment
            if (model.SelectedFreePackageId.HasValue && model.SelectedFreePackageId.Value > 0)
            {
                // Apply free package quota
                var package = await _dbContext.BandwidthPackages.FindAsync(model.SelectedFreePackageId.Value);
                if (package != null)
                {
                    existingGuest.FreeQuotaBytes = (long)(package.QuotaGB * 1073741824);
                    _logger.LogInformation("Applied free package {Package} to guest {Room}: {Quota}GB",
                        package.Name, existingGuest.RoomNumber, package.QuotaGB);
                }
            }
            else if (model.TotalQuotaGB > 0)
            {
                // Manual quota override
                existingGuest.FreeQuotaBytes = (long)(model.TotalQuotaGB * 1073741824) - existingGuest.PaidQuotaBytes;
                if (existingGuest.FreeQuotaBytes < 0) existingGuest.FreeQuotaBytes = 0;
            }

            // Handle bandwidth profile assignment
            if (model.SelectedBandwidthProfileId.HasValue && model.SelectedBandwidthProfileId.Value > 0)
            {
                existingGuest.BandwidthProfileId = model.SelectedBandwidthProfileId.Value;
                var profile = await _dbContext.BandwidthProfiles.FindAsync(model.SelectedBandwidthProfileId.Value);
                _logger.LogInformation("Applied bandwidth profile {Profile} to guest {Room}",
                    profile?.Name, existingGuest.RoomNumber);
            }
            else
            {
                existingGuest.BandwidthProfileId = null; // Use default
            }

            // Reset usage if requested
            if (model.ResetUsage)
            {
                existingGuest.UsedQuotaBytes = 0;
                _logger.LogInformation("Reset usage for guest {Room}", existingGuest.RoomNumber);
            }

            // Handle WiFi password updates
            var oldWifiPassword = existingGuest.WifiPassword;
            existingGuest.WifiPassword = model.Guest.WifiPassword;
            existingGuest.PasswordResetRequired = model.Guest.PasswordResetRequired;

            // If WiFi password was changed, update the timestamp
            if (oldWifiPassword != existingGuest.WifiPassword && !string.IsNullOrEmpty(existingGuest.WifiPassword))
            {
                existingGuest.PasswordSetAt = DateTime.UtcNow;
                _logger.LogInformation("WiFi password updated for guest {Room}", existingGuest.RoomNumber);
            }

            await _dbContext.SaveChangesAsync();

            // If WiFi password was set/changed, update FreeRADIUS
            if (!string.IsNullOrEmpty(existingGuest.WifiPassword) && oldWifiPassword != existingGuest.WifiPassword)
            {
                try
                {
                    // Update FreeRADIUS with new password
                    var freeRadiusService = HttpContext.RequestServices.GetService<Services.Radius.FreeRadiusService>();
                    if (freeRadiusService != null)
                    {
                        await freeRadiusService.CreateOrUpdateUserAsync(existingGuest);
                        _logger.LogInformation("FreeRADIUS updated with new password for {Room}", existingGuest.RoomNumber);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not update FreeRADIUS password for {Room}", existingGuest.RoomNumber);
                }
            }

            TempData["Success"] = "Guest updated successfully.";
            return RedirectToAction(nameof(Edit), new { id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> ApplyToActiveSession(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                TempData["Error"] = "Guest not found.";
                return RedirectToAction(nameof(Index));
            }

            try
            {
                var disconnected = await _radiusServer.ForceGuestReauthenticationAsync(id);

                if (disconnected > 0)
                {
                    _logger.LogInformation("Force re-authentication for guest {GuestId}: {Count} sessions disconnected",
                        id, disconnected);
                    TempData["Success"] = $"Disconnected {disconnected} active session(s). Guest will reconnect with updated settings.";
                }
                else
                {
                    TempData["Warning"] = "No active sessions found for this guest.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error forcing re-authentication for guest {GuestId}", id);
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(Edit), new { id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> ResetGuestUsage(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                TempData["Error"] = "Guest not found.";
                return RedirectToAction(nameof(Index));
            }

            try
            {
                var oldUsage = guest.UsedQuotaBytes;
                guest.UsedQuotaBytes = 0;
                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("Reset usage for guest {Room}: {OldUsage}MB -> 0",
                    guest.RoomNumber, oldUsage / 1048576.0);

                // Also try to reset in FreeRADIUS radacct
                try
                {
                    var settings = await _dbContext.SystemSettings.ToListAsync();
                    var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                    var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                    if (!string.IsNullOrEmpty(connStr))
                    {
                        using var connection = new MySqlConnector.MySqlConnection(connStr);
                        await connection.OpenAsync();

                        using var cmd = new MySqlConnector.MySqlCommand(
                            $"UPDATE {prefix}acct SET acctinputoctets = 0, acctoutputoctets = 0 WHERE username = @username",
                            connection);
                        cmd.Parameters.AddWithValue("@username", guest.RoomNumber);
                        await cmd.ExecuteNonQueryAsync();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not reset FreeRADIUS accounting for {Room}", guest.RoomNumber);
                }

                TempData["Success"] = $"Usage reset to zero for Room {guest.RoomNumber}. Previous usage: {oldUsage / 1048576.0:N2} MB";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting usage for guest {GuestId}", id);
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(Edit), new { id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> DeleteFromRadius(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                TempData["Error"] = "Guest not found.";
                return RedirectToAction(nameof(Index));
            }

            try
            {
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (string.IsNullOrEmpty(connStr))
                {
                    TempData["Warning"] = "FreeRADIUS is not configured.";
                    return RedirectToAction(nameof(Edit), new { id });
                }

                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();

                int totalDeleted = 0;

                // Delete from radcheck
                using var cmd1 = new MySqlConnector.MySqlCommand(
                    $"DELETE FROM {prefix}check WHERE username = @username", connection);
                cmd1.Parameters.AddWithValue("@username", guest.RoomNumber);
                totalDeleted += await cmd1.ExecuteNonQueryAsync();

                // Delete from radreply
                using var cmd2 = new MySqlConnector.MySqlCommand(
                    $"DELETE FROM {prefix}reply WHERE username = @username", connection);
                cmd2.Parameters.AddWithValue("@username", guest.RoomNumber);
                totalDeleted += await cmd2.ExecuteNonQueryAsync();

                // Delete from radusergroup
                using var cmd3 = new MySqlConnector.MySqlCommand(
                    $"DELETE FROM {prefix}usergroup WHERE username = @username", connection);
                cmd3.Parameters.AddWithValue("@username", guest.RoomNumber);
                totalDeleted += await cmd3.ExecuteNonQueryAsync();

                _logger.LogInformation("Deleted guest {Room} from FreeRADIUS: {Count} entries",
                    guest.RoomNumber, totalDeleted);

                TempData["Success"] = $"Deleted Room {guest.RoomNumber} from FreeRADIUS ({totalDeleted} entries). Use 'Sync All Guests' to re-add.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting guest {GuestId} from FreeRADIUS", id);
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(Edit), new { id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> Delete(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                return NotFound();
            }

            _dbContext.Guests.Remove(guest);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Guest deleted: {Name} Room {Room}", guest.GuestName, guest.RoomNumber);
            TempData["Success"] = "Guest deleted successfully.";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> CheckOut(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                return NotFound();
            }

            guest.Status = "checked-out";
            guest.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            TempData["Success"] = $"Guest {guest.GuestName} checked out successfully.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> ResetQuota(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                return NotFound();
            }

            guest.UsedQuotaBytes = 0;
            guest.QuotaResetDate = DateTime.UtcNow;
            guest.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Quota reset for guest: {Name} Room {Room}", guest.GuestName, guest.RoomNumber);
            TempData["Success"] = "Guest quota reset successfully.";

            return RedirectToAction(nameof(Details), new { id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> AddQuota(int id, double quotaGB)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                return NotFound();
            }

            var quotaBytes = (long)(quotaGB * 1024 * 1024 * 1024);
            guest.PaidQuotaBytes += quotaBytes;
            guest.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Added {QuotaGB}GB quota to guest: {Name} Room {Room}", quotaGB, guest.GuestName, guest.RoomNumber);
            TempData["Success"] = $"Added {quotaGB} GB to guest quota.";

            return RedirectToAction(nameof(Details), new { id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> SyncFromPms()
        {
            if (!_fiasServer.IsConnected)
            {
                TempData["Error"] = "PMS is not connected.";
                return RedirectToAction(nameof(Index));
            }

            await _fiasServer.RequestDatabaseResyncAsync();
            TempData["Success"] = "Database resync requested. Guests will be synchronized from PMS.";

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> GetGuestJson(int id)
        {
            var guest = await _dbContext.Guests.FindAsync(id);
            if (guest == null)
            {
                return NotFound();
            }

            return Json(new
            {
                guest.Id,
                guest.RoomNumber,
                guest.ReservationNumber,
                guest.GuestName,
                guest.Status,
                guest.UsedQuotaGB,
                guest.TotalQuotaGB,
                guest.RemainingQuotaGB,
                guest.IsQuotaExhausted
            });
        }
    }
}