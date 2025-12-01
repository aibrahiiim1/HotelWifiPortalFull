using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services;
using HotelWifiPortal.Services.PMS;
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
        private readonly ILogger<GuestsController> _logger;

        public GuestsController(
            ApplicationDbContext dbContext,
            QuotaService quotaService,
            FiasSocketServer fiasServer,
            ILogger<GuestsController> logger)
        {
            _dbContext = dbContext;
            _quotaService = quotaService;
            _fiasServer = fiasServer;
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

            return View(guest);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Edit(int id, Guest guest)
        {
            if (id != guest.Id)
            {
                return NotFound();
            }

            var existingGuest = await _dbContext.Guests.FindAsync(id);
            if (existingGuest == null)
            {
                return NotFound();
            }

            existingGuest.RoomNumber = guest.RoomNumber;
            existingGuest.GuestName = guest.GuestName;
            existingGuest.Language = guest.Language;
            existingGuest.ArrivalDate = guest.ArrivalDate;
            existingGuest.DepartureDate = guest.DepartureDate;
            existingGuest.Status = guest.Status;
            existingGuest.VipStatus = guest.VipStatus;
            existingGuest.Email = guest.Email;
            existingGuest.Phone = guest.Phone;
            existingGuest.Notes = guest.Notes;
            existingGuest.LocalPassword = guest.LocalPassword;
            existingGuest.UpdatedAt = DateTime.UtcNow;

            // Recalculate quota if stay length changed
            var newQuota = await _quotaService.CalculateFreeQuotaAsync(existingGuest.StayLength);
            if (existingGuest.FreeQuotaBytes != newQuota)
            {
                existingGuest.FreeQuotaBytes = newQuota;
            }

            await _dbContext.SaveChangesAsync();

            TempData["Success"] = "Guest updated successfully.";
            return RedirectToAction(nameof(Details), new { id });
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
