using HotelWifiPortal.Data;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services.WiFi;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Admin
{
    [Route("Admin/[controller]/[action]")]
    [Authorize(Roles = "Admin,SuperAdmin,Manager,Viewer")]
    public class SessionsController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly WifiService _wifiService;
        private readonly ILogger<SessionsController> _logger;

        public SessionsController(
            ApplicationDbContext dbContext,
            WifiService wifiService,
            ILogger<SessionsController> logger)
        {
            _dbContext = dbContext;
            _wifiService = wifiService;
            _logger = logger;
        }

        public async Task<IActionResult> Index(string? status, string? room, int page = 1)
        {
            var query = _dbContext.WifiSessions
                .Include(s => s.Guest)
                .Include(s => s.BandwidthProfile)
                .AsQueryable();

            if (!string.IsNullOrEmpty(status))
            {
                query = query.Where(s => s.Status == status);
            }

            if (!string.IsNullOrEmpty(room))
            {
                query = query.Where(s => s.RoomNumber.Contains(room));
            }

            var totalCount = await query.CountAsync();
            var pageSize = 20;

            var sessions = await query
                .OrderByDescending(s => s.SessionStart)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var model = new SessionListViewModel
            {
                Sessions = sessions,
                StatusFilter = status,
                RoomFilter = room,
                TotalCount = totalCount,
                PageNumber = page,
                PageSize = pageSize
            };

            return View(model);
        }

        public async Task<IActionResult> Active()
        {
            var sessions = await _wifiService.GetActiveSessionsAsync();
            return View(sessions);
        }

        public async Task<IActionResult> Details(int id)
        {
            var session = await _dbContext.WifiSessions
                .Include(s => s.Guest)
                .Include(s => s.BandwidthProfile)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (session == null)
            {
                return NotFound();
            }

            return View(session);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Disconnect(int id)
        {
            var session = await _dbContext.WifiSessions.FindAsync(id);
            if (session == null)
            {
                return NotFound();
            }

            await _wifiService.DisconnectSessionAsync(id);

            _logger.LogInformation("Session disconnected: MAC {Mac}, Room {Room}", session.MacAddress, session.RoomNumber);
            TempData["Success"] = "Session disconnected successfully.";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> DisconnectAll(string room)
        {
            var sessions = await _dbContext.WifiSessions
                .Where(s => s.RoomNumber == room && s.Status == "Active")
                .ToListAsync();

            foreach (var session in sessions)
            {
                await _wifiService.DisconnectSessionAsync(session.Id);
            }

            _logger.LogInformation("All sessions disconnected for Room {Room}", room);
            TempData["Success"] = $"All sessions for Room {room} disconnected.";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> Block(int id)
        {
            var session = await _dbContext.WifiSessions.FindAsync(id);
            if (session == null)
            {
                return NotFound();
            }

            var controller = _wifiService.GetController(session.ControllerType);
            if (controller != null)
            {
                await controller.BlockClientAsync(session.MacAddress);
            }

            session.Status = "Blocked";
            session.SessionEnd = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Client blocked: MAC {Mac}", session.MacAddress);
            TempData["Success"] = "Client blocked successfully.";

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> GetActiveSessionsJson()
        {
            var sessions = await _wifiService.GetActiveSessionsAsync();
            return Json(sessions.Select(s => new
            {
                s.Id,
                s.RoomNumber,
                s.GuestName,
                s.MacAddress,
                s.IpAddress,
                s.Status,
                BytesUsedMB = s.BytesUsedMB,
                SessionDuration = s.SessionDuration?.ToString(@"hh\:mm\:ss"),
                s.ControllerType
            }));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> RefreshUsage()
        {
            await _wifiService.UpdateSessionUsageAsync();
            TempData["Success"] = "Session usage data refreshed.";
            return RedirectToAction(nameof(Active));
        }
    }
}
