using HotelWifiPortal.Data;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services.WiFi;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;

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

        // Main Sessions view - shows all sessions with room-based usage
        public async Task<IActionResult> Index(string? status, string? room, int page = 1)
        {
            var query = _dbContext.WifiSessions
                .Include(s => s.Guest)
                .Include(s => s.BandwidthProfile)
                .AsQueryable();

            if (!string.IsNullOrEmpty(status))
                query = query.Where(s => s.Status == status);

            if (!string.IsNullOrEmpty(room))
                query = query.Where(s => s.RoomNumber.Contains(room));

            var totalCount = await query.CountAsync();
            var pageSize = 50;

            var sessions = await query
                .OrderByDescending(s => s.SessionStart)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var roomUsage = await GetRoomBasedUsageAsync();
            ViewBag.RoomUsage = roomUsage;

            var guestIds = sessions.Select(s => s.GuestId).Distinct().ToList();
            var guests = await _dbContext.Guests
                .Where(g => guestIds.Contains(g.Id))
                .ToDictionaryAsync(g => g.Id);
            ViewBag.Guests = guests;

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

        // Room Usage Summary - Aggregated by room (uses Guest quota as source of truth)
        public async Task<IActionResult> RoomUsage(string? room, int page = 1)
        {
            // Get session stats for device count and session info
            var query = _dbContext.WifiSessions.AsQueryable();

            if (!string.IsNullOrEmpty(room))
                query = query.Where(s => s.RoomNumber.Contains(room));

            var sessionStats = await query
                .GroupBy(s => s.RoomNumber)
                .Select(g => new
                {
                    RoomNumber = g.Key,
                    DeviceCount = g.Select(s => s.MacAddress).Distinct().Count(),
                    SessionCount = g.Count(),
                    ActiveSessions = g.Count(s => s.Status == "Active"),
                    FirstSession = g.Min(s => s.SessionStart),
                    LastActivity = g.Max(s => s.SessionStart)
                })
                .ToDictionaryAsync(x => x.RoomNumber);

            // Get all active guests - Guest.UsedQuotaBytes is the source of truth for room usage
            var guestQuery = _dbContext.Guests
                .Where(g => g.Status == "checked-in" || g.Status == "Checked-In" || g.Status == "CheckedIn" || g.Status == "active");

            if (!string.IsNullOrEmpty(room))
                guestQuery = guestQuery.Where(g => g.RoomNumber.Contains(room));

            var guests = await guestQuery.ToListAsync();

            var roomUsageList = guests.Select(g => {
                var stats = sessionStats.ContainsKey(g.RoomNumber) ? sessionStats[g.RoomNumber] : null;
                return new RoomUsageViewModel
                {
                    RoomNumber = g.RoomNumber,
                    GuestName = g.GuestName,
                    // Use Guest's UsedQuotaBytes as the source of truth for room usage
                    TotalBytesUsed = g.UsedQuotaBytes,
                    TotalBytesDownloaded = 0, // Not tracked per-room
                    TotalBytesUploaded = 0,   // Not tracked per-room
                    TotalQuotaBytes = g.TotalQuotaBytes,
                    UsedQuotaBytes = g.UsedQuotaBytes,
                    DeviceCount = stats?.DeviceCount ?? 0,
                    SessionCount = stats?.SessionCount ?? 0,
                    ActiveSessions = stats?.ActiveSessions ?? 0,
                    FirstSession = stats?.FirstSession ?? g.CheckInDate,
                    LastActivity = stats?.LastActivity ?? g.CheckInDate
                };
            })
            .OrderByDescending(r => r.TotalBytesUsed)
            .ToList();

            var totalCount = roomUsageList.Count;
            var pageSize = 50;

            ViewBag.TotalCount = totalCount;
            ViewBag.PageNumber = page;
            ViewBag.PageSize = pageSize;
            ViewBag.RoomFilter = room;
            ViewBag.TotalUsageBytes = roomUsageList.Sum(r => r.UsedQuotaBytes);
            ViewBag.TotalRooms = roomUsageList.Count;

            return View(roomUsageList.Skip((page - 1) * pageSize).Take(pageSize).ToList());
        }

        // MAC Address Usage view - Device-based usage
        public async Task<IActionResult> MacUsage(string? room, string? mac, int page = 1)
        {
            var query = _dbContext.WifiSessions.Include(s => s.Guest).AsQueryable();

            if (!string.IsNullOrEmpty(room))
                query = query.Where(s => s.RoomNumber.Contains(room));

            if (!string.IsNullOrEmpty(mac))
                query = query.Where(s => s.MacAddress.Contains(mac));

            var macUsageList = await query
                .GroupBy(s => new { s.MacAddress, s.RoomNumber, s.GuestName })
                .Select(g => new MacUsageViewModel
                {
                    MacAddress = g.Key.MacAddress,
                    RoomNumber = g.Key.RoomNumber,
                    GuestName = g.Key.GuestName ?? "Unknown",
                    TotalBytesUsed = g.Sum(s => s.BytesUsed),
                    TotalBytesDownloaded = g.Sum(s => s.BytesDownloaded),
                    TotalBytesUploaded = g.Sum(s => s.BytesUploaded),
                    SessionCount = g.Count(),
                    FirstSeen = g.Min(s => s.SessionStart),
                    LastSeen = g.Max(s => s.SessionStart),
                    IsCurrentlyActive = g.Any(s => s.Status == "Active")
                })
                .OrderByDescending(m => m.TotalBytesUsed)
                .ToListAsync();

            var totalCount = macUsageList.Count;
            var pageSize = 50;

            ViewBag.TotalCount = totalCount;
            ViewBag.PageNumber = page;
            ViewBag.PageSize = pageSize;
            ViewBag.RoomFilter = room;
            ViewBag.MacFilter = mac;
            ViewBag.TotalUsageBytes = macUsageList.Sum(m => m.TotalBytesUsed);
            ViewBag.TotalDevices = macUsageList.Count;

            return View(macUsageList.Skip((page - 1) * pageSize).Take(pageSize).ToList());
        }

        private async Task<Dictionary<string, long>> GetRoomBasedUsageAsync()
        {
            return await _dbContext.WifiSessions
                .GroupBy(s => s.RoomNumber)
                .Select(g => new { RoomNumber = g.Key, TotalBytes = g.Sum(s => s.BytesUsed) })
                .ToDictionaryAsync(x => x.RoomNumber, x => x.TotalBytes);
        }

        public async Task<IActionResult> Active()
        {
            var sessions = await _wifiService.GetActiveSessionsAsync();
            var guestIds = sessions.Select(s => s.GuestId).Distinct().ToList();
            var guests = await _dbContext.Guests.Where(g => guestIds.Contains(g.Id)).ToDictionaryAsync(g => g.Id);
            var roomUsage = await GetRoomBasedUsageAsync();
            ViewBag.Guests = guests;
            ViewBag.RoomUsage = roomUsage;
            return View(sessions);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> ForceExpireQuota(int id)
        {
            var session = await _dbContext.WifiSessions.Include(s => s.Guest).FirstOrDefaultAsync(s => s.Id == id);
            if (session == null) { TempData["Error"] = "Session not found."; return RedirectToAction(nameof(Active)); }

            var guest = session.Guest ?? await _dbContext.Guests.FirstOrDefaultAsync(g => g.RoomNumber == session.RoomNumber);
            if (guest == null) { TempData["Error"] = "Guest not found."; return RedirectToAction(nameof(Active)); }

            try
            {
                guest.UsedQuotaBytes = guest.TotalQuotaBytes + 1048576;
                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("Force expired quota for Room {Room}", guest.RoomNumber);
                await _wifiService.DisconnectSessionAsync(id);
                TempData["Success"] = $"Quota force expired for Room {guest.RoomNumber}.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error force expiring quota");
                TempData["Error"] = $"Error: {ex.Message}";
            }
            return RedirectToAction(nameof(Active));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Disconnect(int id)
        {
            var session = await _dbContext.WifiSessions.FindAsync(id);
            if (session == null) return NotFound();
            await _wifiService.DisconnectSessionAsync(id);
            _logger.LogInformation("Session disconnected: MAC {Mac}, Room {Room}", session.MacAddress, session.RoomNumber);
            TempData["Success"] = "Session disconnected successfully.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Block(int id)
        {
            var session = await _dbContext.WifiSessions.FindAsync(id);
            if (session == null) return NotFound();
            var controller = _wifiService.GetController(session.ControllerType);
            if (controller != null) await controller.BlockClientAsync(session.MacAddress);
            session.Status = "Blocked";
            session.SessionEnd = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
            TempData["Success"] = "Client blocked successfully.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> RefreshUsage()
        {
            try
            {
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (enabled?.ToLower() != "true" || string.IsNullOrEmpty(connStr))
                {
                    await _wifiService.UpdateSessionUsageAsync();
                    TempData["Success"] = "Session usage refreshed.";
                    return RedirectToAction(nameof(Index));
                }

                using var connection = new MySqlConnection(connStr);
                await connection.OpenAsync();

                var roomNumbers = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active")
                    .Select(s => s.RoomNumber)
                    .Distinct()
                    .ToListAsync();

                int updatedRooms = 0;
                foreach (var roomNumber in roomNumbers)
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = $"SELECT COALESCE(SUM(acctinputoctets), 0) + COALESCE(SUM(acctoutputoctets), 0) FROM {prefix}acct WHERE username = @username";
                    cmd.Parameters.AddWithValue("@username", roomNumber);

                    var totalBytes = Convert.ToInt64(await cmd.ExecuteScalarAsync() ?? 0);
                    if (totalBytes > 0)
                    {
                        var guest = await _dbContext.Guests.FirstOrDefaultAsync(g => g.RoomNumber == roomNumber &&
                            (g.Status == "checked-in" || g.Status == "Checked-In" || g.Status == "CheckedIn" || g.Status == "active"));
                        if (guest != null && totalBytes > guest.UsedQuotaBytes)
                        {
                            guest.UsedQuotaBytes = totalBytes;
                            updatedRooms++;
                        }
                    }
                }
                await _dbContext.SaveChangesAsync();
                TempData["Success"] = $"Updated room-based usage for {updatedRooms} rooms.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing usage");
                TempData["Error"] = $"Error: {ex.Message}";
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> CleanupDuplicateSessions()
        {
            try
            {
                var duplicateGroups = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active" || s.Status == "QuotaExceeded")
                    .GroupBy(s => new { s.GuestId, s.MacAddress })
                    .Where(g => g.Count() > 1)
                    .ToListAsync();

                int removed = 0;
                foreach (var group in duplicateGroups)
                {
                    var sessions = group.OrderByDescending(s => s.SessionStart).ToList();
                    var keepSession = sessions.First();
                    keepSession.BytesUsed = sessions.Sum(s => s.BytesUsed);
                    foreach (var dup in sessions.Skip(1))
                    {
                        dup.Status = "Merged";
                        dup.SessionEnd = DateTime.UtcNow;
                        removed++;
                    }
                }
                await _dbContext.SaveChangesAsync();
                TempData["Success"] = removed > 0 ? $"Cleaned up {removed} duplicate sessions." : "No duplicate sessions found.";
            }
            catch (Exception ex)
            {
                TempData["Error"] = $"Error: {ex.Message}";
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> CloseQuotaExceededSessions()
        {
            var exceededSessions = await _dbContext.WifiSessions.Where(s => s.Status == "QuotaExceeded").ToListAsync();
            foreach (var session in exceededSessions)
            {
                session.Status = "Disconnected";
                session.SessionEnd = DateTime.UtcNow;
            }
            await _dbContext.SaveChangesAsync();
            TempData["Success"] = $"Closed {exceededSessions.Count} quota exceeded sessions.";
            return RedirectToAction(nameof(Index));
        }
    }

    public class MacUsageViewModel
    {
        public string MacAddress { get; set; } = "";
        public string RoomNumber { get; set; } = "";
        public string GuestName { get; set; } = "";
        public long TotalBytesUsed { get; set; }
        public long TotalBytesDownloaded { get; set; }
        public long TotalBytesUploaded { get; set; }
        public int SessionCount { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public bool IsCurrentlyActive { get; set; }
        public double TotalMBUsed => TotalBytesUsed / 1048576.0;
        public double TotalGBUsed => TotalBytesUsed / 1073741824.0;
    }

    public class RoomUsageViewModel
    {
        public string RoomNumber { get; set; } = "";
        public string? GuestName { get; set; }
        public long TotalBytesUsed { get; set; }
        public long TotalBytesDownloaded { get; set; }
        public long TotalBytesUploaded { get; set; }
        public int DeviceCount { get; set; }
        public int SessionCount { get; set; }
        public int ActiveSessions { get; set; }
        public DateTime FirstSession { get; set; }
        public DateTime LastActivity { get; set; }
        public long TotalQuotaBytes { get; set; }
        public long UsedQuotaBytes { get; set; }
        public double TotalMBUsed => TotalBytesUsed / 1048576.0;
        public double TotalGBUsed => TotalBytesUsed / 1073741824.0;
        public int QuotaPercentUsed => TotalQuotaBytes > 0 ? (int)((UsedQuotaBytes * 100) / TotalQuotaBytes) : 0;
    }
}