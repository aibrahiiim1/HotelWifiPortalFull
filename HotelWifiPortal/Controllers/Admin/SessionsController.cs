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

            // Get guest data for quota display
            var guestIds = sessions.Select(s => s.GuestId).Distinct().ToList();
            var guests = await _dbContext.Guests
                .Where(g => guestIds.Contains(g.Id))
                .ToDictionaryAsync(g => g.Id);

            ViewBag.Guests = guests;

            return View(sessions);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> ForceExpireQuota(int id)
        {
            var session = await _dbContext.WifiSessions
                .Include(s => s.Guest)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (session == null)
            {
                TempData["Error"] = "Session not found.";
                return RedirectToAction(nameof(Active));
            }

            var guest = session.Guest;
            if (guest == null)
            {
                guest = await _dbContext.Guests.FirstOrDefaultAsync(g => g.RoomNumber == session.RoomNumber);
            }

            if (guest == null)
            {
                TempData["Error"] = "Guest not found.";
                return RedirectToAction(nameof(Active));
            }

            try
            {
                // Set usage to exceed quota (total quota + 1 MB to ensure exceeded)
                var oldUsage = guest.UsedQuotaBytes;
                guest.UsedQuotaBytes = guest.TotalQuotaBytes + 1048576; // Exceed by 1 MB
                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("Force expired quota for Room {Room}: {OldUsage}MB -> {NewUsage}MB (Total quota: {Quota}MB)",
                    guest.RoomNumber,
                    oldUsage / 1048576.0,
                    guest.UsedQuotaBytes / 1048576.0,
                    guest.TotalQuotaBytes / 1048576.0);

                // Also update FreeRADIUS radacct if configured
                try
                {
                    var settings = await _dbContext.SystemSettings.ToListAsync();
                    var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                    var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                    if (!string.IsNullOrEmpty(connStr))
                    {
                        using var connection = new MySqlConnection(connStr);
                        await connection.OpenAsync();

                        // Update accounting to show exceeded usage
                        using var cmd = new MySqlConnection(connStr).CreateCommand();
                        cmd.Connection = connection;
                        cmd.CommandText = $"UPDATE {prefix}acct SET acctinputoctets = @bytes WHERE username = @username AND acctstoptime IS NULL";
                        cmd.Parameters.AddWithValue("@bytes", guest.UsedQuotaBytes);
                        cmd.Parameters.AddWithValue("@username", guest.RoomNumber);
                        await cmd.ExecuteNonQueryAsync();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not update FreeRADIUS accounting for forced quota expiry");
                }

                // Disconnect the session
                await _wifiService.DisconnectSessionAsync(id);

                TempData["Success"] = $"Quota force expired for Room {guest.RoomNumber}. Session disconnected. Guest will see paywall on reconnect.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error force expiring quota for session {SessionId}", id);
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(Active));
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
            try
            {
                // Get settings directly
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (enabled?.ToLower() != "true" || string.IsNullOrEmpty(connStr))
                {
                    // Fall back to WifiService
                    await _wifiService.UpdateSessionUsageAsync();
                    TempData["Success"] = "Session usage refreshed (FreeRADIUS not configured).";
                    return RedirectToAction(nameof(Active));
                }

                // Connect to FreeRADIUS database directly
                using var connection = new MySqlConnection(connStr);
                await connection.OpenAsync();

                // Get active sessions
                var sessions = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active")
                    .ToListAsync();

                int updated = 0;
                foreach (var session in sessions)
                {
                    var sql = $@"
                        SELECT 
                            COALESCE(SUM(acctinputoctets), 0) as total_input,
                            COALESCE(SUM(acctoutputoctets), 0) as total_output
                        FROM {prefix}acct WHERE username = @username";

                    using var cmd = new MySqlConnection(connStr).CreateCommand();
                    cmd.Connection = connection;
                    cmd.CommandText = sql;
                    cmd.Parameters.AddWithValue("@username", session.RoomNumber);

                    using var reader = await cmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        var inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                        var outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                        var totalBytes = inputBytes + outputBytes;

                        if (totalBytes > 0)
                        {
                            session.BytesDownloaded = inputBytes;
                            session.BytesUploaded = outputBytes;
                            session.BytesUsed = totalBytes;
                            session.LastActivity = DateTime.UtcNow;
                            updated++;

                            // Also update guest
                            if (session.GuestId > 0)
                            {
                                var guest = await _dbContext.Guests.FindAsync(session.GuestId);
                                if (guest != null && totalBytes > guest.UsedQuotaBytes)
                                {
                                    guest.UsedQuotaBytes = totalBytes;
                                }
                            }
                        }
                    }
                }

                await _dbContext.SaveChangesAsync();
                TempData["Success"] = $"Updated usage for {updated} sessions from FreeRADIUS.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing usage");
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(Active));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> CleanupDuplicateSessions()
        {
            try
            {
                // Find duplicate sessions for same guest+MAC combination
                var duplicateGroups = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active" || s.Status == "QuotaExceeded")
                    .GroupBy(s => new { s.GuestId, s.MacAddress })
                    .Where(g => g.Count() > 1)
                    .ToListAsync();

                int removed = 0;
                foreach (var group in duplicateGroups)
                {
                    // Keep the most recent session, close others
                    var sessions = group.OrderByDescending(s => s.SessionStart).ToList();
                    var keepSession = sessions.First();

                    // Aggregate usage to the kept session
                    long totalBytes = sessions.Sum(s => s.BytesUsed);
                    keepSession.BytesUsed = totalBytes;
                    keepSession.BytesDownloaded = sessions.Sum(s => s.BytesDownloaded);
                    keepSession.BytesUploaded = sessions.Sum(s => s.BytesUploaded);

                    // Close duplicate sessions
                    foreach (var dup in sessions.Skip(1))
                    {
                        dup.Status = "Merged";
                        dup.SessionEnd = DateTime.UtcNow;
                        removed++;
                    }
                }

                await _dbContext.SaveChangesAsync();

                if (removed > 0)
                {
                    TempData["Success"] = $"Cleaned up {removed} duplicate sessions.";
                    _logger.LogInformation("Cleaned up {Count} duplicate sessions", removed);
                }
                else
                {
                    TempData["Success"] = "No duplicate sessions found.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up duplicate sessions");
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> CloseQuotaExceededSessions()
        {
            try
            {
                var exceededSessions = await _dbContext.WifiSessions
                    .Where(s => s.Status == "QuotaExceeded")
                    .ToListAsync();

                foreach (var session in exceededSessions)
                {
                    session.Status = "Disconnected";
                    session.SessionEnd = DateTime.UtcNow;
                }

                await _dbContext.SaveChangesAsync();
                TempData["Success"] = $"Closed {exceededSessions.Count} quota exceeded sessions.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error closing quota exceeded sessions");
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(Index));
        }
    }
}