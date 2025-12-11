using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services.Radius;
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
        private readonly FreeRadiusService _freeRadiusService;
        private readonly ILogger<SessionsController> _logger;

        public SessionsController(
            ApplicationDbContext dbContext,
            WifiService wifiService,
            FreeRadiusService freeRadiusService,
            ILogger<SessionsController> logger)
        {
            _dbContext = dbContext;
            _wifiService = wifiService;
            _freeRadiusService = freeRadiusService;
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
                    QuotaExceededSessions = g.Count(s => s.Status == "QuotaExceeded"),
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

            // Get active paid packages for all guests
            var guestIds = guests.Select(g => g.Id).ToList();
            var activePaidPackages = await _dbContext.GuestPaidPackages
                .Where(p => guestIds.Contains(p.GuestId) && p.Status == "Active")
                .ToListAsync();

            var packagesByGuestId = activePaidPackages
                .GroupBy(p => p.GuestId)
                .ToDictionary(g => g.Key, g => g.ToList());

            var roomUsageList = guests.Select(g => {
                var stats = sessionStats.ContainsKey(g.RoomNumber) ? sessionStats[g.RoomNumber] : null;
                var guestPackages = packagesByGuestId.ContainsKey(g.Id) ? packagesByGuestId[g.Id] : new List<GuestPaidPackage>();

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
                    LastActivity = stats?.LastActivity ?? g.CheckInDate,
                    // New fields for quota status
                    FreeQuotaBytes = g.FreeQuotaBytes,
                    PaidQuotaBytes = g.PaidQuotaBytes,
                    IsQuotaExceeded = g.IsQuotaExhausted,
                    HasPurchasedPackage = g.HasPurchasedPackage,
                    GuestStatus = g.Status,
                    QuotaExceededSessions = stats?.QuotaExceededSessions ?? 0,
                    // Active paid packages
                    ActivePaidPackages = guestPackages.Select(p => new ActivePaidPackageInfo
                    {
                        Id = p.Id,
                        PackageName = p.PackageName,
                        PackageType = p.PackageType,
                        QuotaGB = p.QuotaGB,
                        UsedGB = p.UsedGB,
                        DownloadSpeedKbps = p.DownloadSpeedKbps,
                        UploadSpeedKbps = p.UploadSpeedKbps,
                        ActivatedAt = p.ActivatedAt,
                        ExpiresAt = p.ExpiresAt,
                        Status = p.Status
                    }).ToList()
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

            var macAddress = session.MacAddress?.ToUpper();
            if (string.IsNullOrEmpty(macAddress))
            {
                TempData["Error"] = "No MAC address found for this session.";
                return RedirectToAction(nameof(Index));
            }

            try
            {
                // Disconnect from network via CoA and MikroTik API
                await DisconnectMacFromNetwork(macAddress, session.RadiusSessionId);

                // Update session in database
                session.Status = "Disconnected";
                session.SessionEnd = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("Session disconnected: MAC {Mac}, Room {Room} by {User}",
                    macAddress, session.RoomNumber, User.Identity?.Name);
                TempData["Success"] = $"Session for MAC {macAddress} disconnected successfully.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disconnecting session {Id}", id);
                TempData["Error"] = $"Error disconnecting: {ex.Message}";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Block(int id)
        {
            var session = await _dbContext.WifiSessions
                .Include(s => s.Guest)
                .FirstOrDefaultAsync(s => s.Id == id);
            if (session == null) return NotFound();

            var macAddress = session.MacAddress?.ToUpper();
            if (string.IsNullOrEmpty(macAddress))
            {
                TempData["Error"] = "No MAC address found for this session.";
                return RedirectToAction(nameof(Index));
            }

            try
            {
                // 1. First disconnect the user via CoA
                await DisconnectMacFromNetwork(macAddress, session.RadiusSessionId);

                // 2. Add to BlockedMacs table
                var existingBlock = await _dbContext.BlockedMacs
                    .FirstOrDefaultAsync(b => b.MacAddress == macAddress && b.IsActive);

                if (existingBlock == null)
                {
                    var blockedMac = new BlockedMac
                    {
                        MacAddress = macAddress,
                        Reason = "Blocked from session management",
                        BlockedBy = User.Identity?.Name ?? "System",
                        RoomNumber = session.RoomNumber,
                        GuestName = session.GuestName ?? session.Guest?.GuestName,
                        BlockedAt = DateTime.UtcNow,
                        IsActive = true
                    };
                    _dbContext.BlockedMacs.Add(blockedMac);
                }

                // 3. Add to FreeRADIUS radcheck with Auth-Type := Reject
                await AddToFreeRadiusBlockList(macAddress);

                // 4. Update session status
                session.Status = "Blocked";
                session.SessionEnd = DateTime.UtcNow;

                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("Blocked MAC {Mac} by {User}", macAddress, User.Identity?.Name);
                TempData["Success"] = $"MAC {macAddress} blocked successfully.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error blocking MAC {Mac}", macAddress);
                TempData["Error"] = $"Error blocking MAC: {ex.Message}";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> Unblock(int id)
        {
            var blockedMac = await _dbContext.BlockedMacs.FindAsync(id);
            if (blockedMac == null) return NotFound();

            try
            {
                // Remove from FreeRADIUS block list
                await RemoveFromFreeRadiusBlockList(blockedMac.MacAddress);

                // Update BlockedMacs record
                blockedMac.IsActive = false;
                blockedMac.UnblockedAt = DateTime.UtcNow;
                blockedMac.UnblockedBy = User.Identity?.Name ?? "System";

                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("Unblocked MAC {Mac} by {User}", blockedMac.MacAddress, User.Identity?.Name);
                TempData["Success"] = $"MAC {blockedMac.MacAddress} unblocked successfully.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unblocking MAC {Mac}", blockedMac.MacAddress);
                TempData["Error"] = $"Error unblocking MAC: {ex.Message}";
            }

            return RedirectToAction(nameof(BlockedMacs));
        }

        // Blocked MACs management page
        public async Task<IActionResult> BlockedMacs()
        {
            var blockedMacs = await _dbContext.BlockedMacs
                .OrderByDescending(b => b.BlockedAt)
                .ToListAsync();

            return View(blockedMacs);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin,Manager")]
        public async Task<IActionResult> AddBlockedMac(string macAddress, string? reason)
        {
            if (string.IsNullOrWhiteSpace(macAddress))
            {
                TempData["Error"] = "MAC address is required.";
                return RedirectToAction(nameof(BlockedMacs));
            }

            // Normalize MAC address
            macAddress = macAddress.ToUpper().Replace("-", ":").Trim();

            // Check if already blocked
            var existing = await _dbContext.BlockedMacs
                .FirstOrDefaultAsync(b => b.MacAddress == macAddress && b.IsActive);

            if (existing != null)
            {
                TempData["Error"] = $"MAC {macAddress} is already blocked.";
                return RedirectToAction(nameof(BlockedMacs));
            }

            try
            {
                // Disconnect if currently connected
                await DisconnectMacFromNetwork(macAddress, null);

                // Add to database
                var blockedMac = new BlockedMac
                {
                    MacAddress = macAddress,
                    Reason = reason ?? "Manually blocked",
                    BlockedBy = User.Identity?.Name ?? "System",
                    BlockedAt = DateTime.UtcNow,
                    IsActive = true
                };
                _dbContext.BlockedMacs.Add(blockedMac);

                // Add to FreeRADIUS
                await AddToFreeRadiusBlockList(macAddress);

                await _dbContext.SaveChangesAsync();

                TempData["Success"] = $"MAC {macAddress} blocked successfully.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding blocked MAC {Mac}", macAddress);
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(BlockedMacs));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> DeleteBlockedMac(int id)
        {
            var blockedMac = await _dbContext.BlockedMacs.FindAsync(id);
            if (blockedMac == null) return NotFound();

            try
            {
                // Remove from FreeRADIUS
                await RemoveFromFreeRadiusBlockList(blockedMac.MacAddress);

                // Delete from database
                _dbContext.BlockedMacs.Remove(blockedMac);
                await _dbContext.SaveChangesAsync();

                TempData["Success"] = $"Blocked MAC {blockedMac.MacAddress} deleted.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting blocked MAC {Mac}", blockedMac.MacAddress);
                TempData["Error"] = $"Error: {ex.Message}";
            }

            return RedirectToAction(nameof(BlockedMacs));
        }

        // Helper: Disconnect MAC from network via CoA
        private async Task DisconnectMacFromNetwork(string macAddress, string? radiusSessionId)
        {
            _logger.LogInformation("Disconnecting MAC {Mac} from network via CoA", macAddress);

            // Find the username associated with this MAC address from active session
            var session = await _dbContext.WifiSessions
                .FirstOrDefaultAsync(s => s.MacAddress == macAddress && s.Status == "Active");

            if (session != null && !string.IsNullOrEmpty(session.RoomNumber))
            {
                // Use FreeRadiusService to send CoA disconnect via FreeRADIUS to MikroTik
                var success = await _freeRadiusService.DisconnectUserByUsernameAsync(session.RoomNumber);
                if (success)
                {
                    _logger.LogInformation("CoA disconnect sent successfully for MAC {Mac}, Room {Room}",
                        macAddress, session.RoomNumber);
                }
                else
                {
                    _logger.LogWarning("CoA disconnect failed for MAC {Mac}, trying alternative methods", macAddress);
                }
            }

            // Also try MikroTik REST API as fallback
            var controller = _wifiService.GetController("Mikrotik");
            if (controller != null)
            {
                try
                {
                    await controller.DisconnectUserAsync(macAddress);
                    _logger.LogInformation("MikroTik API disconnect sent for MAC {Mac}", macAddress);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "MikroTik API disconnect failed for MAC {Mac}", macAddress);
                }
            }
        }

        // Helper: Add MAC to FreeRADIUS block list
        private async Task AddToFreeRadiusBlockList(string macAddress)
        {
            var settings = await _dbContext.SystemSettings.ToListAsync();
            var enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
            var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
            var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

            if (enabled?.ToLower() != "true" || string.IsNullOrEmpty(connStr))
            {
                _logger.LogDebug("FreeRADIUS not enabled, skipping block list update");
                return;
            }

            // Format MAC for FreeRADIUS (uppercase with colons or dashes based on your setup)
            var formattedMac = macAddress.ToUpper();

            using var connection = new MySqlConnection(connStr);
            await connection.OpenAsync();

            // Delete any existing entries for this MAC
            var deleteSql = $"DELETE FROM {prefix}check WHERE username = @mac AND attribute = 'Auth-Type'";
            using var deleteCmd = new MySqlCommand(deleteSql, connection);
            deleteCmd.Parameters.AddWithValue("@mac", formattedMac);
            await deleteCmd.ExecuteNonQueryAsync();

            // Insert Auth-Type := Reject to block this MAC
            var insertSql = $@"INSERT INTO {prefix}check (username, attribute, op, value) 
                               VALUES (@mac, 'Auth-Type', ':=', 'Reject')";
            using var insertCmd = new MySqlCommand(insertSql, connection);
            insertCmd.Parameters.AddWithValue("@mac", formattedMac);
            await insertCmd.ExecuteNonQueryAsync();

            _logger.LogInformation("Added MAC {Mac} to FreeRADIUS block list", formattedMac);
        }

        // Helper: Remove MAC from FreeRADIUS block list
        private async Task RemoveFromFreeRadiusBlockList(string macAddress)
        {
            var settings = await _dbContext.SystemSettings.ToListAsync();
            var enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
            var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
            var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

            if (enabled?.ToLower() != "true" || string.IsNullOrEmpty(connStr))
            {
                return;
            }

            var formattedMac = macAddress.ToUpper();

            using var connection = new MySqlConnection(connStr);
            await connection.OpenAsync();

            // Delete the Auth-Type := Reject entry
            var sql = $"DELETE FROM {prefix}check WHERE username = @mac AND attribute = 'Auth-Type' AND value = 'Reject'";
            using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@mac", formattedMac);
            await cmd.ExecuteNonQueryAsync();

            _logger.LogInformation("Removed MAC {Mac} from FreeRADIUS block list", formattedMac);
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
        public async Task<IActionResult> SyncAllSessions()
        {
            try
            {
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (enabled?.ToLower() != "true" || string.IsNullOrEmpty(connStr))
                {
                    TempData["Error"] = "FreeRADIUS is not enabled or configured.";
                    return RedirectToAction(nameof(Index));
                }

                using var connection = new MySqlConnection(connStr);
                await connection.OpenAsync();

                // Get ALL sessions from radacct (not just active ones)
                // Note: Not using gigawords columns as they may not exist in older schemas
                var sql = $@"
                    SELECT 
                        username,
                        callingstationid,
                        acctsessionid,
                        acctstarttime,
                        acctstoptime,
                        framedipaddress,
                        COALESCE(acctinputoctets, 0) as bytes_in,
                        COALESCE(acctoutputoctets, 0) as bytes_out
                    FROM {prefix}acct 
                    ORDER BY acctstarttime DESC
                    LIMIT 1000";

                using var cmd = connection.CreateCommand();
                cmd.CommandText = sql;

                int created = 0, updated = 0, markedOffline = 0;

                using var reader = await cmd.ExecuteReaderAsync();
                var radSessions = new List<(string username, string mac, string sessionId, DateTime start, DateTime? stop, string ip, long bytesIn, long bytesOut)>();

                while (await reader.ReadAsync())
                {
                    var username = reader.GetString(0);
                    var mac = reader.IsDBNull(1) ? "" : reader.GetString(1);
                    var sessionId = reader.IsDBNull(2) ? "" : reader.GetString(2);
                    var start = reader.IsDBNull(3) ? DateTime.UtcNow : reader.GetDateTime(3);
                    var stop = reader.IsDBNull(4) ? (DateTime?)null : reader.GetDateTime(4);
                    var ip = reader.IsDBNull(5) ? "" : reader.GetString(5);
                    var bytesIn = reader.GetInt64(6);
                    var bytesOut = reader.GetInt64(7);

                    radSessions.Add((username, mac, sessionId, start, stop, ip, bytesIn, bytesOut));
                }
                await reader.CloseAsync();

                // Get ALL guests (not just checked-in) to handle historical sessions
                var guests = await _dbContext.Guests.ToDictionaryAsync(g => g.RoomNumber);

                // Get all existing sessions by RadiusSessionId for quick lookup
                var existingSessionIds = await _dbContext.WifiSessions
                    .Where(s => !string.IsNullOrEmpty(s.RadiusSessionId))
                    .Select(s => s.RadiusSessionId)
                    .ToListAsync();
                var existingSet = new HashSet<string>(existingSessionIds!);

                foreach (var (username, mac, sessionId, start, stop, ip, bytesIn, bytesOut) in radSessions)
                {
                    if (string.IsNullOrEmpty(sessionId)) continue;

                    if (existingSet.Contains(sessionId))
                    {
                        // Update existing session
                        var existing = await _dbContext.WifiSessions.FirstOrDefaultAsync(s => s.RadiusSessionId == sessionId);
                        if (existing != null)
                        {
                            existing.BytesDownloaded = bytesIn;
                            existing.BytesUploaded = bytesOut;
                            existing.BytesUsed = bytesIn + bytesOut;
                            existing.LastActivity = DateTime.UtcNow;

                            // Mark as disconnected if stopped in FreeRADIUS
                            if (stop.HasValue && existing.Status == "Active")
                            {
                                existing.Status = "Disconnected";
                                existing.SessionEnd = stop;
                                markedOffline++;
                            }
                            updated++;
                        }
                    }
                    else if (guests.TryGetValue(username, out var guest))
                    {
                        // Create new session
                        var normalizedMac = mac.ToUpper().Replace("-", ":");
                        var newSession = new WifiSession
                        {
                            GuestId = guest.Id,
                            RoomNumber = username,
                            GuestName = guest.GuestName,
                            MacAddress = normalizedMac,
                            IpAddress = ip,
                            RadiusSessionId = sessionId,
                            SessionStart = start,
                            SessionEnd = stop,
                            Status = stop.HasValue ? "Disconnected" : "Active",
                            ControllerType = "FreeRADIUS",
                            AuthMethod = "RADIUS",
                            LastActivity = stop ?? DateTime.UtcNow,
                            BytesDownloaded = bytesIn,
                            BytesUploaded = bytesOut,
                            BytesUsed = bytesIn + bytesOut
                        };
                        _dbContext.WifiSessions.Add(newSession);
                        existingSet.Add(sessionId); // Prevent duplicates in same batch
                        created++;
                    }
                }

                await _dbContext.SaveChangesAsync();
                TempData["Success"] = $"Synced from FreeRADIUS: {created} created, {updated} updated, {markedOffline} marked offline.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing all sessions");
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
                int merged = 0;
                int deleted = 0;

                // STEP 1: Find sessions without RadiusSessionId that have a matching session WITH RadiusSessionId
                // These are portal-created duplicates that should be merged/deleted
                var sessionsWithoutRadiusId = await _dbContext.WifiSessions
                    .Where(s => string.IsNullOrEmpty(s.RadiusSessionId) &&
                                (string.IsNullOrEmpty(s.IpAddress) || s.IpAddress == "-"))
                    .ToListAsync();

                foreach (var orphan in sessionsWithoutRadiusId)
                {
                    // Find matching session with RadiusSessionId (same MAC, Room, similar time)
                    var matchingSession = await _dbContext.WifiSessions
                        .FirstOrDefaultAsync(s => s.MacAddress == orphan.MacAddress &&
                                                   s.RoomNumber == orphan.RoomNumber &&
                                                   !string.IsNullOrEmpty(s.RadiusSessionId) &&
                                                   s.Id != orphan.Id);

                    if (matchingSession != null)
                    {
                        // The matching session has the real data from FreeRADIUS, mark orphan as merged
                        orphan.Status = "Merged";
                        orphan.SessionEnd = DateTime.UtcNow;
                        merged++;
                    }
                }

                // STEP 2: Find duplicate active sessions for same MAC+Room (keep the one with RadiusSessionId)
                var allSessions = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active" || s.Status == "QuotaExceeded")
                    .ToListAsync();

                var groupedByMacRoom = allSessions
                    .GroupBy(s => new { s.MacAddress, s.RoomNumber })
                    .Where(g => g.Count() > 1);

                foreach (var group in groupedByMacRoom)
                {
                    var sessions = group.OrderByDescending(s => !string.IsNullOrEmpty(s.RadiusSessionId))
                                        .ThenByDescending(s => s.SessionStart)
                                        .ToList();

                    var keepSession = sessions.First(); // Keep the one with RadiusSessionId (or most recent)

                    foreach (var dup in sessions.Skip(1))
                    {
                        // If duplicate has no RadiusSessionId, just mark as merged
                        // If it has one, mark as merged but don't combine bytes (they're separate radacct records)
                        dup.Status = "Merged";
                        dup.SessionEnd = DateTime.UtcNow;
                        deleted++;
                    }
                }

                await _dbContext.SaveChangesAsync();

                var msg = new List<string>();
                if (merged > 0) msg.Add($"{merged} orphan sessions merged");
                if (deleted > 0) msg.Add($"{deleted} duplicate sessions cleaned");

                TempData["Success"] = msg.Any() ? string.Join(", ", msg) : "No duplicate sessions found.";
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

        // Quota status and paid packages
        public long FreeQuotaBytes { get; set; }
        public long PaidQuotaBytes { get; set; }
        public bool IsQuotaExceeded { get; set; }
        public bool HasPurchasedPackage { get; set; }
        public string? GuestStatus { get; set; }
        public int QuotaExceededSessions { get; set; }

        // Active paid packages for this guest
        public List<ActivePaidPackageInfo> ActivePaidPackages { get; set; } = new();

        // Computed properties
        public double FreeQuotaGB => FreeQuotaBytes / 1073741824.0;
        public double PaidQuotaGB => PaidQuotaBytes / 1073741824.0;
        public double TotalQuotaGB => TotalQuotaBytes / 1073741824.0;
        public double UsedQuotaGB => UsedQuotaBytes / 1073741824.0;
        public double RemainingQuotaGB => Math.Max(0, TotalQuotaGB - UsedQuotaGB);
    }

    public class ActivePaidPackageInfo
    {
        public int Id { get; set; }
        public string PackageName { get; set; } = "";
        public string PackageType { get; set; } = "DataBased";
        public double QuotaGB { get; set; }
        public double UsedGB { get; set; }
        public double RemainingGB => Math.Max(0, QuotaGB - UsedGB);
        public int QuotaPercent => QuotaGB > 0 ? (int)((UsedGB / QuotaGB) * 100) : 0;
        public int? DownloadSpeedKbps { get; set; }
        public int? UploadSpeedKbps { get; set; }
        public DateTime ActivatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public string Status { get; set; } = "Active";

        public bool IsExpired => ExpiresAt.HasValue && DateTime.UtcNow > ExpiresAt.Value;
        public bool IsActive => Status == "Active" && !IsExpired;

        public string RemainingTimeDisplay
        {
            get
            {
                if (PackageType == "RestOfStay") return "Rest of Stay";
                if (PackageType == "DataBased") return "Data-based";
                if (!ExpiresAt.HasValue) return "N/A";
                if (IsExpired) return "Expired";

                var remaining = ExpiresAt.Value - DateTime.UtcNow;
                if (remaining.TotalDays >= 1)
                    return $"{(int)remaining.TotalDays}d {remaining.Hours}h";
                if (remaining.TotalHours >= 1)
                    return $"{(int)remaining.TotalHours}h {remaining.Minutes}m";
                return $"{remaining.Minutes}m";
            }
        }
    }
}