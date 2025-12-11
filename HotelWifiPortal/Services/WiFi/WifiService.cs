using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Services.Radius;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Services.WiFi
{
    public class WifiControllerFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILoggerFactory _loggerFactory;
        private readonly IHttpClientFactory _httpClientFactory;

        public WifiControllerFactory(IServiceProvider serviceProvider, ILoggerFactory loggerFactory, IHttpClientFactory httpClientFactory)
        {
            _serviceProvider = serviceProvider;
            _loggerFactory = loggerFactory;
            _httpClientFactory = httpClientFactory;
        }

        public IWifiController? CreateController(WifiControllerSettings settings)
        {
            return settings.ControllerType switch
            {
                "Ruckus" => new RuckusController(settings, _loggerFactory.CreateLogger<RuckusController>(), _httpClientFactory),
                "RuckusZD" => new RuckusZoneDirectorController(settings, _loggerFactory.CreateLogger<RuckusZoneDirectorController>(), _httpClientFactory),
                "Mikrotik" => new MikrotikController(settings, _loggerFactory.CreateLogger<MikrotikController>(), _httpClientFactory, _serviceProvider),
                "ExtremeCloud" => new ExtremeCloudController(settings, _loggerFactory.CreateLogger<ExtremeCloudController>(), _httpClientFactory),
                _ => null
            };
        }
    }

    public class WifiService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly WifiControllerFactory _controllerFactory;
        private readonly ILogger<WifiService> _logger;
        private readonly IServiceProvider _serviceProvider;
        private readonly Dictionary<string, IWifiController> _controllers = new();

        public WifiService(ApplicationDbContext dbContext, WifiControllerFactory controllerFactory, 
            ILogger<WifiService> logger, IServiceProvider serviceProvider)
        {
            _dbContext = dbContext;
            _controllerFactory = controllerFactory;
            _logger = logger;
            _serviceProvider = serviceProvider;
        }

        public async Task InitializeControllersAsync()
        {
            var settings = await _dbContext.WifiControllerSettings
                .Where(s => s.IsEnabled)
                .ToListAsync();

            foreach (var setting in settings)
            {
                var controller = _controllerFactory.CreateController(setting);
                if (controller != null)
                {
                    _controllers[setting.ControllerType] = controller;
                    _logger.LogInformation("Initialized WiFi controller: {Type}", setting.ControllerType);
                }
            }
        }

        public IWifiController? GetController(string? controllerType = null)
        {
            if (string.IsNullOrEmpty(controllerType))
            {
                // Return default or first available
                return _controllers.Values.FirstOrDefault();
            }

            _controllers.TryGetValue(controllerType, out var controller);
            return controller;
        }

        public async Task<IWifiController?> GetDefaultControllerAsync()
        {
            var defaultSettings = await _dbContext.WifiControllerSettings
                .FirstOrDefaultAsync(s => s.IsEnabled && s.IsDefault);

            if (defaultSettings == null)
            {
                defaultSettings = await _dbContext.WifiControllerSettings
                    .FirstOrDefaultAsync(s => s.IsEnabled);
            }

            if (defaultSettings == null) return null;

            return GetController(defaultSettings.ControllerType);
        }

        public async Task<bool> AuthenticateGuestAsync(Guest guest, string macAddress)
        {
            var controller = await GetDefaultControllerAsync();
            if (controller == null)
            {
                _logger.LogWarning("No WiFi controller available for authentication");
                return false;
            }

            var username = $"Room{guest.RoomNumber}";
            var success = await controller.AuthenticateUserAsync(macAddress, username);

            if (success)
            {
                // Apply bandwidth profile if applicable
                var profile = await GetBandwidthProfileForGuestAsync(guest);
                if (profile != null)
                {
                    await controller.SetBandwidthLimitAsync(macAddress, profile.DownloadSpeedKbps, profile.UploadSpeedKbps);
                }

                // Create WiFi session
                var session = new WifiSession
                {
                    GuestId = guest.Id,
                    RoomNumber = guest.RoomNumber,
                    GuestName = guest.GuestName,
                    MacAddress = macAddress,
                    Status = "Active",
                    ControllerType = controller.ControllerType,
                    BandwidthProfileId = profile?.Id,
                    SessionStart = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow
                };

                _dbContext.WifiSessions.Add(session);
                
                guest.LastWifiLogin = DateTime.UtcNow;
                
                await _dbContext.SaveChangesAsync();
            }

            return success;
        }

        public async Task<bool> DisconnectSessionAsync(int sessionId)
        {
            var session = await _dbContext.WifiSessions.FindAsync(sessionId);
            if (session == null) return false;

            var controller = GetController(session.ControllerType);
            if (controller != null)
            {
                await controller.DisconnectUserAsync(session.MacAddress);
            }

            session.Status = "Disconnected";
            session.SessionEnd = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            return true;
        }

        public async Task<List<WifiSession>> GetActiveSessionsAsync()
        {
            return await _dbContext.WifiSessions
                .Include(s => s.Guest)
                .Include(s => s.BandwidthProfile)
                .Where(s => s.Status == "Active" || s.Status == "QuotaExceeded")
                .OrderByDescending(s => s.SessionStart)
                .ToListAsync();
        }

        public async Task<List<WifiSession>> GetGuestSessionsAsync(int guestId)
        {
            return await _dbContext.WifiSessions
                .Where(s => s.GuestId == guestId)
                .OrderByDescending(s => s.SessionStart)
                .ToListAsync();
        }

        public async Task UpdateSessionUsageAsync()
        {
            var activeSessions = await GetActiveSessionsAsync();
            
            // First, try to sync from FreeRADIUS if enabled
            bool freeRadiusSynced = await SyncFromFreeRadiusAsync(activeSessions);
            
            // If FreeRADIUS sync worked, we're done
            if (freeRadiusSynced)
            {
                await _dbContext.SaveChangesAsync();
                return;
            }
            
            // Otherwise, try to get usage from WiFi controller directly
            var controller = await GetDefaultControllerAsync();
            if (controller == null) return;

            foreach (var session in activeSessions)
            {
                try
                {
                    var usage = await controller.GetClientUsageAsync(session.MacAddress);
                    if (usage != null)
                    {
                        var newBytes = usage.TotalBytesUsed - session.BytesUsed;
                        if (newBytes > 0)
                        {
                            session.BytesUsed = usage.TotalBytesUsed;
                            session.BytesDownloaded = usage.BytesDownloaded;
                            session.BytesUploaded = usage.BytesUploaded;
                            session.LastActivity = DateTime.UtcNow;

                            // NOTE: Do NOT update guest.UsedQuotaBytes here!
                            // This is per-MAC usage from the controller.
                            // Guest quota should be updated from FreeRADIUS radacct aggregated by room number.
                        }
                    }
                    else
                    {
                        // Client might have disconnected
                        session.Status = "Disconnected";
                        session.SessionEnd = DateTime.UtcNow;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error updating session usage for {Mac}", session.MacAddress);
                }
            }

            await _dbContext.SaveChangesAsync();
        }

        /// <summary>
        /// Sync usage data from FreeRADIUS radacct table
        /// </summary>
        private async Task<bool> SyncFromFreeRadiusAsync(List<WifiSession> activeSessions)
        {
            try
            {
                // Check if FreeRADIUS is enabled
                var freeRadiusEnabled = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusEnabled")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync();
                
                if (freeRadiusEnabled?.ToLower() != "true")
                {
                    _logger.LogDebug("FreeRADIUS not enabled, skipping sync");
                    return false;
                }

                var connectionString = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusConnectionString")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync();

                if (string.IsNullOrEmpty(connectionString))
                {
                    _logger.LogWarning("FreeRADIUS connection string is empty");
                    return false;
                }

                var tablePrefix = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusTablePrefix")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "rad";

                _logger.LogInformation("=== Starting FreeRADIUS Usage Sync ===");
                _logger.LogInformation("Active sessions to sync: {Count}", activeSessions.Count);

                using var connection = new MySqlConnector.MySqlConnection(connectionString);
                await connection.OpenAsync();

                // APPROACH 1: Sync active sessions by room number or MAC
                foreach (var session in activeSessions)
                {
                    try
                    {
                        // Normalize MAC address to different formats for matching
                        var macClean = session.MacAddress?.ToLower().Replace(":", "").Replace("-", "") ?? "";
                        var macWithColons = session.MacAddress?.ToUpper() ?? "";
                        var macWithDashes = session.MacAddress?.ToUpper().Replace(":", "-") ?? "";
                        
                        _logger.LogDebug("Syncing session: Room={Room}, MAC={Mac}, SessionId={SessionId}", 
                            session.RoomNumber, session.MacAddress, session.RadiusSessionId);

                        long inputBytes = 0, outputBytes = 0;
                        DateTime? lastStop = null;

                        // If we have a RadiusSessionId, query that specific session only
                        if (!string.IsNullOrEmpty(session.RadiusSessionId))
                        {
                            var sql = $@"
                                SELECT 
                                    COALESCE(acctinputoctets, 0) as total_input,
                                    COALESCE(acctoutputoctets, 0) as total_output,
                                    acctstoptime
                                FROM {tablePrefix}acct 
                                WHERE acctsessionid = @sessionId
                                LIMIT 1";

                            using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                            cmd.Parameters.AddWithValue("@sessionId", session.RadiusSessionId);

                            using var reader = await cmd.ExecuteReaderAsync();
                            if (await reader.ReadAsync())
                            {
                                inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                                outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                                lastStop = reader.IsDBNull(2) ? null : reader.GetDateTime(2);
                            }
                        }
                        else
                        {
                            // Fallback: Query by room number + MAC for sessions without RadiusSessionId
                            var sql = $@"
                                SELECT 
                                    COALESCE(SUM(acctinputoctets), 0) as total_input,
                                    COALESCE(SUM(acctoutputoctets), 0) as total_output,
                                    MAX(acctstoptime) as last_stop
                                FROM {tablePrefix}acct 
                                WHERE username = @username 
                                   AND (callingstationid = @macWithColons 
                                        OR callingstationid = @macWithDashes
                                        OR LOWER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')) = @macClean)";

                            using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                            cmd.Parameters.AddWithValue("@username", session.RoomNumber);
                            cmd.Parameters.AddWithValue("@macClean", macClean);
                            cmd.Parameters.AddWithValue("@macWithColons", macWithColons);
                            cmd.Parameters.AddWithValue("@macWithDashes", macWithDashes);

                            using var reader = await cmd.ExecuteReaderAsync();
                            if (await reader.ReadAsync())
                            {
                                inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                                outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                                lastStop = reader.IsDBNull(2) ? null : reader.GetDateTime(2);
                            }
                        }

                        var totalBytes = inputBytes + outputBytes;

                        if (totalBytes > 0)
                        {
                            // Update session
                            session.BytesDownloaded = inputBytes;
                            session.BytesUploaded = outputBytes;
                            session.BytesUsed = totalBytes;
                            session.LastActivity = DateTime.UtcNow;
                            
                            // If session has ended in FreeRADIUS, mark it as Disconnected
                            if (lastStop.HasValue && session.Status == "Active")
                            {
                                session.Status = "Disconnected";
                                session.SessionEnd = lastStop;
                            }
                            
                            _dbContext.Entry(session).State = Microsoft.EntityFrameworkCore.EntityState.Modified;

                            _logger.LogDebug("Updated session {Id} for Room={Room} MAC={Mac}: BytesUsed={Total}MB", 
                                session.Id, session.RoomNumber, session.MacAddress, totalBytes / 1048576.0);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error syncing usage for session {Room}", session.RoomNumber);
                    }
                }

                // APPROACH 2: Also sync directly to all checked-in guests by room number
                // This handles cases where the session might not exist but usage does
                _logger.LogInformation("=== Syncing usage directly to guests ===");
                
                var checkedInGuests = await _dbContext.Guests
                    .Where(g => g.Status.ToLower() == "checked-in" || 
                               g.Status.ToLower() == "checkedin" ||
                               g.Status == "CheckedIn")
                    .ToListAsync();
                
                _logger.LogInformation("Found {Count} checked-in guests to sync", checkedInGuests.Count);

                foreach (var guest in checkedInGuests)
                {
                    try
                    {
                        // Count ALL sessions for this username (entire stay usage)
                        // This ensures quota is cumulative and doesn't reset when session ends
                        var sql = $@"
                            SELECT 
                                COALESCE(SUM(acctinputoctets), 0) as total_input,
                                COALESCE(SUM(acctoutputoctets), 0) as total_output
                            FROM {tablePrefix}acct 
                            WHERE username = @username";

                        using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                        cmd.Parameters.AddWithValue("@username", guest.RoomNumber);

                        using var reader = await cmd.ExecuteReaderAsync();
                        if (await reader.ReadAsync())
                        {
                            var inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                            var outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                            var totalBytes = inputBytes + outputBytes;

                            if (totalBytes > 0)
                            {
                                _logger.LogInformation("Guest Room={Room}: Found {Total}MB usage in radacct, current UsedQuotaBytes={Current}",
                                    guest.RoomNumber, totalBytes / 1048576.0, guest.UsedQuotaBytes / 1048576.0);

                                if (totalBytes > guest.UsedQuotaBytes)
                                {
                                    guest.UsedQuotaBytes = totalBytes;
                                    _dbContext.Entry(guest).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
                                    _logger.LogInformation("Updated guest {Room} UsedQuotaBytes to {Total}MB", 
                                        guest.RoomNumber, totalBytes / 1048576.0);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error syncing usage for guest {Room}", guest.RoomNumber);
                    }
                }

                // Save all changes
                var changes = await _dbContext.SaveChangesAsync();
                _logger.LogInformation("=== Sync Complete: Saved {Changes} changes to database ===", changes);

                // APPROACH 3: Create sessions for active FreeRADIUS sessions that don't exist in portal
                await CreateMissingSessionsFromFreeRadiusAsync(connection, tablePrefix);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing from FreeRADIUS");
                return false;
            }
        }

        /// <summary>
        /// Create WifiSession records for active FreeRADIUS sessions that don't exist in portal
        /// </summary>
        private async Task CreateMissingSessionsFromFreeRadiusAsync(MySqlConnector.MySqlConnection connection, string tablePrefix)
        {
            try
            {
                _logger.LogInformation("=== Checking for missing sessions in FreeRADIUS ===");

                // Find active sessions in radacct (acctstoptime IS NULL means active)
                var sql = $@"
                    SELECT DISTINCT
                        username,
                        callingstationid,
                        acctsessionid,
                        acctstarttime,
                        framedipaddress,
                        COALESCE(acctinputoctets, 0) as acctinputoctets,
                        COALESCE(acctoutputoctets, 0) as acctoutputoctets
                    FROM {tablePrefix}acct 
                    WHERE acctstoptime IS NULL
                    ORDER BY acctstarttime DESC";

                using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                using var reader = await cmd.ExecuteReaderAsync();
                
                var newSessions = new List<(string username, string mac, string sessionId, DateTime start, string ip, long bytesIn, long bytesOut)>();
                while (await reader.ReadAsync())
                {
                    var username = reader.GetString(0);
                    var mac = reader.IsDBNull(1) ? "" : reader.GetString(1);
                    var sessionId = reader.IsDBNull(2) ? "" : reader.GetString(2);
                    var start = reader.IsDBNull(3) ? DateTime.UtcNow : reader.GetDateTime(3);
                    var ip = reader.IsDBNull(4) ? "" : reader.GetString(4);
                    var bytesIn = reader.GetInt64(5);
                    var bytesOut = reader.GetInt64(6);
                    
                    newSessions.Add((username, mac, sessionId, start, ip, bytesIn, bytesOut));
                }
                await reader.CloseAsync();

                _logger.LogInformation("Found {Count} active sessions in FreeRADIUS", newSessions.Count);

                foreach (var (username, mac, sessionId, start, ip, bytesIn, bytesOut) in newSessions)
                {
                    try
                    {
                        // Normalize MAC
                        var normalizedMac = mac.ToUpper().Replace("-", ":");
                        
                        // Check if this specific session already exists in portal (by RadiusSessionId)
                        WifiSession? existingSession = null;
                        
                        if (!string.IsNullOrEmpty(sessionId))
                        {
                            existingSession = await _dbContext.WifiSessions
                                .FirstOrDefaultAsync(s => s.RadiusSessionId == sessionId);
                        }
                        
                        // Fallback: check by MAC + Room + Active/QuotaExceeded status (only if no sessionId match)
                        if (existingSession == null)
                        {
                            existingSession = await _dbContext.WifiSessions
                                .FirstOrDefaultAsync(s => 
                                    (s.MacAddress == normalizedMac || s.MacAddress == mac) && 
                                    s.RoomNumber == username &&
                                    (s.Status == "Active" || s.Status == "QuotaExceeded") &&
                                    string.IsNullOrEmpty(s.RadiusSessionId));
                        }

                        if (existingSession != null)
                        {
                            // Update existing session
                            existingSession.BytesDownloaded = bytesIn;
                            existingSession.BytesUploaded = bytesOut;
                            existingSession.BytesUsed = bytesIn + bytesOut;
                            existingSession.LastActivity = DateTime.UtcNow;
                            existingSession.IpAddress = ip;
                            if (!string.IsNullOrEmpty(sessionId) && string.IsNullOrEmpty(existingSession.RadiusSessionId))
                                existingSession.RadiusSessionId = sessionId;
                            continue;
                        }

                        // Find guest by username (room number)
                        var guest = await _dbContext.Guests
                            .FirstOrDefaultAsync(g => g.RoomNumber == username && 
                                (g.Status == "checked-in" || g.Status == "Checked-In" || g.Status == "CheckedIn"));

                        if (guest == null)
                        {
                            _logger.LogDebug("No checked-in guest found for username {Username}", username);
                            continue;
                        }

                        // Create new session - each radacct record = one session
                        var newSession = new WifiSession
                        {
                            GuestId = guest.Id,
                            RoomNumber = guest.RoomNumber,
                            GuestName = guest.GuestName,
                            MacAddress = normalizedMac,
                            IpAddress = ip,
                            RadiusSessionId = sessionId,
                            SessionStart = start,
                            Status = "Active",
                            ControllerType = "FreeRADIUS",
                            AuthMethod = "RADIUS",
                            LastActivity = DateTime.UtcNow,
                            BytesDownloaded = bytesIn,
                            BytesUploaded = bytesOut,
                            BytesUsed = bytesIn + bytesOut
                        };

                        _dbContext.WifiSessions.Add(newSession);
                        _logger.LogInformation("Created new session from FreeRADIUS: Room={Room}, MAC={Mac}, SessionId={SessionId}", 
                            guest.RoomNumber, normalizedMac, sessionId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error creating session for {Username}", username);
                    }
                }

                await _dbContext.SaveChangesAsync();
                
                // Also mark sessions as disconnected if they're no longer active in FreeRADIUS
                await MarkDisconnectedSessionsAsync(connection, tablePrefix);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating missing sessions from FreeRADIUS");
            }
        }

        /// <summary>
        /// Mark sessions as disconnected if they have ended in FreeRADIUS (acctstoptime is set)
        /// </summary>
        private async Task MarkDisconnectedSessionsAsync(MySqlConnector.MySqlConnection connection, string tablePrefix)
        {
            try
            {
                // Get all our "Active" sessions that have a RadiusSessionId
                var activeSessions = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active" && !string.IsNullOrEmpty(s.RadiusSessionId))
                    .ToListAsync();

                if (!activeSessions.Any())
                {
                    return;
                }

                // Build a query to check which sessions have ended in FreeRADIUS
                var sessionIds = activeSessions.Select(s => s.RadiusSessionId).ToList();
                var placeholders = string.Join(",", sessionIds.Select((_, i) => $"@sid{i}"));
                
                var sql = $@"
                    SELECT acctsessionid, acctstoptime, 
                           COALESCE(acctinputoctets, 0) as bytes_in,
                           COALESCE(acctoutputoctets, 0) as bytes_out
                    FROM {tablePrefix}acct 
                    WHERE acctsessionid IN ({placeholders})
                      AND acctstoptime IS NOT NULL";

                using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                for (int i = 0; i < sessionIds.Count; i++)
                {
                    cmd.Parameters.AddWithValue($"@sid{i}", sessionIds[i]);
                }

                var endedSessions = new Dictionary<string, (DateTime stopTime, long bytesIn, long bytesOut)>();
                
                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var sid = reader.GetString(0);
                    var stopTime = reader.GetDateTime(1);
                    var bytesIn = reader.GetInt64(2);
                    var bytesOut = reader.GetInt64(3);
                    endedSessions[sid] = (stopTime, bytesIn, bytesOut);
                }
                await reader.CloseAsync();

                // Mark sessions as disconnected
                int markedCount = 0;
                foreach (var session in activeSessions)
                {
                    if (session.RadiusSessionId != null && endedSessions.TryGetValue(session.RadiusSessionId, out var ended))
                    {
                        session.Status = "Disconnected";
                        session.SessionEnd = ended.stopTime;
                        session.BytesDownloaded = ended.bytesIn;
                        session.BytesUploaded = ended.bytesOut;
                        session.BytesUsed = ended.bytesIn + ended.bytesOut;
                        session.LastActivity = ended.stopTime;
                        markedCount++;
                    }
                }

                if (markedCount > 0)
                {
                    await _dbContext.SaveChangesAsync();
                    _logger.LogInformation("Marked {Count} sessions as disconnected based on FreeRADIUS data", markedCount);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error marking disconnected sessions");
            }
        }

        public async Task<BandwidthProfile?> GetBandwidthProfileForGuestAsync(Guest guest)
        {
            // Check for VIP profile
            if (!string.IsNullOrEmpty(guest.VipStatus))
            {
                var vipProfile = await _dbContext.BandwidthProfiles
                    .FirstOrDefaultAsync(p => p.IsActive && p.Name.Contains("VIP"));
                if (vipProfile != null) return vipProfile;
            }

            // Check for room-specific profile
            var roomProfile = await _dbContext.BandwidthProfiles
                .Where(p => p.IsActive && !string.IsNullOrEmpty(p.ApplyToRooms))
                .ToListAsync();

            foreach (var profile in roomProfile)
            {
                var rooms = profile.ApplyToRooms!.Split(',').Select(r => r.Trim());
                if (rooms.Contains(guest.RoomNumber))
                    return profile;
            }

            // Return default profile
            return await _dbContext.BandwidthProfiles
                .FirstOrDefaultAsync(p => p.IsActive && p.IsDefault);
        }

        public async Task<bool> TestControllerAsync(string controllerType)
        {
            var controller = GetController(controllerType);
            if (controller == null)
            {
                var settings = await _dbContext.WifiControllerSettings
                    .FirstOrDefaultAsync(s => s.ControllerType == controllerType);
                
                if (settings == null) return false;
                
                controller = _controllerFactory.CreateController(settings);
            }

            if (controller == null) return false;

            return await controller.TestConnectionAsync();
        }

        public async Task CheckQuotaExceededAsync()
        {
            var controller = await GetDefaultControllerAsync();
            
            // Get MikroTik IP for CoA disconnect
            var mikrotikIpSetting = await _dbContext.SystemSettings
                .FirstOrDefaultAsync(s => s.Key == "MikroTikHotspotIp");
            var mikrotikIp = mikrotikIpSetting?.Value ?? "";
            
            // Check if FreeRADIUS is enabled - if so, query radacct directly
            var freeRadiusEnabled = await _dbContext.SystemSettings
                .Where(s => s.Key == "FreeRadiusEnabled")
                .Select(s => s.Value)
                .FirstOrDefaultAsync();
                
            if (freeRadiusEnabled?.ToLower() == "true")
            {
                // Use FreeRADIUS radacct for accurate usage data
                await CheckQuotaFromFreeRadiusAsync(mikrotikIp, controller);
            }
            else
            {
                // Fallback to portal database
                await CheckQuotaFromPortalAsync(mikrotikIp, controller);
            }
        }

        /// <summary>
        /// Check quota by querying FreeRADIUS radacct directly
        /// PROFESSIONAL ARCHITECTURE: Portal only reads/updates status
        /// FreeRADIUS check_quota.sh script handles actual disconnect!
        /// </summary>
        private async Task CheckQuotaFromFreeRadiusAsync(string mikrotikIp, IWifiController? controller)
        {
            try
            {
                var connectionString = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusConnectionString")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync();

                if (string.IsNullOrEmpty(connectionString))
                {
                    _logger.LogWarning("FreeRADIUS connection string empty, falling back to portal check");
                    await CheckQuotaFromPortalAsync(mikrotikIp, controller);
                    return;
                }

                var tablePrefix = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusTablePrefix")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "rad";

                using var connection = new MySqlConnector.MySqlConnection(connectionString);
                await connection.OpenAsync();

                // Get all checked-in guests with quota limits
                var guests = await _dbContext.Guests
                    .Where(g => (g.Status.ToLower() == "checked-in" || 
                                g.Status.ToLower() == "checkedin" ||
                                g.Status == "CheckedIn") &&
                               (g.FreeQuotaBytes + g.PaidQuotaBytes) > 0)
                    .ToListAsync();

                _logger.LogDebug("Checking quota for {Count} guests with quota limits", guests.Count);

                foreach (var guest in guests)
                {
                    try
                    {
                        // Query radacct for TOTAL usage (ALL sessions - active AND closed)
                        // This is critical: quota is cumulative for entire stay, not per-session
                        var usageSql = $@"
                            SELECT 
                                COALESCE(SUM(acctinputoctets), 0) + COALESCE(SUM(acctoutputoctets), 0) as total_bytes
                            FROM {tablePrefix}acct 
                            WHERE username = @username";

                        using var usageCmd = new MySqlConnector.MySqlCommand(usageSql, connection);
                        usageCmd.Parameters.AddWithValue("@username", guest.RoomNumber);
                        var totalBytes = Convert.ToInt64(await usageCmd.ExecuteScalarAsync() ?? 0L);

                        var quotaBytes = guest.FreeQuotaBytes + guest.PaidQuotaBytes;
                        var usedMB = totalBytes / 1048576.0;
                        var quotaMB = quotaBytes / 1048576.0;

                        // Update guest's UsedQuotaBytes
                        if (totalBytes != guest.UsedQuotaBytes)
                        {
                            guest.UsedQuotaBytes = totalBytes;
                            _dbContext.Entry(guest).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
                        }

                        // Check if quota exceeded - UPDATE PORTAL STATUS ONLY
                        // FreeRADIUS check_quota.sh handles actual disconnect!
                        if (totalBytes >= quotaBytes)
                        {
                            _logger.LogWarning("=== ROOM {Room} QUOTA STATUS: {Used:F2}MB / {Quota:F2}MB (EXCEEDED) ===",
                                guest.RoomNumber, usedMB, quotaMB);

                            // Update portal sessions to QuotaExceeded status
                            // This is for display purposes only - FreeRADIUS handles enforcement
                            var activeSessions = await _dbContext.WifiSessions
                                .Where(s => s.RoomNumber == guest.RoomNumber && s.Status == "Active")
                                .ToListAsync();

                            foreach (var session in activeSessions)
                            {
                                session.Status = "QuotaExceeded";
                                session.SessionEnd = DateTime.UtcNow;
                                _logger.LogInformation("Portal: Marked session {Mac} for Room {Room} as QuotaExceeded",
                                    session.MacAddress, guest.RoomNumber);
                            }

                            // NOTE: We do NOT send CoA disconnect from portal!
                            // FreeRADIUS check_quota.sh script running on FreeRADIUS server handles this
                            // because portal cannot reach MikroTik directly (different network segment)
                        }
                        else
                        {
                            _logger.LogDebug("Room {Room}: {Used:F2}MB / {Quota:F2}MB ({Percent:F1}%)",
                                guest.RoomNumber, usedMB, quotaMB, (usedMB / quotaMB) * 100);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error checking quota for Room {Room}", guest.RoomNumber);
                    }
                }

                await _dbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in CheckQuotaFromFreeRadiusAsync");
                // Fallback to portal-based check
                await CheckQuotaFromPortalAsync(mikrotikIp, controller);
            }
        }

        /// <summary>
        /// Fallback: Check quota using portal database only
        /// </summary>
        private async Task CheckQuotaFromPortalAsync(string mikrotikIp, IWifiController? controller)
        {
            // Get guests that MIGHT be over quota based on stored UsedQuotaBytes
            // We'll verify against actual radacct data before marking sessions
            var guestsOverQuota = await _dbContext.Guests
                .Where(g => (g.Status == "checked-in" || g.Status == "Checked-In" || g.Status == "CheckedIn") && 
                            g.UsedQuotaBytes >= (g.FreeQuotaBytes + g.PaidQuotaBytes) &&
                            (g.FreeQuotaBytes + g.PaidQuotaBytes) > 0)
                .ToListAsync();

            // If no guests appear over quota from portal data, nothing to do
            if (!guestsOverQuota.Any())
                return;

            // Verify against actual FreeRADIUS radacct data before taking action
            var connectionString = await _dbContext.SystemSettings
                .Where(s => s.Key == "FreeRadiusConnectionString")
                .Select(s => s.Value)
                .FirstOrDefaultAsync();
            
            if (string.IsNullOrEmpty(connectionString))
            {
                _logger.LogWarning("FreeRADIUS not configured, cannot verify quota from radacct");
                return;
            }

            var tablePrefix = await _dbContext.SystemSettings
                .Where(s => s.Key == "FreeRadiusTablePrefix")
                .Select(s => s.Value)
                .FirstOrDefaultAsync() ?? "rad";

            try
            {
                using var connection = new MySqlConnector.MySqlConnection(connectionString);
                await connection.OpenAsync();

                foreach (var guest in guestsOverQuota)
                {
                    // Query TOTAL usage from radacct (ALL sessions - active AND closed)
                    // Quota is cumulative for entire stay
                    var usageSql = $@"
                        SELECT COALESCE(SUM(acctinputoctets + acctoutputoctets), 0) as total_bytes
                        FROM {tablePrefix}acct 
                        WHERE username = @username";

                    using var usageCmd = new MySqlConnector.MySqlCommand(usageSql, connection);
                    usageCmd.Parameters.AddWithValue("@username", guest.RoomNumber);
                    var actualBytes = Convert.ToInt64(await usageCmd.ExecuteScalarAsync() ?? 0L);

                    var quotaBytes = guest.FreeQuotaBytes + guest.PaidQuotaBytes;
                    
                    // Only mark as exceeded if ACTUAL usage exceeds quota
                    if (actualBytes < quotaBytes)
                    {
                        _logger.LogDebug("Room {Room}: Stored UsedQuotaBytes={Stored}MB but actual active usage={Actual}MB, quota={Quota}MB - NOT exceeded",
                            guest.RoomNumber, guest.UsedQuotaBytes / 1048576.0, actualBytes / 1048576.0, quotaBytes / 1048576.0);
                        
                        // Update UsedQuotaBytes to actual value
                        if (guest.UsedQuotaBytes != actualBytes)
                        {
                            guest.UsedQuotaBytes = actualBytes;
                        }
                        continue;
                    }

                    // Mark ALL sessions for this guest by BOTH GuestId AND RoomNumber
                    var sessions = await _dbContext.WifiSessions
                        .Where(s => (s.GuestId == guest.Id || s.RoomNumber == guest.RoomNumber) && 
                                    s.Status == "Active")
                        .ToListAsync();

                    if (sessions.Any())
                    {
                        _logger.LogWarning("=== ROOM {Room} EXCEEDED QUOTA: {Used}MB / {Total}MB ===",
                            guest.RoomNumber, actualBytes / 1048576.0, quotaBytes / 1048576.0);
                        _logger.LogInformation("Disconnecting {Count} active sessions for Room {Room}", 
                            sessions.Count, guest.RoomNumber);
                    }

                    foreach (var session in sessions)
                    {
                        // Mark session as QuotaExceeded (portal status only)
                        // FreeRADIUS check_quota.sh handles actual disconnect!
                        session.Status = "QuotaExceeded";
                        session.SessionEnd = DateTime.UtcNow;
                        
                        // Ensure GuestId is set correctly
                        if (session.GuestId != guest.Id)
                        {
                            session.GuestId = guest.Id;
                        }
                        
                        _logger.LogInformation("Portal: Marked session {Mac} as QuotaExceeded for Room {Room}", 
                            session.MacAddress, guest.RoomNumber);
                        
                        // NOTE: We do NOT send CoA disconnect from portal!
                        // FreeRADIUS check_quota.sh script handles enforcement
                    }
                }

                await _dbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in CheckQuotaFromPortalAsync");
            }
        }
    }

    // Background service for periodic tasks
    public class WifiMonitoringService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<WifiMonitoringService> _logger;

        public WifiMonitoringService(IServiceProvider serviceProvider, ILogger<WifiMonitoringService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Wait a bit for app to start
            await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _serviceProvider.CreateScope();
                    var wifiService = scope.ServiceProvider.GetRequiredService<WifiService>();

                    // Update usage statistics
                    await wifiService.UpdateSessionUsageAsync();

                    // Check for quota exceeded
                    await wifiService.CheckQuotaExceededAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in WiFi monitoring service");
                }

                // Run every 1 minute for faster session updates
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
        }
    }
}
