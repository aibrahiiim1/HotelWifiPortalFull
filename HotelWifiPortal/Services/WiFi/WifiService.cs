using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
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
        private readonly Dictionary<string, IWifiController> _controllers = new();

        public WifiService(ApplicationDbContext dbContext, WifiControllerFactory controllerFactory, ILogger<WifiService> logger)
        {
            _dbContext = dbContext;
            _controllerFactory = controllerFactory;
            _logger = logger;
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
                .Where(s => s.Status == "Active")
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

                            // Update guest usage
                            var guest = await _dbContext.Guests.FindAsync(session.GuestId);
                            if (guest != null)
                            {
                                guest.UsedQuotaBytes += newBytes;
                            }
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
                    return false;

                var connectionString = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusConnectionString")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync();

                if (string.IsNullOrEmpty(connectionString))
                    return false;

                var tablePrefix = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusTablePrefix")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "rad";

                _logger.LogInformation("Syncing usage from FreeRADIUS for {Count} active sessions...", activeSessions.Count);

                using var connection = new MySqlConnector.MySqlConnection(connectionString);
                await connection.OpenAsync();

                foreach (var session in activeSessions)
                {
                    try
                    {
                        // Normalize MAC address to different formats for matching
                        var macClean = session.MacAddress?.ToLower().Replace(":", "").Replace("-", "") ?? "";
                        var macWithColons = session.MacAddress?.ToUpper() ?? "";
                        var macWithDashes = session.MacAddress?.ToUpper().Replace(":", "-") ?? "";

                        _logger.LogDebug("Querying for Room={Room}, MAC formats: clean={Clean}, colons={Colons}, dashes={Dashes}",
                            session.RoomNumber, macClean, macWithColons, macWithDashes);

                        // Query radacct for this session's usage
                        // Match by username (room number) OR various MAC address formats
                        var sql = $@"
                            SELECT 
                                COALESCE(SUM(acctinputoctets), 0) + 
                                COALESCE(SUM(CAST(COALESCE(acctinputgigawords, 0) AS UNSIGNED) * 4294967296), 0) as total_input,
                                COALESCE(SUM(acctoutputoctets), 0) + 
                                COALESCE(SUM(CAST(COALESCE(acctoutputgigawords, 0) AS UNSIGNED) * 4294967296), 0) as total_output,
                                MAX(acctstarttime) as last_start,
                                MAX(acctstoptime) as last_stop
                            FROM {tablePrefix}acct 
                            WHERE username = @username 
                               OR username = @macClean
                               OR username = @macWithColons
                               OR username = @macWithDashes
                               OR callingstationid = @macClean
                               OR callingstationid = @macWithColons
                               OR callingstationid = @macWithDashes
                               OR LOWER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')) = @macClean";

                        using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                        cmd.Parameters.AddWithValue("@username", session.RoomNumber);
                        cmd.Parameters.AddWithValue("@macClean", macClean);
                        cmd.Parameters.AddWithValue("@macWithColons", macWithColons);
                        cmd.Parameters.AddWithValue("@macWithDashes", macWithDashes);

                        using var reader = await cmd.ExecuteReaderAsync();
                        if (await reader.ReadAsync())
                        {
                            var inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                            var outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                            var totalBytes = inputBytes + outputBytes;

                            _logger.LogInformation("Found usage for Room={Room}: Input={Input}MB, Output={Output}MB, Total={Total}MB",
                                session.RoomNumber, inputBytes / 1048576.0, outputBytes / 1048576.0, totalBytes / 1048576.0);

                            if (totalBytes > 0)
                            {
                                // Update session - mark as modified to ensure EF tracks it
                                session.BytesDownloaded = inputBytes;
                                session.BytesUploaded = outputBytes;
                                session.BytesUsed = totalBytes;
                                session.LastActivity = DateTime.UtcNow;
                                _dbContext.Entry(session).State = Microsoft.EntityFrameworkCore.EntityState.Modified;

                                _logger.LogInformation("Updated session {Id} for Room={Room}: BytesUsed={Total}",
                                    session.Id, session.RoomNumber, totalBytes);

                                // Update guest usage directly
                                if (session.GuestId > 0)
                                {
                                    var guest = await _dbContext.Guests.FindAsync(session.GuestId);
                                    if (guest != null)
                                    {
                                        var oldUsage = guest.UsedQuotaBytes;
                                        guest.UsedQuotaBytes = Math.Max(guest.UsedQuotaBytes, totalBytes);
                                        _dbContext.Entry(guest).State = Microsoft.EntityFrameworkCore.EntityState.Modified;

                                        _logger.LogInformation("Updated guest {GuestId} Room={Room}: Usage {Old}MB -> {New}MB",
                                            guest.Id, guest.RoomNumber, oldUsage / 1048576.0, guest.UsedQuotaBytes / 1048576.0);
                                    }
                                    else
                                    {
                                        _logger.LogWarning("Guest not found for GuestId={GuestId}", session.GuestId);
                                    }
                                }
                                else
                                {
                                    _logger.LogWarning("Session has no GuestId, skipping guest update");
                                }
                            }
                            else
                            {
                                _logger.LogDebug("No usage found in radacct for Room={Room}", session.RoomNumber);
                            }
                        }
                        else
                        {
                            _logger.LogDebug("No radacct records found for Room={Room}", session.RoomNumber);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error syncing usage for session {Room}", session.RoomNumber);
                    }
                }

                // Save all changes
                var changes = await _dbContext.SaveChangesAsync();
                _logger.LogInformation("Saved {Changes} changes to database", changes);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing from FreeRADIUS");
                return false;
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
            if (controller == null) return;

            var guestsOverQuota = await _dbContext.Guests
                .Where(g => g.Status == "checked-in" && g.UsedQuotaBytes >= (g.FreeQuotaBytes + g.PaidQuotaBytes))
                .ToListAsync();

            foreach (var guest in guestsOverQuota)
            {
                var sessions = await _dbContext.WifiSessions
                    .Where(s => s.GuestId == guest.Id && s.Status == "Active")
                    .ToListAsync();

                foreach (var session in sessions)
                {
                    // Block or limit the client
                    await controller.SetBandwidthLimitAsync(session.MacAddress, 64, 64); // Very low speed
                    session.Status = "QuotaExceeded";
                }
            }

            await _dbContext.SaveChangesAsync();
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

                // Run every 5 minutes
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
        }
    }
}