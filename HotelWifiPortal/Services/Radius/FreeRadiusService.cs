using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace HotelWifiPortal.Services.Radius
{
    /// <summary>
    /// FreeRADIUS Integration Service
    /// Comprehensive integration with FreeRADIUS 3.x SQL module
    /// Supports: PAP, CHAP, MSCHAP, EAP-TTLS/PEAP, Accounting, CoA
    /// </summary>
    public class FreeRadiusService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<FreeRadiusService> _logger;
        private readonly IConfiguration _configuration;

        private bool _isEnabled;
        private string _connectionString = "";
        private string _tablePrefix = "rad";
        private string _nasSecret = "radius_secret";
        private int _coaPort = 3799;
        private bool _configLoaded = false;

        public FreeRadiusService(
            IServiceProvider serviceProvider,
            ILogger<FreeRadiusService> logger,
            IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _configuration = configuration;

            // Initial load from appsettings as fallback
            LoadConfigurationFromAppSettings();
        }

        private void LoadConfigurationFromAppSettings()
        {
            _isEnabled = _configuration.GetValue<bool>("FreeRadius:Enabled", false);
            _connectionString = _configuration["FreeRadius:ConnectionString"] ?? "";
            _tablePrefix = _configuration["FreeRadius:TablePrefix"] ?? "rad";
            _nasSecret = _configuration["FreeRadius:NasSecret"] ?? _configuration["Radius:SharedSecret"] ?? "radius_secret";
            _coaPort = _configuration.GetValue("FreeRadius:CoAPort", 3799);
        }

        /// <summary>
        /// Load configuration from database (call before any operation)
        /// </summary>
        public async Task LoadConfigurationFromDatabaseAsync()
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                var settings = await dbContext.SystemSettings.ToListAsync();

                var enabledSetting = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
                _isEnabled = enabledSetting?.ToLower() == "true";

                _connectionString = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value ?? "";
                _tablePrefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";
                _nasSecret = settings.FirstOrDefault(s => s.Key == "FreeRadiusNasSecret")?.Value ?? "radius_secret";

                var coaPortStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusCoAPort")?.Value;
                _coaPort = int.TryParse(coaPortStr, out var port) ? port : 3799;

                _configLoaded = true;

                _logger.LogDebug("FreeRADIUS config loaded from DB: Enabled={Enabled}, ConnStr={HasConnStr}, Prefix={Prefix}",
                    _isEnabled, !string.IsNullOrEmpty(_connectionString), _tablePrefix);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading FreeRADIUS configuration from database");
            }
        }

        /// <summary>
        /// Ensure configuration is loaded from database
        /// </summary>
        private async Task EnsureConfigLoadedAsync()
        {
            if (!_configLoaded)
            {
                await LoadConfigurationFromDatabaseAsync();
            }
        }

        public bool IsEnabled => _isEnabled;

        #region User Management

        /// <summary>
        /// Create or update a guest user in FreeRADIUS
        /// </summary>
        public async Task<bool> CreateOrUpdateUserAsync(Guest guest, string? password = null)
        {
            await EnsureConfigLoadedAsync();

            if (!_isEnabled || string.IsNullOrEmpty(_connectionString))
            {
                _logger.LogDebug("FreeRADIUS is not enabled or no connection string. Enabled={Enabled}, HasConnStr={HasConnStr}",
                    _isEnabled, !string.IsNullOrEmpty(_connectionString));
                return false;
            }

            try
            {
                var username = guest.RoomNumber;
                var userPassword = password ?? guest.LocalPassword ?? guest.ReservationNumber;

                _logger.LogInformation("Creating/updating FreeRADIUS user: {Username}", username);

                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var profile = await GetBandwidthProfileAsync(dbContext, guest);

                var checkoutTime = guest.DepartureDate.Date.AddHours(12);
                var sessionTimeout = Math.Max(0, (int)(checkoutTime - DateTime.UtcNow).TotalSeconds);
                var remainingQuota = Math.Max(0, guest.TotalQuotaBytes - guest.UsedQuotaBytes);

                using var transaction = await connection.BeginTransactionAsync();

                try
                {
                    // Clear existing entries
                    await ExecuteAsync(connection, $"DELETE FROM {_tablePrefix}check WHERE username = @username",
                        new MySqlParameter("@username", username), transaction);
                    await ExecuteAsync(connection, $"DELETE FROM {_tablePrefix}reply WHERE username = @username",
                        new MySqlParameter("@username", username), transaction);

                    // Insert radcheck - Cleartext-Password for PAP/CHAP
                    await ExecuteAsync(connection, $@"
                        INSERT INTO {_tablePrefix}check (username, attribute, op, value)
                        VALUES (@username, 'Cleartext-Password', ':=', @password)",
                        new[] {
                            new MySqlParameter("@username", username),
                            new MySqlParameter("@password", userPassword)
                        }, transaction);

                    // NT-Password for MS-CHAPv2
                    var ntHash = ComputeNtHash(userPassword);
                    await ExecuteAsync(connection, $@"
                        INSERT INTO {_tablePrefix}check (username, attribute, op, value)
                        VALUES (@username, 'NT-Password', ':=', @nthash)",
                        new[] {
                            new MySqlParameter("@username", username),
                            new MySqlParameter("@nthash", ntHash)
                        }, transaction);

                    // Insert radreply attributes
                    var replyAttributes = new List<(string attr, string op, string value)>
                    {
                        ("Session-Timeout", ":=", sessionTimeout.ToString()),
                        ("Idle-Timeout", ":=", "1800"),
                        ("Acct-Interim-Interval", ":=", "300"),
                        ("Reply-Message", "=", $"Welcome {guest.GuestName}! Room {guest.RoomNumber}")
                    };

                    // Speed limit attributes
                    if (profile != null)
                    {
                        var rateLimit = $"{profile.UploadSpeedKbps}k/{profile.DownloadSpeedKbps}k";
                        replyAttributes.Add(("Mikrotik-Rate-Limit", ":=", rateLimit));
                        replyAttributes.Add(("WISPr-Bandwidth-Max-Up", ":=", (profile.UploadSpeedKbps * 1000).ToString()));
                        replyAttributes.Add(("WISPr-Bandwidth-Max-Down", ":=", (profile.DownloadSpeedKbps * 1000).ToString()));
                    }

                    // Data limit attributes
                    if (remainingQuota > 0)
                    {
                        var gigawords = remainingQuota / 4294967296;
                        var bytes = remainingQuota % 4294967296;

                        if (gigawords > 0)
                            replyAttributes.Add(("Mikrotik-Total-Limit-Gigawords", ":=", gigawords.ToString()));
                        replyAttributes.Add(("Mikrotik-Total-Limit", ":=", bytes.ToString()));
                    }

                    foreach (var (attr, op, value) in replyAttributes)
                    {
                        await ExecuteAsync(connection, $@"
                            INSERT INTO {_tablePrefix}reply (username, attribute, op, value)
                            VALUES (@username, @attr, @op, @value)",
                            new[] {
                                new MySqlParameter("@username", username),
                                new MySqlParameter("@attr", attr),
                                new MySqlParameter("@op", op),
                                new MySqlParameter("@value", value)
                            }, transaction);
                    }

                    // Update user group
                    await ExecuteAsync(connection, $"DELETE FROM {_tablePrefix}usergroup WHERE username = @username",
                        new MySqlParameter("@username", username), transaction);

                    var groupName = DetermineGroupName(guest, profile);
                    await ExecuteAsync(connection, $@"
                        INSERT INTO {_tablePrefix}usergroup (username, groupname, priority)
                        VALUES (@username, @groupname, 1)",
                        new[] {
                            new MySqlParameter("@username", username),
                            new MySqlParameter("@groupname", groupName)
                        }, transaction);

                    await transaction.CommitAsync();
                    _logger.LogInformation("FreeRADIUS user created/updated: {Username}, Group: {Group}", username, groupName);
                    return true;
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating FreeRADIUS user for room {Room}", guest.RoomNumber);
                return false;
            }
        }

        /// <summary>
        /// Remove user from FreeRADIUS
        /// </summary>
        public async Task<bool> RemoveUserAsync(string username)
        {
            if (!_isEnabled) return false;

            try
            {
                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                await ExecuteAsync(connection, $"DELETE FROM {_tablePrefix}check WHERE username = @username",
                    new MySqlParameter("@username", username));
                await ExecuteAsync(connection, $"DELETE FROM {_tablePrefix}reply WHERE username = @username",
                    new MySqlParameter("@username", username));
                await ExecuteAsync(connection, $"DELETE FROM {_tablePrefix}usergroup WHERE username = @username",
                    new MySqlParameter("@username", username));

                _logger.LogInformation("FreeRADIUS user removed: {Username}", username);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing FreeRADIUS user {Username}", username);
                return false;
            }
        }

        #endregion

        #region Accounting

        /// <summary>
        /// Get accounting data for a user
        /// </summary>
        public async Task<RadiusAccountingData?> GetAccountingDataAsync(string username)
        {
            if (!_isEnabled) return null;

            try
            {
                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                using var cmd = new MySqlCommand($@"
                    SELECT 
                        username,
                        COALESCE(SUM(acctinputoctets), 0) as total_input,
                        COALESCE(SUM(acctoutputoctets), 0) as total_output,
                        COALESCE(SUM(acctsessiontime), 0) as total_time,
                        COUNT(*) as session_count,
                        MAX(acctstarttime) as last_session
                    FROM {_tablePrefix}acct 
                    WHERE username = @username
                    GROUP BY username", connection);

                cmd.Parameters.AddWithValue("@username", username);

                using var reader = await cmd.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    return new RadiusAccountingData
                    {
                        Username = reader.GetString("username"),
                        TotalInputOctets = reader.GetInt64("total_input"),
                        TotalOutputOctets = reader.GetInt64("total_output"),
                        TotalSessionTime = reader.GetInt32("total_time"),
                        SessionCount = reader.GetInt32("session_count"),
                        LastSession = reader.IsDBNull(reader.GetOrdinal("last_session")) ? null : reader.GetDateTime("last_session")
                    };
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting accounting data for {Username}", username);
                return null;
            }
        }

        /// <summary>
        /// Get active sessions
        /// </summary>
        public async Task<List<RadiusSession>> GetActiveSessionsAsync(string? username = null)
        {
            if (!_isEnabled) return new List<RadiusSession>();

            try
            {
                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                var sql = $@"SELECT * FROM {_tablePrefix}acct WHERE acctstoptime IS NULL";
                if (!string.IsNullOrEmpty(username))
                    sql += " AND username = @username";

                using var cmd = new MySqlCommand(sql, connection);
                if (!string.IsNullOrEmpty(username))
                    cmd.Parameters.AddWithValue("@username", username);

                var sessions = new List<RadiusSession>();
                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    sessions.Add(new RadiusSession
                    {
                        AcctSessionId = reader.GetString("acctsessionid"),
                        Username = reader.GetString("username"),
                        NasIpAddress = reader.GetString("nasipaddress"),
                        FramedIpAddress = reader.IsDBNull(reader.GetOrdinal("framedipaddress")) ? "" : reader.GetString("framedipaddress"),
                        CallingStationId = reader.IsDBNull(reader.GetOrdinal("callingstationid")) ? "" : reader.GetString("callingstationid"),
                        AcctStartTime = reader.GetDateTime("acctstarttime"),
                        AcctInputOctets = reader.IsDBNull(reader.GetOrdinal("acctinputoctets")) ? 0 : reader.GetInt64("acctinputoctets"),
                        AcctOutputOctets = reader.IsDBNull(reader.GetOrdinal("acctoutputoctets")) ? 0 : reader.GetInt64("acctoutputoctets"),
                        AcctSessionTime = reader.IsDBNull(reader.GetOrdinal("acctsessiontime")) ? 0 : reader.GetInt32("acctsessiontime")
                    });
                }

                return sessions;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active sessions");
                return new List<RadiusSession>();
            }
        }

        /// <summary>
        /// Sync accounting data to guest usage
        /// </summary>
        public async Task SyncAccountingToGuestsAsync()
        {
            await EnsureConfigLoadedAsync();

            if (!_isEnabled)
            {
                _logger.LogWarning("FreeRADIUS is not enabled, skipping accounting sync");
                return;
            }

            if (string.IsNullOrEmpty(_connectionString))
            {
                _logger.LogWarning("FreeRADIUS connection string is empty, skipping accounting sync");
                return;
            }

            try
            {
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                var guests = await dbContext.Guests
                    .Where(g => g.Status.ToLower() == "checked-in" ||
                               g.Status.ToLower() == "checkedin" ||
                               g.Status == "CheckedIn")
                    .ToListAsync();

                _logger.LogInformation("Syncing accounting for {Count} checked-in guests", guests.Count);

                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                foreach (var guest in guests)
                {
                    try
                    {
                        // Query by room number directly
                        var sql = $@"
                            SELECT 
                                COALESCE(SUM(acctinputoctets), 0) as total_input,
                                COALESCE(SUM(acctoutputoctets), 0) as total_output
                            FROM {_tablePrefix}acct 
                            WHERE username = @username";

                        using var cmd = new MySqlCommand(sql, connection);
                        cmd.Parameters.AddWithValue("@username", guest.RoomNumber);

                        using var reader = await cmd.ExecuteReaderAsync();
                        if (await reader.ReadAsync())
                        {
                            var inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                            var outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                            var totalBytes = inputBytes + outputBytes;

                            if (totalBytes > 0)
                            {
                                _logger.LogInformation("Guest Room={Room}: Usage={Total}MB (In={In}MB, Out={Out}MB)",
                                    guest.RoomNumber, totalBytes / 1048576.0, inputBytes / 1048576.0, outputBytes / 1048576.0);

                                if (totalBytes > guest.UsedQuotaBytes)
                                {
                                    guest.UsedQuotaBytes = totalBytes;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error getting accounting for guest {Room}", guest.RoomNumber);
                    }
                }

                await dbContext.SaveChangesAsync();
                _logger.LogInformation("Accounting sync completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing accounting to guests");
            }
        }

        #endregion

        #region Session Control (CoA/Disconnect)

        /// <summary>
        /// Disconnect a user session by removing from radacct
        /// Note: For real-time disconnect, use the builtin RADIUS server's CoA
        /// This method marks the session as closed in the database
        /// </summary>
        public async Task<bool> DisconnectUserAsync(string nasIpAddress, string username, string? acctSessionId = null)
        {
            try
            {
                _logger.LogInformation("Disconnecting user {Username} from NAS {NAS}", username, nasIpAddress);

                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                // Mark active sessions as stopped
                var sql = $@"UPDATE {_tablePrefix}acct 
                            SET acctstoptime = NOW(), 
                                acctterminatecause = 'Admin-Reset'
                            WHERE username = @username 
                            AND acctstoptime IS NULL";

                if (!string.IsNullOrEmpty(acctSessionId))
                    sql += " AND acctsessionid = @sessionId";

                using var cmd = new MySqlCommand(sql, connection);
                cmd.Parameters.AddWithValue("@username", username);
                if (!string.IsNullOrEmpty(acctSessionId))
                    cmd.Parameters.AddWithValue("@sessionId", acctSessionId);

                var affected = await cmd.ExecuteNonQueryAsync();

                _logger.LogInformation("Disconnected {Count} session(s) for user {Username}", affected, username);
                return affected > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disconnecting user {Username}", username);
                return false;
            }
        }

        /// <summary>
        /// Change of Authorization - Update session attributes
        /// </summary>
        public async Task<bool> ChangeAuthorizationAsync(string nasIpAddress, string username,
            int? downloadKbps = null, int? uploadKbps = null, long? quotaBytes = null)
        {
            try
            {
                _logger.LogInformation("Sending CoA-Request for {Username} to {NAS}", username, nasIpAddress);

                // CoA is typically sent directly via UDP - simplified implementation
                // For full implementation, use the RadiusServer's CoA capabilities

                // Update the user's attributes in the database instead
                // The router will pick up the changes on the next accounting update

                // Use stored connection string from configuration
                if (string.IsNullOrEmpty(_connectionString))
                {
                    _logger.LogWarning("No FreeRADIUS connection string for CoA");
                    return false;
                }

                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                // Update rate limit if specified
                if (downloadKbps.HasValue && uploadKbps.HasValue)
                {
                    var rateLimit = $"{uploadKbps}k/{downloadKbps}k";

                    // Delete existing rate limit
                    using var delCmd = new MySqlCommand(
                        $"DELETE FROM {_tablePrefix}reply WHERE username = @username AND attribute = 'Mikrotik-Rate-Limit'",
                        connection);
                    delCmd.Parameters.AddWithValue("@username", username);
                    await delCmd.ExecuteNonQueryAsync();

                    // Insert new rate limit
                    using var insCmd = new MySqlCommand(
                        $"INSERT INTO {_tablePrefix}reply (username, attribute, op, value) VALUES (@username, 'Mikrotik-Rate-Limit', ':=', @value)",
                        connection);
                    insCmd.Parameters.AddWithValue("@username", username);
                    insCmd.Parameters.AddWithValue("@value", rateLimit);
                    await insCmd.ExecuteNonQueryAsync();
                }

                _logger.LogInformation("CoA attributes updated for {Username}", username);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending CoA for {Username}", username);
                return false;
            }
        }

        #endregion

        #region Group & NAS Management

        public async Task<bool> CreateOrUpdateGroupAsync(string groupName, int downloadKbps, int uploadKbps,
            long? quotaBytes = null, int? sessionTimeoutSecs = null)
        {
            if (!_isEnabled) return false;

            try
            {
                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                await ExecuteAsync(connection, $"DELETE FROM {_tablePrefix}groupreply WHERE groupname = @groupname",
                    new MySqlParameter("@groupname", groupName));

                var attributes = new List<(string attr, string op, string value)>
                {
                    ("Mikrotik-Rate-Limit", ":=", $"{uploadKbps}k/{downloadKbps}k"),
                    ("WISPr-Bandwidth-Max-Up", ":=", (uploadKbps * 1000).ToString()),
                    ("WISPr-Bandwidth-Max-Down", ":=", (downloadKbps * 1000).ToString())
                };

                if (quotaBytes.HasValue && quotaBytes.Value > 0)
                {
                    var gigawords = quotaBytes.Value / 4294967296;
                    var bytes = quotaBytes.Value % 4294967296;
                    if (gigawords > 0)
                        attributes.Add(("Mikrotik-Total-Limit-Gigawords", ":=", gigawords.ToString()));
                    attributes.Add(("Mikrotik-Total-Limit", ":=", bytes.ToString()));
                }

                if (sessionTimeoutSecs.HasValue)
                    attributes.Add(("Session-Timeout", ":=", sessionTimeoutSecs.Value.ToString()));

                foreach (var (attr, op, value) in attributes)
                {
                    await ExecuteAsync(connection, $@"
                        INSERT INTO {_tablePrefix}groupreply (groupname, attribute, op, value)
                        VALUES (@groupname, @attr, @op, @value)",
                        new[] {
                            new MySqlParameter("@groupname", groupName),
                            new MySqlParameter("@attr", attr),
                            new MySqlParameter("@op", op),
                            new MySqlParameter("@value", value)
                        });
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating FreeRADIUS group {GroupName}", groupName);
                return false;
            }
        }

        public async Task<bool> RegisterNasAsync(string nasName, string nasIpAddress, string secret, string nasType = "mikrotik")
        {
            if (!_isEnabled) return false;

            try
            {
                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                await ExecuteAsync(connection, @"
                    INSERT INTO nas (nasname, shortname, type, secret, description)
                    VALUES (@nasname, @shortname, @type, @secret, @description)
                    ON DUPLICATE KEY UPDATE shortname = @shortname, type = @type, secret = @secret",
                    new[] {
                        new MySqlParameter("@nasname", nasIpAddress),
                        new MySqlParameter("@shortname", nasName),
                        new MySqlParameter("@type", nasType),
                        new MySqlParameter("@secret", secret),
                        new MySqlParameter("@description", nasName)
                    });

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering NAS {NasName}", nasName);
                return false;
            }
        }

        #endregion

        #region Sync Methods

        public async Task SyncAllGuestsAsync()
        {
            await EnsureConfigLoadedAsync();

            if (!_isEnabled || string.IsNullOrEmpty(_connectionString))
            {
                _logger.LogWarning("SyncAllGuestsAsync: FreeRADIUS not enabled or no connection string. Enabled={Enabled}, HasConnStr={HasConnStr}",
                    _isEnabled, !string.IsNullOrEmpty(_connectionString));
                return;
            }

            try
            {
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                var guests = await dbContext.Guests
                    .Where(g => g.Status.ToLower() == "checked-in" ||
                               g.Status.ToLower() == "checkedin" ||
                               g.Status == "CheckedIn")
                    .ToListAsync();

                _logger.LogInformation("SyncAllGuestsAsync: Found {Count} checked-in guests to sync", guests.Count);

                int successCount = 0;
                foreach (var guest in guests)
                {
                    var result = await CreateOrUpdateUserAsync(guest);
                    if (result) successCount++;
                }

                _logger.LogInformation("Synced {SuccessCount}/{TotalCount} guests to FreeRADIUS", successCount, guests.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing guests to FreeRADIUS");
                throw; // Re-throw so controller can report error
            }
        }

        public async Task SyncBandwidthProfilesAsync()
        {
            await EnsureConfigLoadedAsync();

            if (!_isEnabled || string.IsNullOrEmpty(_connectionString)) return;

            try
            {
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                var profiles = await dbContext.BandwidthProfiles.Where(p => p.IsActive).ToListAsync();

                foreach (var profile in profiles)
                {
                    var groupName = $"profile-{profile.Name.ToLower().Replace(" ", "-")}";
                    // BandwidthProfile doesn't have data limits, only speed limits
                    await CreateOrUpdateGroupAsync(groupName, profile.DownloadSpeedKbps, profile.UploadSpeedKbps);
                }

                await CreateOrUpdateGroupAsync("guests", 2048, 1024);
                await CreateOrUpdateGroupAsync("vip", 10240, 5120);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error syncing bandwidth profiles to FreeRADIUS");
            }
        }

        public async Task CleanupCheckedOutGuestsAsync()
        {
            await EnsureConfigLoadedAsync();

            if (!_isEnabled || string.IsNullOrEmpty(_connectionString)) return;

            try
            {
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                var checkedOutGuests = await dbContext.Guests
                    .Where(g => g.Status == "checked-out" && g.DepartureDate < DateTime.Today)
                    .ToListAsync();

                foreach (var guest in checkedOutGuests)
                    await RemoveUserAsync(guest.RoomNumber);

                _logger.LogInformation("Cleaned up {Count} checked-out guests from FreeRADIUS", checkedOutGuests.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up checked-out guests");
            }
        }

        #endregion

        #region Database Schema

        public string GetDatabaseSchema()
        {
            return $@"
-- FreeRADIUS Database Schema for MySQL/MariaDB

CREATE TABLE IF NOT EXISTS `{_tablePrefix}check` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `username` varchar(64) NOT NULL DEFAULT '',
    `attribute` varchar(64) NOT NULL DEFAULT '',
    `op` char(2) NOT NULL DEFAULT '==',
    `value` varchar(253) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    KEY `username` (`username`(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `{_tablePrefix}reply` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `username` varchar(64) NOT NULL DEFAULT '',
    `attribute` varchar(64) NOT NULL DEFAULT '',
    `op` char(2) NOT NULL DEFAULT '=',
    `value` varchar(253) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    KEY `username` (`username`(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `{_tablePrefix}usergroup` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `username` varchar(64) NOT NULL DEFAULT '',
    `groupname` varchar(64) NOT NULL DEFAULT '',
    `priority` int(11) NOT NULL DEFAULT 1,
    PRIMARY KEY (`id`),
    KEY `username` (`username`(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `{_tablePrefix}groupcheck` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `groupname` varchar(64) NOT NULL DEFAULT '',
    `attribute` varchar(64) NOT NULL DEFAULT '',
    `op` char(2) NOT NULL DEFAULT '==',
    `value` varchar(253) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    KEY `groupname` (`groupname`(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `{_tablePrefix}groupreply` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `groupname` varchar(64) NOT NULL DEFAULT '',
    `attribute` varchar(64) NOT NULL DEFAULT '',
    `op` char(2) NOT NULL DEFAULT '=',
    `value` varchar(253) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    KEY `groupname` (`groupname`(32))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `{_tablePrefix}acct` (
    `radacctid` bigint(21) NOT NULL AUTO_INCREMENT,
    `acctsessionid` varchar(64) NOT NULL DEFAULT '',
    `acctuniqueid` varchar(32) NOT NULL DEFAULT '',
    `username` varchar(64) NOT NULL DEFAULT '',
    `realm` varchar(64) DEFAULT '',
    `nasipaddress` varchar(15) NOT NULL DEFAULT '',
    `nasportid` varchar(32) DEFAULT NULL,
    `nasporttype` varchar(32) DEFAULT NULL,
    `acctstarttime` datetime DEFAULT NULL,
    `acctupdatetime` datetime DEFAULT NULL,
    `acctstoptime` datetime DEFAULT NULL,
    `acctinterval` int(12) DEFAULT NULL,
    `acctsessiontime` int(12) unsigned DEFAULT NULL,
    `acctauthentic` varchar(32) DEFAULT NULL,
    `connectinfo_start` varchar(128) DEFAULT NULL,
    `connectinfo_stop` varchar(128) DEFAULT NULL,
    `acctinputoctets` bigint(20) DEFAULT NULL,
    `acctoutputoctets` bigint(20) DEFAULT NULL,
    `calledstationid` varchar(50) NOT NULL DEFAULT '',
    `callingstationid` varchar(50) NOT NULL DEFAULT '',
    `acctterminatecause` varchar(32) NOT NULL DEFAULT '',
    `servicetype` varchar(32) DEFAULT NULL,
    `framedprotocol` varchar(32) DEFAULT NULL,
    `framedipaddress` varchar(15) NOT NULL DEFAULT '',
    PRIMARY KEY (`radacctid`),
    UNIQUE KEY `acctuniqueid` (`acctuniqueid`),
    KEY `username` (`username`),
    KEY `acctsessionid` (`acctsessionid`),
    KEY `acctstarttime` (`acctstarttime`),
    KEY `nasipaddress` (`nasipaddress`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `{_tablePrefix}postauth` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `username` varchar(64) NOT NULL DEFAULT '',
    `pass` varchar(64) NOT NULL DEFAULT '',
    `reply` varchar(32) NOT NULL DEFAULT '',
    `authdate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `nas` (
    `id` int(10) NOT NULL AUTO_INCREMENT,
    `nasname` varchar(128) NOT NULL,
    `shortname` varchar(32) DEFAULT NULL,
    `type` varchar(30) DEFAULT 'other',
    `ports` int(5) DEFAULT NULL,
    `secret` varchar(60) NOT NULL DEFAULT 'secret',
    `server` varchar(64) DEFAULT NULL,
    `community` varchar(50) DEFAULT NULL,
    `description` varchar(200) DEFAULT 'RADIUS Client',
    PRIMARY KEY (`id`),
    KEY `nasname` (`nasname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO `{_tablePrefix}groupreply` (`groupname`, `attribute`, `op`, `value`) VALUES
('guests', 'Mikrotik-Rate-Limit', ':=', '1024k/2048k'),
('guests', 'Session-Timeout', ':=', '86400'),
('vip', 'Mikrotik-Rate-Limit', ':=', '5120k/10240k'),
('staff', 'Mikrotik-Rate-Limit', ':=', '10240k/20480k');
";
        }

        public async Task<bool> InitializeDatabaseAsync()
        {
            if (!_isEnabled || string.IsNullOrEmpty(_connectionString)) return false;

            try
            {
                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();

                var schema = GetDatabaseSchema();
                var statements = schema.Split(new[] { ";\n", ";\r\n" }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var statement in statements)
                {
                    var sql = statement.Trim();
                    if (string.IsNullOrEmpty(sql) || sql.StartsWith("--")) continue;

                    try
                    {
                        using var cmd = new MySqlCommand(sql, connection);
                        await cmd.ExecuteNonQueryAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("Schema statement warning: {Error}", ex.Message);
                    }
                }

                _logger.LogInformation("FreeRADIUS database schema initialized");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing FreeRADIUS database");
                return false;
            }
        }

        #endregion

        #region Test Connection

        public async Task<FreeRadiusTestResult> TestConnectionAsync()
        {
            await EnsureConfigLoadedAsync();

            var result = new FreeRadiusTestResult { IsEnabled = _isEnabled };

            if (!_isEnabled)
            {
                result.Message = "FreeRADIUS integration is disabled";
                return result;
            }

            if (string.IsNullOrEmpty(_connectionString))
            {
                result.Message = "No connection string configured";
                return result;
            }

            try
            {
                using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync();
                result.DatabaseConnected = true;

                var tables = new[] { $"{_tablePrefix}check", $"{_tablePrefix}reply", $"{_tablePrefix}acct", "nas" };
                foreach (var table in tables)
                {
                    using var cmd = new MySqlCommand($"SELECT COUNT(*) FROM `{table}` LIMIT 1", connection);
                    try
                    {
                        await cmd.ExecuteScalarAsync();
                        result.TablesExist = true;
                    }
                    catch
                    {
                        result.TablesExist = false;
                        result.Message = $"Table '{table}' does not exist";
                        return result;
                    }
                }

                using var statsCmd = new MySqlCommand($@"
                    SELECT 
                        (SELECT COUNT(DISTINCT username) FROM `{_tablePrefix}check`) as users,
                        (SELECT COUNT(*) FROM `{_tablePrefix}acct` WHERE acctstoptime IS NULL) as active_sessions,
                        (SELECT COUNT(*) FROM `nas`) as nas_count", connection);

                using var reader = await statsCmd.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    result.UserCount = reader.GetInt32("users");
                    result.ActiveSessions = reader.GetInt32("active_sessions");
                    result.NasCount = reader.GetInt32("nas_count");
                }

                result.Success = true;
                result.Message = "FreeRADIUS database connection successful";
            }
            catch (Exception ex)
            {
                result.Message = $"Connection failed: {ex.Message}";
            }

            return result;
        }

        #endregion

        #region Helper Methods

        private string DetermineGroupName(Guest guest, BandwidthProfile? profile)
        {
            if (!string.IsNullOrEmpty(guest.VipStatus)) return "vip";
            if (profile != null) return $"profile-{profile.Name.ToLower().Replace(" ", "-")}";
            return "guests";
        }

        private async Task<BandwidthProfile?> GetBandwidthProfileAsync(ApplicationDbContext dbContext, Guest guest)
        {
            if (!string.IsNullOrEmpty(guest.VipStatus))
            {
                var vipProfile = await dbContext.BandwidthProfiles
                    .FirstOrDefaultAsync(p => p.IsActive && p.Name.ToLower().Contains("vip"));
                if (vipProfile != null) return vipProfile;
            }

            return await dbContext.BandwidthProfiles.FirstOrDefaultAsync(p => p.IsActive && p.IsDefault);
        }

        private async Task ExecuteAsync(MySqlConnection connection, string sql, MySqlParameter parameter,
            MySqlTransaction? transaction = null)
        {
            await ExecuteAsync(connection, sql, new[] { parameter }, transaction);
        }

        private async Task ExecuteAsync(MySqlConnection connection, string sql, MySqlParameter[] parameters,
            MySqlTransaction? transaction = null)
        {
            using var cmd = new MySqlCommand(sql, connection, transaction);
            cmd.Parameters.AddRange(parameters);
            await cmd.ExecuteNonQueryAsync();
        }

        private string ComputeNtHash(string password)
        {
            var unicodeBytes = Encoding.Unicode.GetBytes(password);
            using var md4 = MD4.Create();
            var hash = md4.ComputeHash(unicodeBytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        #endregion
    }

    #region Data Models

    public class RadiusAccountingData
    {
        public string Username { get; set; } = "";
        public long TotalInputOctets { get; set; }
        public long TotalOutputOctets { get; set; }
        public int TotalSessionTime { get; set; }
        public int SessionCount { get; set; }
        public DateTime? LastSession { get; set; }
        public long TotalBytes => TotalInputOctets + TotalOutputOctets;
        public double TotalMB => TotalBytes / (1024.0 * 1024.0);
        public double TotalGB => TotalBytes / (1024.0 * 1024.0 * 1024.0);
    }

    public class RadiusSession
    {
        public string AcctSessionId { get; set; } = "";
        public string Username { get; set; } = "";
        public string NasIpAddress { get; set; } = "";
        public string FramedIpAddress { get; set; } = "";
        public string CallingStationId { get; set; } = "";
        public DateTime AcctStartTime { get; set; }
        public long AcctInputOctets { get; set; }
        public long AcctOutputOctets { get; set; }
        public int AcctSessionTime { get; set; }
        public long TotalBytes => AcctInputOctets + AcctOutputOctets;
        public TimeSpan Duration => TimeSpan.FromSeconds(AcctSessionTime);
    }

    public class FreeRadiusTestResult
    {
        public bool IsEnabled { get; set; }
        public bool DatabaseConnected { get; set; }
        public bool TablesExist { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public int UserCount { get; set; }
        public int ActiveSessions { get; set; }
        public int NasCount { get; set; }
    }

    #endregion

    #region MD4 Implementation

    public class MD4 : HashAlgorithm
    {
        private uint[] _state = new uint[4];
        private uint[] _count = new uint[2];
        private byte[] _buffer = new byte[64];

        public static new MD4 Create() => new MD4();

        public MD4() { Initialize(); }

        public override void Initialize()
        {
            _state[0] = 0x67452301; _state[1] = 0xefcdab89;
            _state[2] = 0x98badcfe; _state[3] = 0x10325476;
            _count[0] = 0; _count[1] = 0;
            Array.Clear(_buffer, 0, 64);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int i, index, partLen;
            index = (int)((_count[0] >> 3) & 0x3F);
            if ((_count[0] += (uint)(cbSize << 3)) < (uint)(cbSize << 3)) _count[1]++;
            _count[1] += (uint)(cbSize >> 29);
            partLen = 64 - index;
            if (cbSize >= partLen)
            {
                Buffer.BlockCopy(array, ibStart, _buffer, index, partLen);
                Transform(_buffer, 0);
                for (i = partLen; i + 63 < cbSize; i += 64) Transform(array, ibStart + i);
                index = 0;
            }
            else i = 0;
            Buffer.BlockCopy(array, ibStart + i, _buffer, index, cbSize - i);
        }

        protected override byte[] HashFinal()
        {
            byte[] digest = new byte[16];
            byte[] bits = new byte[8];
            Encode(bits, _count, 8);
            int index = (int)((_count[0] >> 3) & 0x3f);
            int padLen = (index < 56) ? (56 - index) : (120 - index);
            byte[] padding = new byte[padLen];
            padding[0] = 0x80;
            HashCore(padding, 0, padLen);
            HashCore(bits, 0, 8);
            Encode(digest, _state, 16);
            return digest;
        }

        private void Transform(byte[] block, int offset)
        {
            uint a = _state[0], b = _state[1], c = _state[2], d = _state[3];
            uint[] x = new uint[16];
            Decode(x, block, offset, 64);

            a = FF(a, b, c, d, x[0], 3); d = FF(d, a, b, c, x[1], 7);
            c = FF(c, d, a, b, x[2], 11); b = FF(b, c, d, a, x[3], 19);
            a = FF(a, b, c, d, x[4], 3); d = FF(d, a, b, c, x[5], 7);
            c = FF(c, d, a, b, x[6], 11); b = FF(b, c, d, a, x[7], 19);
            a = FF(a, b, c, d, x[8], 3); d = FF(d, a, b, c, x[9], 7);
            c = FF(c, d, a, b, x[10], 11); b = FF(b, c, d, a, x[11], 19);
            a = FF(a, b, c, d, x[12], 3); d = FF(d, a, b, c, x[13], 7);
            c = FF(c, d, a, b, x[14], 11); b = FF(b, c, d, a, x[15], 19);

            a = GG(a, b, c, d, x[0], 3); d = GG(d, a, b, c, x[4], 5);
            c = GG(c, d, a, b, x[8], 9); b = GG(b, c, d, a, x[12], 13);
            a = GG(a, b, c, d, x[1], 3); d = GG(d, a, b, c, x[5], 5);
            c = GG(c, d, a, b, x[9], 9); b = GG(b, c, d, a, x[13], 13);
            a = GG(a, b, c, d, x[2], 3); d = GG(d, a, b, c, x[6], 5);
            c = GG(c, d, a, b, x[10], 9); b = GG(b, c, d, a, x[14], 13);
            a = GG(a, b, c, d, x[3], 3); d = GG(d, a, b, c, x[7], 5);
            c = GG(c, d, a, b, x[11], 9); b = GG(b, c, d, a, x[15], 13);

            a = HH(a, b, c, d, x[0], 3); d = HH(d, a, b, c, x[8], 9);
            c = HH(c, d, a, b, x[4], 11); b = HH(b, c, d, a, x[12], 15);
            a = HH(a, b, c, d, x[2], 3); d = HH(d, a, b, c, x[10], 9);
            c = HH(c, d, a, b, x[6], 11); b = HH(b, c, d, a, x[14], 15);
            a = HH(a, b, c, d, x[1], 3); d = HH(d, a, b, c, x[9], 9);
            c = HH(c, d, a, b, x[5], 11); b = HH(b, c, d, a, x[13], 15);
            a = HH(a, b, c, d, x[3], 3); d = HH(d, a, b, c, x[11], 9);
            c = HH(c, d, a, b, x[7], 11); b = HH(b, c, d, a, x[15], 15);

            _state[0] += a; _state[1] += b; _state[2] += c; _state[3] += d;
        }

        private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);
        private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
        private static uint H(uint x, uint y, uint z) => x ^ y ^ z;
        private static uint ROL(uint x, int n) => (x << n) | (x >> (32 - n));
        private static uint FF(uint a, uint b, uint c, uint d, uint x, int s) => ROL(a + F(b, c, d) + x, s);
        private static uint GG(uint a, uint b, uint c, uint d, uint x, int s) => ROL(a + G(b, c, d) + x + 0x5a827999, s);
        private static uint HH(uint a, uint b, uint c, uint d, uint x, int s) => ROL(a + H(b, c, d) + x + 0x6ed9eba1, s);

        private static void Encode(byte[] output, uint[] input, int len)
        {
            for (int i = 0, j = 0; j < len; i++, j += 4)
            {
                output[j] = (byte)(input[i] & 0xff);
                output[j + 1] = (byte)((input[i] >> 8) & 0xff);
                output[j + 2] = (byte)((input[i] >> 16) & 0xff);
                output[j + 3] = (byte)((input[i] >> 24) & 0xff);
            }
        }

        private static void Decode(uint[] output, byte[] input, int offset, int len)
        {
            for (int i = 0, j = 0; j < len; i++, j += 4)
                output[i] = input[offset + j] | ((uint)input[offset + j + 1] << 8) |
                           ((uint)input[offset + j + 2] << 16) | ((uint)input[offset + j + 3] << 24);
        }
    }

    #endregion

    #region Background Sync Service

    public class FreeRadiusSyncService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<FreeRadiusSyncService> _logger;
        private readonly IConfiguration _configuration;

        public FreeRadiusSyncService(IServiceProvider serviceProvider, ILogger<FreeRadiusSyncService> logger, IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _configuration = configuration;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var enabled = _configuration.GetValue<bool>("FreeRadius:Enabled", false);
            if (!enabled)
            {
                _logger.LogInformation("FreeRADIUS sync service is disabled");
                return;
            }

            _logger.LogInformation("FreeRADIUS sync service starting");
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

            try
            {
                using var scope = _serviceProvider.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();
                await freeRadiusService.InitializeDatabaseAsync();
                await freeRadiusService.SyncBandwidthProfilesAsync();
                await freeRadiusService.SyncAllGuestsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in initial FreeRADIUS sync");
            }

            var syncInterval = _configuration.GetValue("FreeRadius:SyncIntervalMinutes", 5);

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMinutes(syncInterval), stoppingToken);

                try
                {
                    using var scope = _serviceProvider.CreateScope();
                    var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();
                    await freeRadiusService.SyncAccountingToGuestsAsync();
                    await freeRadiusService.SyncAllGuestsAsync();
                    await freeRadiusService.CleanupCheckedOutGuestsAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in FreeRADIUS periodic sync");
                }
            }
        }
    }

    #endregion
}