using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Services
{
    public class QuotaService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<QuotaService> _logger;

        public QuotaService(ApplicationDbContext dbContext, ILogger<QuotaService> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        public async Task<long> CalculateFreeQuotaAsync(int stayLengthDays)
        {
            var packages = await _dbContext.BandwidthPackages
                .Where(p => p.IsActive)
                .OrderBy(p => p.SortOrder)
                .ToListAsync();

            foreach (var package in packages)
            {
                if (stayLengthDays >= package.MinStayDays)
                {
                    if (!package.MaxStayDays.HasValue || stayLengthDays <= package.MaxStayDays.Value)
                    {
                        return package.QuotaBytes;
                    }
                }
            }

            // Default fallback: 1GB
            return 1L * 1024 * 1024 * 1024;
        }

        public async Task<BandwidthPackage?> GetPackageForStayLengthAsync(int stayLengthDays)
        {
            return await _dbContext.BandwidthPackages
                .Where(p => p.IsActive && 
                           stayLengthDays >= p.MinStayDays && 
                           (!p.MaxStayDays.HasValue || stayLengthDays <= p.MaxStayDays.Value))
                .OrderBy(p => p.SortOrder)
                .FirstOrDefaultAsync();
        }

        public async Task AssignFreeQuotaToGuestAsync(Guest guest)
        {
            var quotaBytes = await CalculateFreeQuotaAsync(guest.StayLength);
            guest.FreeQuotaBytes = quotaBytes;
            guest.QuotaResetDate = guest.ArrivalDate;
            
            await _dbContext.SaveChangesAsync();
            
            _logger.LogInformation("Assigned {QuotaGB:F2} GB free quota to guest {Name} (Room {Room}, {Days} days stay)",
                quotaBytes / (1024.0 * 1024.0 * 1024.0), guest.GuestName, guest.RoomNumber, guest.StayLength);
        }

        public async Task<bool> AddPaidQuotaAsync(Guest guest, PaidPackage package)
        {
            // Calculate quota based on package type
            long quotaToAdd = 0;
            
            if (package.PackageType == "DataBased" && package.QuotaBytes.HasValue)
            {
                // Data-based: use exact quota from package
                quotaToAdd = package.QuotaBytes.Value;
            }
            else if (package.PackageType == "RestOfStay")
            {
                // Rest of stay: give unlimited quota (very large number)
                quotaToAdd = 100L * 1024 * 1024 * 1024 * 1024; // 100 TB
            }
            else if (package.PackageType == "TimeBased")
            {
                // Time-based: use package quota if set, otherwise give generous amount
                if (package.QuotaBytes.HasValue && package.QuotaBytes.Value > 0)
                {
                    quotaToAdd = package.QuotaBytes.Value;
                }
                else
                {
                    // No quota specified, give unlimited for time-based
                    quotaToAdd = 100L * 1024 * 1024 * 1024 * 1024; // 100 TB
                }
            }

            guest.PaidQuotaBytes += quotaToAdd;
            guest.HasPurchasedPackage = true;
            guest.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();
            
            _logger.LogInformation("Added paid quota for Room {Room}: Package={Package}, QuotaAdded={QuotaGB}GB, NewTotal={Total}GB",
                guest.RoomNumber, package.Name, quotaToAdd / 1073741824.0, guest.TotalQuotaGB);

            // Update FreeRADIUS radreply with new quota limit
            await UpdateFreeRadiusQuotaAsync(guest);

            return true;
        }

        /// <summary>
        /// Update FreeRADIUS radreply table with new quota limit for guest
        /// </summary>
        private async Task UpdateFreeRadiusQuotaAsync(Guest guest)
        {
            try
            {
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (enabled?.ToLower() != "true" || string.IsNullOrEmpty(connStr))
                {
                    _logger.LogDebug("FreeRADIUS not configured, skipping quota update");
                    return;
                }

                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();

                // Calculate remaining quota
                var remainingQuota = Math.Max(0, guest.TotalQuotaBytes - guest.UsedQuotaBytes);
                
                // Update or insert Mikrotik-Total-Limit attribute
                var sql = $@"
                    INSERT INTO {prefix}reply (username, attribute, op, value)
                    VALUES (@username, 'Mikrotik-Total-Limit', ':=', @value)
                    ON DUPLICATE KEY UPDATE value = @value";

                using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                cmd.Parameters.AddWithValue("@username", guest.RoomNumber);
                cmd.Parameters.AddWithValue("@value", remainingQuota.ToString());
                await cmd.ExecuteNonQueryAsync();

                _logger.LogInformation("Updated FreeRADIUS quota for Room {Room}: {Quota}MB remaining",
                    guest.RoomNumber, remainingQuota / 1048576.0);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error updating FreeRADIUS quota for guest {Room}", guest.RoomNumber);
            }
        }

        public async Task<(bool IsExhausted, double UsedGB, double TotalGB, double RemainingGB)> CheckGuestQuotaAsync(int guestId)
        {
            var guest = await _dbContext.Guests.FindAsync(guestId);
            if (guest == null)
                return (true, 0, 0, 0);

            var totalQuota = guest.TotalQuotaBytes;
            var usedQuota = guest.UsedQuotaBytes;
            var remainingQuota = Math.Max(0, totalQuota - usedQuota);

            return (
                remainingQuota <= 0,
                usedQuota / (1024.0 * 1024.0 * 1024.0),
                totalQuota / (1024.0 * 1024.0 * 1024.0),
                remainingQuota / (1024.0 * 1024.0 * 1024.0)
            );
        }

        public async Task<List<BandwidthPackage>> GetAllBandwidthPackagesAsync()
        {
            return await _dbContext.BandwidthPackages
                .OrderBy(p => p.SortOrder)
                .ToListAsync();
        }

        public async Task<List<PaidPackage>> GetActivePaidPackagesAsync()
        {
            return await _dbContext.PaidPackages
                .Where(p => p.IsActive)
                .OrderBy(p => p.SortOrder)
                .ToListAsync();
        }

        public async Task UpdateGuestUsageAsync(int guestId, long bytesUsed)
        {
            var guest = await _dbContext.Guests.FindAsync(guestId);
            if (guest != null)
            {
                guest.UsedQuotaBytes += bytesUsed;
                guest.UpdatedAt = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync();
            }
        }
    }
}
