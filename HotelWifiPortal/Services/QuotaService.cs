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
            if (package.PackageType == "DataBased" && package.QuotaBytes.HasValue)
            {
                guest.PaidQuotaBytes += package.QuotaBytes.Value;
            }
            else if (package.PackageType == "RestOfStay")
            {
                // Give unlimited quota (very large number)
                guest.PaidQuotaBytes = 100L * 1024 * 1024 * 1024 * 1024; // 100 TB
            }
            else if (package.PackageType == "TimeBased")
            {
                // For time-based, we track separately or give temporary unlimited
                guest.PaidQuotaBytes += 50L * 1024 * 1024 * 1024; // 50 GB for time-based
            }

            guest.HasPurchasedPackage = true;
            guest.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();
            return true;
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
