using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Services.Radius;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Services
{
    /// <summary>
    /// Background service that monitors time-based packages and disconnects users when packages expire
    /// </summary>
    public class PackageExpiryService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<PackageExpiryService> _logger;
        private readonly TimeSpan _checkInterval = TimeSpan.FromMinutes(1); // Check every minute

        public PackageExpiryService(
            IServiceProvider serviceProvider,
            ILogger<PackageExpiryService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("PackageExpiryService started. Will check for expired packages every {Interval} minutes", 
                _checkInterval.TotalMinutes);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CheckAndHandleExpiredPackagesAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error checking expired packages");
                }

                await Task.Delay(_checkInterval, stoppingToken);
            }
        }

        private async Task CheckAndHandleExpiredPackagesAsync()
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

            // Find expired GuestPaidPackages that are still marked as Active
            var expiredPackages = await dbContext.GuestPaidPackages
                .Include(p => p.Guest)
                .Where(p => p.Status == "Active" && 
                           p.PackageType == "TimeBased" && 
                           p.ExpiresAt.HasValue && 
                           p.ExpiresAt.Value < DateTime.UtcNow)
                .ToListAsync();

            if (expiredPackages.Any())
            {
                _logger.LogInformation("Found {Count} expired time-based packages", expiredPackages.Count);
            }

            foreach (var package in expiredPackages)
            {
                try
                {
                    _logger.LogInformation("Package '{Name}' for guest Room {Room} has expired at {Expiry}",
                        package.PackageName, package.RoomNumber, package.ExpiresAt);

                    // Mark package as expired
                    package.Status = "Expired";
                    package.UpdatedAt = DateTime.UtcNow;

                    // Check if guest has any other active packages
                    var hasOtherActivePackages = await dbContext.GuestPaidPackages
                        .AnyAsync(p => p.GuestId == package.GuestId && 
                                      p.Id != package.Id && 
                                      p.Status == "Active" &&
                                      (!p.ExpiresAt.HasValue || p.ExpiresAt.Value > DateTime.UtcNow));

                    if (!hasOtherActivePackages && package.Guest != null)
                    {
                        // Remove the paid quota from guest
                        var guest = package.Guest;
                        guest.PaidQuotaBytes -= package.QuotaBytes;
                        if (guest.PaidQuotaBytes < 0) guest.PaidQuotaBytes = 0;

                        // Check if guest is now over quota
                        if (guest.IsQuotaExhausted)
                        {
                            _logger.LogInformation("Guest Room {Room} is now over quota after package expiry. Disconnecting...", 
                                guest.RoomNumber);

                            // Disconnect the user
                            try
                            {
                                await freeRadiusService.DisconnectUserByUsernameAsync(guest.RoomNumber);
                                _logger.LogInformation("Disconnected guest Room {Room} due to package expiry", guest.RoomNumber);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Failed to disconnect guest Room {Room}", guest.RoomNumber);
                            }
                        }

                        // Update FreeRADIUS with new quota/bandwidth
                        await freeRadiusService.CreateOrUpdateUserAsync(guest);
                    }

                    await dbContext.SaveChangesAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error handling expired package {PackageId}", package.Id);
                }
            }

            // Also check PaymentTransactions for expired time-based packages (legacy)
            await CheckExpiredTransactionsAsync(dbContext, freeRadiusService);
        }

        private async Task CheckExpiredTransactionsAsync(ApplicationDbContext dbContext, FreeRadiusService freeRadiusService)
        {
            // Find completed time-based transactions that have expired
            var expiredTransactions = await dbContext.PaymentTransactions
                .Include(t => t.Guest)
                .Where(t => t.Status == "Completed" &&
                           t.PackageType == "TimeBased" &&
                           t.ExpiresAt.HasValue &&
                           t.ExpiresAt.Value < DateTime.UtcNow)
                .ToListAsync();

            foreach (var transaction in expiredTransactions)
            {
                if (transaction.Guest == null) continue;

                // Check if there's already a GuestPaidPackage for this transaction
                var hasGuestPackage = await dbContext.GuestPaidPackages
                    .AnyAsync(p => p.TransactionId == transaction.Id);

                if (!hasGuestPackage)
                {
                    // This is a legacy transaction without GuestPaidPackage
                    _logger.LogInformation("Legacy time-based transaction {Id} for Room {Room} has expired",
                        transaction.TransactionId, transaction.RoomNumber);

                    // Update transaction status
                    transaction.Status = "Expired";
                }
            }

            await dbContext.SaveChangesAsync();
        }
    }
}
