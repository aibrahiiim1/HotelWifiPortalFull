using HotelWifiPortal.Data;
using HotelWifiPortal.Services.PMS;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Services
{
    /// <summary>
    /// Background service that monitors PMS connection and automatically posts pending payments
    /// when the connection is restored
    /// </summary>
    public class PmsPostingService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<PmsPostingService> _logger;
        private bool _wasConnected = false;
        private DateTime _lastCheck = DateTime.MinValue;
        private readonly TimeSpan _checkInterval = TimeSpan.FromMinutes(1);
        private readonly TimeSpan _retryInterval = TimeSpan.FromMinutes(5);

        public PmsPostingService(
            IServiceProvider serviceProvider,
            ILogger<PmsPostingService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("PMS Posting Service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CheckAndPostPendingPaymentsAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in PMS Posting Service");
                }

                await Task.Delay(_checkInterval, stoppingToken);
            }

            _logger.LogInformation("PMS Posting Service stopped");
        }

        private async Task CheckAndPostPendingPaymentsAsync()
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var fiasServer = scope.ServiceProvider.GetRequiredService<FiasSocketServer>();

            // Check if PMS is enabled
            var pmsSettings = await dbContext.PmsSettings.FirstOrDefaultAsync();
            if (pmsSettings?.IsEnabled != true || !pmsSettings.AutoPostCharges)
            {
                return;
            }

            bool isConnected = fiasServer.IsConnected;

            // Check if connection was just restored
            if (isConnected && !_wasConnected)
            {
                _logger.LogInformation("=== PMS Connection Restored ===");
                _logger.LogInformation("Checking for pending payments to post...");
                
                await PostAllPendingPaymentsAsync(dbContext, fiasServer);
            }
            // Also do periodic retry for pending payments
            else if (isConnected && DateTime.UtcNow - _lastCheck > _retryInterval)
            {
                var pendingCount = await dbContext.PaymentTransactions
                    .CountAsync(t => !t.PostedToPMS && (t.Status == "Completed" || t.Status == "PostedToPMS"));

                if (pendingCount > 0)
                {
                    _logger.LogInformation("Periodic check: Found {Count} pending payments to post", pendingCount);
                    await PostAllPendingPaymentsAsync(dbContext, fiasServer);
                }

                _lastCheck = DateTime.UtcNow;
            }

            _wasConnected = isConnected;
        }

        private async Task PostAllPendingPaymentsAsync(ApplicationDbContext dbContext, FiasSocketServer fiasServer)
        {
            var pendingTransactions = await dbContext.PaymentTransactions
                .Where(t => !t.PostedToPMS && (t.Status == "Completed" || t.Status == "PostedToPMS"))
                .OrderBy(t => t.CreatedAt)
                .ToListAsync();

            if (!pendingTransactions.Any())
            {
                _logger.LogInformation("No pending payments to post");
                return;
            }

            // Get PMS settings for posting mode
            var pmsSettings = await dbContext.PmsSettings.FirstOrDefaultAsync();
            var postByReservation = pmsSettings?.PostByReservationNumber ?? false;

            _logger.LogInformation("Found {Count} pending payments to post to PMS (by {Mode})", 
                pendingTransactions.Count,
                postByReservation ? "Reservation Number" : "Room Number");

            int posted = 0;
            int failed = 0;

            foreach (var transaction in pendingTransactions)
            {
                // Check if still connected before each posting
                if (!fiasServer.IsConnected)
                {
                    _logger.LogWarning("PMS connection lost during batch posting. Posted {Posted}, remaining {Remaining}",
                        posted, pendingTransactions.Count - posted - failed);
                    break;
                }

                try
                {
                    var description = $"WiFi: {transaction.PackageName}";
                    
                    await fiasServer.PostChargeAsync(
                        transaction.RoomNumber,
                        transaction.ReservationNumber,
                        transaction.Amount,
                        description,
                        postByReservation);

                    transaction.PostedToPMS = true;
                    transaction.PostedToPMSAt = DateTime.UtcNow;
                    transaction.Status = "PostedToPMS";
                    transaction.PMSPostingId = Guid.NewGuid().ToString("N")[..16];
                    transaction.PMSResponse = postByReservation 
                        ? $"Success (by Reservation# {transaction.ReservationNumber})" 
                        : $"Success (by Room {transaction.RoomNumber})";
                    posted++;

                    _logger.LogInformation("✓ Posted transaction {Id} to PMS: {Identifier}, Amount {Currency} {Amount}",
                        transaction.Id, 
                        postByReservation ? $"Reservation# {transaction.ReservationNumber}" : $"Room {transaction.RoomNumber}",
                        transaction.Currency, transaction.Amount);

                    // Small delay between postings to not overwhelm PMS
                    await Task.Delay(500);
                }
                catch (Exception ex)
                {
                    failed++;
                    transaction.PMSResponse = $"Auto-retry failed: {ex.Message}";
                    
                    _logger.LogError(ex, "Failed to post transaction {Id} to PMS: {Error}",
                        transaction.Id, ex.Message);
                }
            }

            await dbContext.SaveChangesAsync();

            // Log summary
            if (posted > 0 || failed > 0)
            {
                _logger.LogInformation("=== PMS Posting Complete: {Posted} posted, {Failed} failed ===", posted, failed);

                // Add system log entry
                dbContext.SystemLogs.Add(new Models.Entities.SystemLog
                {
                    Level = posted > 0 ? "INFO" : "WARNING",
                    Category = "PMS",
                    Source = "PmsPostingService",
                    Message = $"Auto-posted {posted} pending payments to PMS" + (failed > 0 ? $" ({failed} failed)" : ""),
                    Details = $"Posted: {posted}, Failed: {failed}"
                });
                await dbContext.SaveChangesAsync();
            }
        }
    }
}
