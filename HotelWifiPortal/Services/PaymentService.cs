using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Services.PMS;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Services
{
    public class PaymentService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly QuotaService _quotaService;
        private readonly FiasSocketServer _fiasServer;
        private readonly ILogger<PaymentService> _logger;

        public PaymentService(
            ApplicationDbContext dbContext,
            QuotaService quotaService,
            FiasSocketServer fiasServer,
            ILogger<PaymentService> logger)
        {
            _dbContext = dbContext;
            _quotaService = quotaService;
            _fiasServer = fiasServer;
            _logger = logger;
        }

        public async Task<(bool Success, PaymentTransaction? Transaction, string? Error)> PurchasePackageAsync(
            int guestId, 
            int packageId)
        {
            var guest = await _dbContext.Guests.FindAsync(guestId);
            if (guest == null)
                return (false, null, "Guest not found.");

            var package = await _dbContext.PaidPackages.FindAsync(packageId);
            if (package == null || !package.IsActive)
                return (false, null, "Package not available.");

            _logger.LogInformation("=== Processing WiFi Package Purchase ===");
            _logger.LogInformation("Guest: {Name} (Room {Room})", guest.GuestName, guest.RoomNumber);
            _logger.LogInformation("Package: {Package}, Price: {Currency} {Price}", package.Name, package.Currency, package.Price);

            // Create transaction
            var transaction = new PaymentTransaction
            {
                GuestId = guestId,
                PaidPackageId = packageId,
                RoomNumber = guest.RoomNumber,
                ReservationNumber = guest.ReservationNumber,
                GuestName = guest.GuestName,
                PackageName = package.Name,
                Amount = package.Price,
                Currency = package.Currency,
                DurationHours = package.DurationHours ?? (package.DurationDays.HasValue ? package.DurationDays.Value * 24 : null),
                QuotaGB = package.QuotaGB,
                Status = "Pending"
            };

            _dbContext.PaymentTransactions.Add(transaction);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Transaction created: {TransactionId}", transaction.TransactionId);

            try
            {
                // Add quota to guest
                await _quotaService.AddPaidQuotaAsync(guest, package);
                _logger.LogInformation("Quota added to guest. New total: {Total}GB", guest.TotalQuotaGB);

                // Try to post charge to PMS
                var pmsSettings = await _dbContext.PmsSettings.FirstOrDefaultAsync();
                
                if (pmsSettings?.IsEnabled == true && pmsSettings.AutoPostCharges)
                {
                    _logger.LogInformation("PMS auto-posting enabled. Posting by {Mode}...", 
                        pmsSettings.PostByReservationNumber ? "Reservation Number" : "Room Number");
                    
                    if (_fiasServer.IsConnected)
                    {
                        try
                        {
                            var description = $"WiFi: {package.Name}";
                            await _fiasServer.PostChargeAsync(
                                guest.RoomNumber,
                                guest.ReservationNumber,
                                package.Price,
                                description,
                                pmsSettings.PostByReservationNumber);

                            transaction.PostedToPMS = true;
                            transaction.PostedToPMSAt = DateTime.UtcNow;
                            transaction.Status = "PostedToPMS";
                            transaction.PMSPostingId = Guid.NewGuid().ToString("N")[..16];
                            transaction.PMSResponse = pmsSettings.PostByReservationNumber 
                                ? $"Success (by Reservation# {guest.ReservationNumber})" 
                                : $"Success (by Room {guest.RoomNumber})";

                            _logger.LogInformation("✓ Charge posted to PMS successfully: {Identifier}, Amount {Currency} {Amount}",
                                pmsSettings.PostByReservationNumber ? $"Reservation# {guest.ReservationNumber}" : $"Room {guest.RoomNumber}",
                                package.Currency, package.Price);
                        }
                        catch (Exception pmsEx)
                        {
                            _logger.LogWarning(pmsEx, "Failed to post to PMS (will retry later): {Error}", pmsEx.Message);
                            transaction.Status = "Completed";
                            transaction.PMSResponse = $"Failed: {pmsEx.Message}";
                            // Don't fail the purchase, just mark as not posted
                        }
                    }
                    else
                    {
                        _logger.LogWarning("PMS not connected. Charge will need to be posted manually.");
                        transaction.Status = "Completed";
                        transaction.PMSResponse = "Not connected to PMS";
                    }
                }
                else
                {
                    transaction.Status = "Completed";
                    _logger.LogInformation("PMS auto-posting disabled. Transaction completed without PMS posting.");
                }

                transaction.CompletedAt = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync();

                // Log the transaction
                _dbContext.SystemLogs.Add(new SystemLog
                {
                    Level = "INFO",
                    Category = "Payment",
                    Source = "PaymentService",
                    Message = $"Package purchased: {package.Name} for Room {guest.RoomNumber}",
                    Details = $"Amount: {package.Currency} {package.Price}, TransactionId: {transaction.TransactionId}, PostedToPMS: {transaction.PostedToPMS}"
                });
                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("=== Purchase Complete ===");
                return (true, transaction, null);
            }
            catch (Exception ex)
            {
                transaction.Status = "Failed";
                transaction.PMSResponse = $"Error: {ex.Message}";
                await _dbContext.SaveChangesAsync();

                _logger.LogError(ex, "Payment processing failed for guest {GuestId}", guestId);
                return (false, transaction, "Payment processing failed. Please contact reception.");
            }
        }

        public async Task<List<PaymentTransaction>> GetGuestTransactionsAsync(int guestId)
        {
            return await _dbContext.PaymentTransactions
                .Include(t => t.PaidPackage)
                .Where(t => t.GuestId == guestId)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();
        }

        public async Task<List<PaymentTransaction>> GetRecentTransactionsAsync(int count = 50)
        {
            return await _dbContext.PaymentTransactions
                .Include(t => t.Guest)
                .Include(t => t.PaidPackage)
                .OrderByDescending(t => t.CreatedAt)
                .Take(count)
                .ToListAsync();
        }

        public async Task<bool> RetryPmsPostingAsync(int transactionId)
        {
            var transaction = await _dbContext.PaymentTransactions
                .Include(t => t.Guest)
                .Include(t => t.PaidPackage)
                .FirstOrDefaultAsync(t => t.Id == transactionId);

            if (transaction == null || transaction.PostedToPMS)
                return false;

            if (!_fiasServer.IsConnected)
            {
                _logger.LogWarning("Cannot retry PMS posting - not connected");
                return false;
            }

            try
            {
                await _fiasServer.PostChargeAsync(
                    transaction.RoomNumber,
                    transaction.ReservationNumber,
                    transaction.Amount,
                    $"WiFi: {transaction.PackageName}");

                transaction.PostedToPMS = true;
                transaction.PostedToPMSAt = DateTime.UtcNow;
                transaction.Status = "PostedToPMS";
                transaction.PMSPostingId = Guid.NewGuid().ToString("N")[..16];
                transaction.PMSResponse = "Success (retry)";
                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("Successfully retried PMS posting for transaction {Id}", transactionId);
                return true;
            }
            catch (Exception ex)
            {
                transaction.PMSResponse = $"Retry failed: {ex.Message}";
                await _dbContext.SaveChangesAsync();
                
                _logger.LogError(ex, "Failed to retry PMS posting for transaction {Id}", transactionId);
                return false;
            }
        }

        public async Task<(decimal TotalRevenue, int TotalTransactions)> GetRevenueStatsAsync(DateTime? from = null, DateTime? to = null)
        {
            var query = _dbContext.PaymentTransactions
                .Where(t => t.Status == "Completed" || t.Status == "PostedToPMS");

            if (from.HasValue)
                query = query.Where(t => t.CreatedAt >= from.Value);
            if (to.HasValue)
                query = query.Where(t => t.CreatedAt <= to.Value);

            // Use ToListAsync and compute on client side for SQLite compatibility
            var transactions = await query.ToListAsync();
            var totalRevenue = transactions.Sum(t => t.Amount);
            var totalCount = transactions.Count;

            return (totalRevenue, totalCount);
        }

        /// <summary>
        /// Get pending transactions that need to be posted to PMS
        /// </summary>
        public async Task<List<PaymentTransaction>> GetPendingPmsPostingsAsync()
        {
            return await _dbContext.PaymentTransactions
                .Where(t => !t.PostedToPMS && (t.Status == "Completed" || t.Status == "PostedToPMS"))
                .OrderBy(t => t.CreatedAt)
                .ToListAsync();
        }

        /// <summary>
        /// Attempt to post all pending transactions to PMS
        /// </summary>
        public async Task<(int Posted, int Failed)> PostAllPendingToPmsAsync()
        {
            var pending = await GetPendingPmsPostingsAsync();
            int posted = 0;
            int failed = 0;

            if (!_fiasServer.IsConnected)
            {
                _logger.LogWarning("Cannot post to PMS - not connected");
                return (0, pending.Count);
            }

            foreach (var transaction in pending)
            {
                try
                {
                    await _fiasServer.PostChargeAsync(
                        transaction.RoomNumber,
                        transaction.ReservationNumber,
                        transaction.Amount,
                        $"WiFi: {transaction.PackageName}");

                    transaction.PostedToPMS = true;
                    transaction.PostedToPMSAt = DateTime.UtcNow;
                    transaction.Status = "PostedToPMS";
                    transaction.PMSPostingId = Guid.NewGuid().ToString("N")[..16];
                    transaction.PMSResponse = "Success (batch)";
                    posted++;

                    _logger.LogInformation("Posted transaction {Id} to PMS: Room {Room}, Amount {Amount}",
                        transaction.Id, transaction.RoomNumber, transaction.Amount);
                }
                catch (Exception ex)
                {
                    transaction.PMSResponse = $"Batch failed: {ex.Message}";
                    failed++;
                    _logger.LogError(ex, "Failed to post transaction {Id} to PMS", transaction.Id);
                }
            }

            await _dbContext.SaveChangesAsync();
            return (posted, failed);
        }
    }
}
