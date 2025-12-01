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

            try
            {
                // Add quota to guest
                await _quotaService.AddPaidQuotaAsync(guest, package);

                // Post charge to PMS
                var pmsSettings = await _dbContext.PmsSettings.FirstOrDefaultAsync();
                if (pmsSettings?.IsEnabled == true && pmsSettings.AutoPostCharges && _fiasServer.IsConnected)
                {
                    var description = $"WiFi: {package.Name}";
                    await _fiasServer.PostChargeAsync(
                        guest.RoomNumber,
                        guest.ReservationNumber,
                        package.Price,
                        description);

                    transaction.PostedToPMS = true;
                    transaction.PostedToPMSAt = DateTime.UtcNow;
                    transaction.Status = "PostedToPMS";

                    _logger.LogInformation("Charge posted to PMS: Room {Room}, Amount {Amount}, Package {Package}",
                        guest.RoomNumber, package.Price, package.Name);
                }
                else
                {
                    transaction.Status = "Completed";
                    _logger.LogInformation("Package purchased (PMS posting disabled): Room {Room}, Package {Package}",
                        guest.RoomNumber, package.Name);
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
                    Details = $"Amount: {package.Currency} {package.Price}, TransactionId: {transaction.TransactionId}"
                });
                await _dbContext.SaveChangesAsync();

                return (true, transaction, null);
            }
            catch (Exception ex)
            {
                transaction.Status = "Failed";
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
                return false;

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
                await _dbContext.SaveChangesAsync();

                return true;
            }
            catch (Exception ex)
            {
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
    }
}
