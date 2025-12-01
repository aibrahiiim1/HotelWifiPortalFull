using HotelWifiPortal.Data;
using HotelWifiPortal.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;

namespace HotelWifiPortal.Controllers.Admin
{
    [Route("Admin/[controller]/[action]")]
    [Authorize(Roles = "Admin,SuperAdmin,Manager,Viewer")]
    public class LogsController : Controller
    {
        private readonly ApplicationDbContext _dbContext;

        public LogsController(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<IActionResult> Index(string? level, string? category, DateTime? from, DateTime? to, string? search, int page = 1)
        {
            var query = _dbContext.SystemLogs.AsQueryable();

            if (!string.IsNullOrEmpty(level))
            {
                query = query.Where(l => l.Level == level);
            }

            if (!string.IsNullOrEmpty(category))
            {
                query = query.Where(l => l.Category == category);
            }

            if (from.HasValue)
            {
                query = query.Where(l => l.Timestamp >= from.Value);
            }

            if (to.HasValue)
            {
                query = query.Where(l => l.Timestamp <= to.Value.AddDays(1));
            }

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(l => l.Message.Contains(search) || (l.Details != null && l.Details.Contains(search)));
            }

            var totalCount = await query.CountAsync();
            var pageSize = 50;

            var logs = await query
                .OrderByDescending(l => l.Timestamp)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var model = new LogsViewModel
            {
                Logs = logs,
                LevelFilter = level,
                CategoryFilter = category,
                FromDate = from,
                ToDate = to,
                SearchTerm = search,
                TotalCount = totalCount,
                PageNumber = page,
                PageSize = pageSize
            };

            // Get distinct categories for filter
            ViewBag.Categories = await _dbContext.SystemLogs
                .Where(l => l.Category != null)
                .Select(l => l.Category)
                .Distinct()
                .OrderBy(c => c)
                .ToListAsync();

            return View(model);
        }

        public async Task<IActionResult> Details(int id)
        {
            var log = await _dbContext.SystemLogs.FindAsync(id);
            if (log == null)
            {
                return NotFound();
            }

            return View(log);
        }

        [HttpGet]
        public async Task<IActionResult> Export(string? level, string? category, DateTime? from, DateTime? to)
        {
            var query = _dbContext.SystemLogs.AsQueryable();

            if (!string.IsNullOrEmpty(level))
                query = query.Where(l => l.Level == level);

            if (!string.IsNullOrEmpty(category))
                query = query.Where(l => l.Category == category);

            if (from.HasValue)
                query = query.Where(l => l.Timestamp >= from.Value);

            if (to.HasValue)
                query = query.Where(l => l.Timestamp <= to.Value.AddDays(1));

            var logs = await query
                .OrderByDescending(l => l.Timestamp)
                .Take(10000) // Limit export
                .ToListAsync();

            var csv = new StringBuilder();
            csv.AppendLine("Timestamp,Level,Category,Source,Message,Details");

            foreach (var log in logs)
            {
                var message = log.Message.Replace("\"", "\"\"");
                var details = (log.Details ?? "").Replace("\"", "\"\"");
                csv.AppendLine($"\"{log.Timestamp:yyyy-MM-dd HH:mm:ss}\",\"{log.Level}\",\"{log.Category}\",\"{log.Source}\",\"{message}\",\"{details}\"");
            }

            var bytes = Encoding.UTF8.GetBytes(csv.ToString());
            return File(bytes, "text/csv", $"logs-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin,SuperAdmin")]
        public async Task<IActionResult> Clear(int? keepDays)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-(keepDays ?? 30));
            
            var oldLogs = await _dbContext.SystemLogs
                .Where(l => l.Timestamp < cutoffDate)
                .ToListAsync();

            _dbContext.SystemLogs.RemoveRange(oldLogs);
            await _dbContext.SaveChangesAsync();

            TempData["Success"] = $"Cleared {oldLogs.Count} log entries older than {keepDays ?? 30} days.";
            return RedirectToAction(nameof(Index));
        }

        // Transactions Log
        public async Task<IActionResult> Transactions(DateTime? from, DateTime? to, string? status, int page = 1)
        {
            var query = _dbContext.PaymentTransactions
                .Include(t => t.Guest)
                .Include(t => t.PaidPackage)
                .AsQueryable();

            if (from.HasValue)
            {
                query = query.Where(t => t.CreatedAt >= from.Value);
            }

            if (to.HasValue)
            {
                query = query.Where(t => t.CreatedAt <= to.Value.AddDays(1));
            }

            if (!string.IsNullOrEmpty(status))
            {
                query = query.Where(t => t.Status == status);
            }

            var totalCount = await query.CountAsync();
            var pageSize = 50;

            var transactions = await query
                .OrderByDescending(t => t.CreatedAt)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.FromDate = from;
            ViewBag.ToDate = to;
            ViewBag.StatusFilter = status;
            ViewBag.TotalCount = totalCount;
            ViewBag.PageNumber = page;
            ViewBag.PageSize = pageSize;

            return View(transactions);
        }

        // Usage Logs
        public async Task<IActionResult> Usage(DateTime? from, DateTime? to, string? room, int page = 1)
        {
            var query = _dbContext.UsageLogs
                .Include(u => u.Guest)
                .AsQueryable();

            if (from.HasValue)
            {
                query = query.Where(u => u.PeriodStart >= from.Value);
            }

            if (to.HasValue)
            {
                query = query.Where(u => u.PeriodEnd <= to.Value.AddDays(1));
            }

            if (!string.IsNullOrEmpty(room))
            {
                query = query.Where(u => u.RoomNumber == room);
            }

            var totalCount = await query.CountAsync();
            var pageSize = 50;

            var logs = await query
                .OrderByDescending(u => u.PeriodStart)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            ViewBag.FromDate = from;
            ViewBag.ToDate = to;
            ViewBag.RoomFilter = room;
            ViewBag.TotalCount = totalCount;
            ViewBag.PageNumber = page;
            ViewBag.PageSize = pageSize;

            return View(logs);
        }
    }
}
