using HotelWifiPortal.Data;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services;
using HotelWifiPortal.Services.PMS;
using HotelWifiPortal.Services.WiFi;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Admin
{
    [Route("Admin/[controller]/[action]")]
    public class DashboardController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly AuthService _authService;
        private readonly FiasSocketServer _fiasServer;
        private readonly PaymentService _paymentService;
        private readonly ILogger<DashboardController> _logger;

        public DashboardController(
            ApplicationDbContext dbContext,
            AuthService authService,
            FiasSocketServer fiasServer,
            PaymentService paymentService,
            ILogger<DashboardController> logger)
        {
            _dbContext = dbContext;
            _authService = authService;
            _fiasServer = fiasServer;
            _paymentService = paymentService;
            _logger = logger;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl)
        {
            if (User.Identity?.IsAuthenticated == true && (User.IsInRole("Admin") || User.IsInRole("SuperAdmin")))
            {
                return RedirectToAction(nameof(Index));
            }

            return View(new AdminLoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(AdminLoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var (success, user, error) = await _authService.AuthenticateAdminAsync(model.Username, model.Password);

            if (!success)
            {
                model.ErrorMessage = error;
                return View(model);
            }

            var principal = _authService.CreateAdminPrincipal(user!);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal,
                new AuthenticationProperties
                {
                    IsPersistent = model.RememberMe,
                    ExpiresUtc = model.RememberMe ? DateTimeOffset.UtcNow.AddDays(30) : DateTimeOffset.UtcNow.AddHours(8)
                });

            _logger.LogInformation("Admin logged in: {Username}", model.Username);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [Authorize(Roles = "Admin,SuperAdmin,Manager,Viewer")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction(nameof(Login));
        }

        [Authorize(Roles = "Admin,SuperAdmin,Manager,Viewer")]
        public async Task<IActionResult> Index()
        {
            var today = DateTime.Today;
            var monthStart = new DateTime(today.Year, today.Month, 1);

            var pmsStatus = _fiasServer.GetStatus();
            var (todayRevenue, _) = await _paymentService.GetRevenueStatsAsync(today, today.AddDays(1));
            var (monthRevenue, _) = await _paymentService.GetRevenueStatsAsync(monthStart, today.AddDays(1));

            var wifiControllers = await _dbContext.WifiControllerSettings
                .Where(w => w.IsEnabled)
                .Select(w => new WifiControllerStatus
                {
                    Name = w.Name,
                    Type = w.ControllerType,
                    IsEnabled = w.IsEnabled,
                    Status = w.ConnectionStatus ?? "unknown"
                })
                .ToListAsync();

            var model = new AdminDashboardViewModel
            {
                TotalGuests = await _dbContext.Guests.CountAsync(),
                CheckedInGuests = await _dbContext.Guests.CountAsync(g => g.Status == "checked-in"),
                ActiveSessions = await _dbContext.WifiSessions.CountAsync(s => s.Status == "Active"),
                TodayRevenue = todayRevenue,
                MonthRevenue = monthRevenue,

                PmsConnected = pmsStatus.IsConnected,
                PmsStatus = pmsStatus.Status,
                MessagesSent = pmsStatus.MessagesSent,
                MessagesReceived = pmsStatus.MessagesReceived,

                WifiControllers = wifiControllers,

                RecentGuests = await _dbContext.Guests
                    .OrderByDescending(g => g.UpdatedAt)
                    .Take(5)
                    .ToListAsync(),

                RecentSessions = await _dbContext.WifiSessions
                    .Include(s => s.Guest)
                    .OrderByDescending(s => s.SessionStart)
                    .Take(10)
                    .ToListAsync(),

                RecentTransactions = await _dbContext.PaymentTransactions
                    .Include(t => t.Guest)
                    .OrderByDescending(t => t.CreatedAt)
                    .Take(5)
                    .ToListAsync(),

                RecentLogs = await _dbContext.SystemLogs
                    .OrderByDescending(l => l.Timestamp)
                    .Take(10)
                    .ToListAsync()
            };

            return View(model);
        }
    }
}
