using HotelWifiPortal.Data;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services;
using HotelWifiPortal.Services.WiFi;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Portal
{
    public class PortalController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly AuthService _authService;
        private readonly QuotaService _quotaService;
        private readonly PaymentService _paymentService;
        private readonly WifiService _wifiService;
        private readonly ILogger<PortalController> _logger;

        public PortalController(
            ApplicationDbContext dbContext,
            AuthService authService,
            QuotaService quotaService,
            PaymentService paymentService,
            WifiService wifiService,
            ILogger<PortalController> logger)
        {
            _dbContext = dbContext;
            _authService = authService;
            _quotaService = quotaService;
            _paymentService = paymentService;
            _wifiService = wifiService;
            _logger = logger;
        }

        // Captive portal entry point - redirects here when connecting to WiFi
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Index(string? mac, string? url, string? ssid)
        {
            // Store MAC address in session for later use
            if (!string.IsNullOrEmpty(mac))
            {
                HttpContext.Session.SetString("MacAddress", mac);
            }

            // Check if user is already authenticated
            if (User.Identity?.IsAuthenticated == true && User.IsInRole("Guest"))
            {
                return RedirectToAction(nameof(Dashboard));
            }

            // Get hotel settings for display
            var hotelName = await _dbContext.SystemSettings
                .Where(s => s.Key == "HotelName")
                .Select(s => s.Value)
                .FirstOrDefaultAsync() ?? "Hotel";

            var welcomeMessage = await _dbContext.SystemSettings
                .Where(s => s.Key == "WelcomeMessage")
                .Select(s => s.Value)
                .FirstOrDefaultAsync();

            ViewBag.HotelName = hotelName;
            ViewBag.WelcomeMessage = welcomeMessage;
            ViewBag.SSID = ssid;

            var model = new GuestLoginViewModel
            {
                MacAddress = mac,
                ReturnUrl = url
            };

            return View("Login", model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(GuestLoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Try PMS authentication first
            var (success, guest, error) = await _authService.AuthenticateGuestAsync(model.RoomNumber, model.Password);

            if (!success)
            {
                // Try standalone mode if enabled
                if (await _authService.IsStandaloneModeEnabledAsync())
                {
                    var (localSuccess, localUser, localError) = await _authService.AuthenticateLocalUserAsync(model.RoomNumber, model.Password);
                    if (localSuccess && localUser != null)
                    {
                        var localPrincipal = _authService.CreateLocalUserPrincipal(localUser);
                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, localPrincipal,
                            new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7) });
                        
                        return RedirectToAction(nameof(Dashboard));
                    }
                }

                model.ErrorMessage = error ?? "Authentication failed.";
                return View(model);
            }

            // Create authentication cookie
            var principal = _authService.CreateGuestPrincipal(guest!);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                });

            // Authenticate with WiFi controller
            var macAddress = model.MacAddress ?? HttpContext.Session.GetString("MacAddress");
            if (!string.IsNullOrEmpty(macAddress))
            {
                await _wifiService.AuthenticateGuestAsync(guest!, macAddress);
            }

            _logger.LogInformation("Guest logged in: Room {Room}, MAC {Mac}", model.RoomNumber, macAddress);

            // Redirect to original URL or dashboard
            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction(nameof(Dashboard));
        }

        [Authorize(Roles = "Guest,LocalUser")]
        public async Task<IActionResult> Dashboard()
        {
            var guestId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "0");
            var guest = await _dbContext.Guests
                .FirstOrDefaultAsync(g => g.Id == guestId);

            if (guest == null)
            {
                return RedirectToAction(nameof(Index));
            }

            var currentPackage = await _quotaService.GetPackageForStayLengthAsync(guest.StayLength);
            var activeSessions = await _wifiService.GetGuestSessionsAsync(guestId);
            var availablePackages = await _quotaService.GetActivePaidPackagesAsync();

            var model = new GuestDashboardViewModel
            {
                Guest = guest,
                CurrentPackage = currentPackage,
                UsedQuotaGB = guest.UsedQuotaGB,
                TotalQuotaGB = guest.TotalQuotaGB,
                RemainingQuotaGB = guest.RemainingQuotaGB,
                UsagePercentage = guest.TotalQuotaBytes > 0 
                    ? (int)((guest.UsedQuotaBytes * 100) / guest.TotalQuotaBytes) 
                    : 0,
                IsQuotaExhausted = guest.IsQuotaExhausted,
                ActiveSessions = activeSessions.Where(s => s.Status == "Active").ToList(),
                AvailablePackages = availablePackages
            };

            // If quota exhausted, redirect to paywall
            if (guest.IsQuotaExhausted && !guest.HasPurchasedPackage)
            {
                return RedirectToAction(nameof(Paywall));
            }

            return View(model);
        }

        [Authorize(Roles = "Guest,LocalUser")]
        public async Task<IActionResult> Paywall()
        {
            var guestId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "0");
            var guest = await _dbContext.Guests.FindAsync(guestId);

            if (guest == null)
            {
                return RedirectToAction(nameof(Index));
            }

            var availablePackages = await _quotaService.GetActivePaidPackagesAsync();

            var model = new PaywallViewModel
            {
                Guest = guest,
                UsedQuotaGB = guest.UsedQuotaGB,
                AvailablePackages = availablePackages
            };

            return View(model);
        }

        [HttpPost]
        [Authorize(Roles = "Guest,LocalUser")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> PurchasePackage(int packageId)
        {
            var guestId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "0");

            var (success, transaction, error) = await _paymentService.PurchasePackageAsync(guestId, packageId);

            if (!success)
            {
                TempData["Error"] = error ?? "Purchase failed.";
                return RedirectToAction(nameof(Paywall));
            }

            TempData["Success"] = "Package purchased successfully! Your quota has been updated.";
            return RedirectToAction(nameof(PurchaseConfirm), new { transactionId = transaction!.Id });
        }

        [Authorize(Roles = "Guest,LocalUser")]
        public async Task<IActionResult> PurchaseConfirm(int transactionId)
        {
            var transaction = await _dbContext.PaymentTransactions
                .Include(t => t.Guest)
                .Include(t => t.PaidPackage)
                .FirstOrDefaultAsync(t => t.Id == transactionId);

            if (transaction == null)
            {
                return RedirectToAction(nameof(Dashboard));
            }

            var model = new PurchaseConfirmViewModel
            {
                Guest = transaction.Guest!,
                Package = transaction.PaidPackage!,
                Transaction = transaction
            };

            return View(model);
        }

        [Authorize(Roles = "Guest,LocalUser")]
        public async Task<IActionResult> Usage()
        {
            var guestId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "0");
            
            var sessions = await _dbContext.WifiSessions
                .Where(s => s.GuestId == guestId)
                .OrderByDescending(s => s.SessionStart)
                .ToListAsync();

            var transactions = await _paymentService.GetGuestTransactionsAsync(guestId);

            ViewBag.Sessions = sessions;
            ViewBag.Transactions = transactions;

            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Guest,LocalUser")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction(nameof(Index));
        }

        // Success page after WiFi authentication
        [Authorize(Roles = "Guest,LocalUser")]
        public IActionResult Success(string? returnUrl)
        {
            if (!string.IsNullOrEmpty(returnUrl))
            {
                // Redirect to original URL after short delay (handled by view)
                ViewBag.ReturnUrl = returnUrl;
            }

            return View();
        }

        // Error page
        [AllowAnonymous]
        public IActionResult Error(string? message)
        {
            ViewBag.ErrorMessage = message ?? "An error occurred.";
            return View();
        }
    }
}
