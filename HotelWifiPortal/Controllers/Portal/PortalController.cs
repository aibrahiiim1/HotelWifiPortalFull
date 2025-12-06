using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services;
using HotelWifiPortal.Services.Radius;
using HotelWifiPortal.Services.WiFi;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Portal
{
    /// <summary>
    /// Guest-facing captive portal controller
    /// All routes are under /Portal/
    /// </summary>
    [Route("Portal")]
    public class PortalController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly AuthService _authService;
        private readonly QuotaService _quotaService;
        private readonly PaymentService _paymentService;
        private readonly WifiService _wifiService;
        private readonly MikrotikAuthService _mikrotikAuth;
        private readonly ILogger<PortalController> _logger;

        public PortalController(
            ApplicationDbContext dbContext,
            AuthService authService,
            QuotaService quotaService,
            PaymentService paymentService,
            WifiService wifiService,
            MikrotikAuthService mikrotikAuth,
            ILogger<PortalController> logger)
        {
            _dbContext = dbContext;
            _authService = authService;
            _quotaService = quotaService;
            _paymentService = paymentService;
            _wifiService = wifiService;
            _mikrotikAuth = mikrotikAuth;
            _logger = logger;
        }

        // Captive portal entry point - MikroTik/Ruckus redirects here
        [HttpGet]
        [HttpGet("Index")]
        [Route("")]
        [AllowAnonymous]
        public async Task<IActionResult> Index(
            // MikroTik parameters
            string? mac,           // MAC address from MikroTik
            string? ip,            // Client IP from MikroTik
            string? username,      // Pre-filled username
            string? url,           // Original URL (dst)
            string? ssid,          // SSID name
            [FromQuery(Name = "link-login")] string? linkLogin,      // MikroTik login URL
            [FromQuery(Name = "link-orig")] string? linkOrig,        // Original destination
            [FromQuery(Name = "link-login-only")] string? linkLoginOnly,
            // Ruckus ZoneDirector WISPr parameters
            [FromQuery(Name = "client_mac")] string? clientMac,      // Ruckus client MAC
            [FromQuery(Name = "client_ip")] string? clientIp,        // Ruckus client IP
            [FromQuery(Name = "uamip")] string? uamIp,               // Ruckus controller IP
            [FromQuery(Name = "uamport")] string? uamPort,           // Ruckus UAM port
            [FromQuery(Name = "sip")] string? sip,                   // Ruckus client IP (alternate)
            [FromQuery(Name = "called")] string? called,             // Called station ID
            [FromQuery(Name = "nasid")] string? nasId,               // NAS ID
            [FromQuery(Name = "userurl")] string? userUrl,           // Original user URL (Ruckus)
            [FromQuery(Name = "challenge")] string? challenge,       // WISPr challenge
            string? error)         // Error from previous attempt
        {
            // Normalize parameters - prefer Ruckus format if available
            var macAddress = mac ?? clientMac;
            var clientIpAddress = ip ?? clientIp ?? sip;
            var originalUrl = url ?? linkOrig ?? userUrl;

            // Log all incoming parameters for debugging
            _logger.LogInformation("=== Portal Access ===");
            _logger.LogInformation("MAC: {Mac}", macAddress ?? "none");
            _logger.LogInformation("IP: {Ip}", clientIpAddress ?? Request.HttpContext.Connection.RemoteIpAddress?.ToString());
            _logger.LogInformation("Username: {Username}", username ?? "none");
            _logger.LogInformation("URL/Dst: {Url}", originalUrl ?? "none");
            _logger.LogInformation("SSID: {Ssid}", ssid ?? "none");
            _logger.LogInformation("Link-Login: {LinkLogin}", linkLogin ?? "none");
            _logger.LogInformation("UAM IP: {UamIp}", uamIp ?? "none");
            _logger.LogInformation("Challenge: {Challenge}", challenge ?? "none");
            _logger.LogInformation("Error: {Error}", error ?? "none");
            _logger.LogInformation("User-Agent: {UA}", Request.Headers["User-Agent"].ToString());
            _logger.LogInformation("Full Query: {Query}", Request.QueryString.ToString());

            // Store parameters in session for later use
            if (!string.IsNullOrEmpty(macAddress))
                HttpContext.Session.SetString("MacAddress", macAddress);
            if (!string.IsNullOrEmpty(clientIpAddress))
                HttpContext.Session.SetString("ClientIp", clientIpAddress);
            if (!string.IsNullOrEmpty(linkLogin))
                HttpContext.Session.SetString("LinkLogin", linkLogin);
            if (!string.IsNullOrEmpty(originalUrl))
            {
                HttpContext.Session.SetString("LinkOrig", originalUrl);
                HttpContext.Session.SetString("OriginalUrl", originalUrl);
            }
            if (!string.IsNullOrEmpty(uamIp))
                HttpContext.Session.SetString("UamIp", uamIp);
            if (!string.IsNullOrEmpty(uamPort))
                HttpContext.Session.SetString("UamPort", uamPort);
            if (!string.IsNullOrEmpty(challenge))
                HttpContext.Session.SetString("WisprChallenge", challenge);

            // Check if user is already authenticated
            if (User.Identity?.IsAuthenticated == true && User.IsInRole("Guest"))
            {
                _logger.LogInformation("User already authenticated, redirecting to dashboard");
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
            ViewBag.Error = error;

            var model = new GuestLoginViewModel
            {
                MacAddress = macAddress,
                ClientIp = clientIpAddress ?? Request.HttpContext.Connection.RemoteIpAddress?.ToString(),
                ReturnUrl = originalUrl,
                LinkLogin = linkLogin,
                LinkOrig = linkOrig ?? originalUrl
            };

            _logger.LogInformation("Model LinkLogin: {LinkLogin}", model.LinkLogin ?? "null");
            _logger.LogInformation("Model LinkOrig: {LinkOrig}", model.LinkOrig ?? "null");

            return View("Login", model);
        }

        [HttpPost("Login")]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(GuestLoginViewModel model)
        {
            _logger.LogInformation("=== Login Attempt ===");
            _logger.LogInformation("Room: {Room}", model.RoomNumber);
            _logger.LogInformation("MAC: {Mac}", model.MacAddress ?? HttpContext.Session.GetString("MacAddress"));
            _logger.LogInformation("IP: {Ip}", model.ClientIp ?? HttpContext.Session.GetString("ClientIp"));

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model state invalid");
                return View(model);
            }

            // Try PMS authentication first
            var (success, guest, error) = await _authService.AuthenticateGuestAsync(model.RoomNumber, model.Password);

            if (!success)
            {
                _logger.LogWarning("PMS authentication failed: {Error}", error);

                // Try standalone mode if enabled
                if (await _authService.IsStandaloneModeEnabledAsync())
                {
                    var (localSuccess, localUser, localError) = await _authService.AuthenticateLocalUserAsync(model.RoomNumber, model.Password);
                    if (localSuccess && localUser != null)
                    {
                        _logger.LogInformation("Local user authenticated: {User}", localUser.Username);

                        var localPrincipal = _authService.CreateLocalUserPrincipal(localUser);
                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, localPrincipal,
                            new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7) });

                        // Try Ruckus WISPr auth for local users too
                        var localWisprResult = await TryRuckusWisprAuthAsync(localUser.Username, model.Password);
                        if (localWisprResult != null)
                            return localWisprResult;

                        return RedirectToAction(nameof(Dashboard));
                    }
                }

                model.ErrorMessage = error ?? "Invalid room number or password.";
                _logger.LogWarning("Authentication failed for room {Room}: {Error}", model.RoomNumber, model.ErrorMessage);
                return View(model);
            }

            _logger.LogInformation("Guest authenticated locally: Room={Room}, Name={Name}", guest!.RoomNumber, guest.GuestName);

            // Get client info from model or session
            var macAddress = model.MacAddress ?? HttpContext.Session.GetString("MacAddress");
            var clientIp = model.ClientIp ?? HttpContext.Session.GetString("ClientIp")
                ?? Request.HttpContext.Connection.RemoteIpAddress?.ToString();
            var linkLogin = model.LinkLogin ?? HttpContext.Session.GetString("LinkLogin");
            var linkOrig = model.ReturnUrl ?? model.LinkOrig ?? HttpContext.Session.GetString("LinkOrig")
                ?? HttpContext.Session.GetString("OriginalUrl");
            var uamIp = HttpContext.Session.GetString("UamIp");
            var uamPort = HttpContext.Session.GetString("UamPort");

            _logger.LogInformation("=== Starting WiFi Authentication ===");
            _logger.LogInformation("MAC: {Mac}", macAddress);
            _logger.LogInformation("Client IP: {Ip}", clientIp);
            _logger.LogInformation("Link-Login: {LinkLogin}", linkLogin ?? "null");
            _logger.LogInformation("Link-Orig: {LinkOrig}", linkOrig ?? "null");

            // ============================================
            // CHECK FOR MIKROTIK EXTERNAL PORTAL FIRST
            // If link-login is present, we MUST redirect back to MikroTik
            // ============================================
            if (!string.IsNullOrEmpty(linkLogin))
            {
                _logger.LogInformation("=== MikroTik External Portal Mode ===");
                _logger.LogInformation("Redirecting to MikroTik with credentials...");

                // Build the redirect URL back to MikroTik
                var mikrotikLoginUrl = linkLogin;

                // Add credentials to the URL
                if (mikrotikLoginUrl.Contains("?"))
                {
                    mikrotikLoginUrl += $"&username={Uri.EscapeDataString(model.RoomNumber)}&password={Uri.EscapeDataString(model.Password)}";
                }
                else
                {
                    mikrotikLoginUrl += $"?username={Uri.EscapeDataString(model.RoomNumber)}&password={Uri.EscapeDataString(model.Password)}";
                }

                // Add destination if we have it
                if (!string.IsNullOrEmpty(linkOrig))
                {
                    mikrotikLoginUrl += $"&dst={Uri.EscapeDataString(linkOrig)}";
                }

                _logger.LogInformation("MikroTik Redirect URL: {Url}", mikrotikLoginUrl);

                // Create authentication cookie for our portal
                var mikrotikPrincipal = _authService.CreateGuestPrincipal(guest);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, mikrotikPrincipal,
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                    });

                // Create WiFi session record
                if (!string.IsNullOrEmpty(macAddress))
                    await CreateWifiSessionAsync(guest, macAddress, "MikrotikExternal");

                // REDIRECT TO MIKROTIK - This is the KEY!
                // MikroTik will authenticate via RADIUS and grant internet access
                return Redirect(mikrotikLoginUrl);
            }

            // ============================================
            // RADIUS AUTHENTICATION (for non-MikroTik controllers)
            // Send Access-Request to FreeRADIUS
            // ============================================
            var radiusResult = await AuthenticateViaRadiusAsync(model.RoomNumber, model.Password, clientIp, macAddress);

            if (radiusResult.Success)
            {
                _logger.LogInformation("=== RADIUS Authentication SUCCESS ===");

                // Create authentication cookie
                var principal = _authService.CreateGuestPrincipal(guest);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                    });

                // Create WiFi session record
                if (!string.IsNullOrEmpty(macAddress))
                    await CreateWifiSessionAsync(guest, macAddress, "RADIUS");

                // Redirect to success page
                return RedirectToAction(nameof(Success), new { returnUrl = linkOrig });
            }
            else
            {
                _logger.LogWarning("=== RADIUS Authentication FAILED ===");
                _logger.LogWarning("Error: {Error}", radiusResult.Error);

                // Still create local session, but user may not have internet
                var principal = _authService.CreateGuestPrincipal(guest);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                    });

                TempData["Warning"] = $"Local authentication succeeded, but RADIUS authentication failed: {radiusResult.Error}. You may not have internet access.";
            }

            _logger.LogInformation("Link-Login: {Link}", linkLogin);
            _logger.LogInformation("Link-Orig: {Orig}", linkOrig);
            _logger.LogInformation("UAM IP: {UamIp}", uamIp);
            _logger.LogInformation("UAM Port: {UamPort}", uamPort);

            // Detect which controller is being used based on parameters and settings
            var activeController = await DetectActiveControllerAsync(linkLogin, uamIp);
            _logger.LogInformation("Detected active controller: {Controller}", activeController);

            // Handle based on controller type
            switch (activeController)
            {
                case "Mikrotik":
                    // MikroTik External Portal Flow
                    // The KEY is to redirect back to MikroTik's link-login URL with credentials
                    // MikroTik will then authenticate via RADIUS and grant access

                    if (!string.IsNullOrEmpty(linkLogin))
                    {
                        _logger.LogInformation("=== MikroTik External Portal Redirect ===");
                        _logger.LogInformation("Link-Login: {LinkLogin}", linkLogin);

                        // Build the redirect URL back to MikroTik
                        // MikroTik expects: link-login?username=XXX&password=XXX
                        var mikrotikLoginUrl = linkLogin;

                        // Add credentials to the URL
                        if (mikrotikLoginUrl.Contains("?"))
                        {
                            mikrotikLoginUrl += $"&username={Uri.EscapeDataString(model.RoomNumber)}&password={Uri.EscapeDataString(model.Password)}";
                        }
                        else
                        {
                            mikrotikLoginUrl += $"?username={Uri.EscapeDataString(model.RoomNumber)}&password={Uri.EscapeDataString(model.Password)}";
                        }

                        // Add destination if we have it
                        if (!string.IsNullOrEmpty(linkOrig))
                        {
                            mikrotikLoginUrl += $"&dst={Uri.EscapeDataString(linkOrig)}";
                        }

                        _logger.LogInformation("Redirecting to MikroTik: {Url}", mikrotikLoginUrl);

                        // Create WiFi session record
                        if (!string.IsNullOrEmpty(macAddress))
                            await CreateWifiSessionAsync(guest, macAddress, "MikrotikExternal");

                        // Redirect back to MikroTik - this is the KEY!
                        // MikroTik will authenticate via RADIUS and grant internet access
                        return Redirect(mikrotikLoginUrl);
                    }
                    else
                    {
                        // No link-login - try API-based authentication
                        _logger.LogWarning("No link-login URL, trying API-based auth");

                        if (!string.IsNullOrEmpty(macAddress) && !string.IsNullOrEmpty(clientIp))
                        {
                            var authMethod = await _dbContext.SystemSettings
                                .Where(s => s.Key == "MikrotikAuthMethod")
                                .Select(s => s.Value)
                                .FirstOrDefaultAsync() ?? "MacBinding";

                            var mikrotikResult = await _mikrotikAuth.AuthenticateGuestAsync(
                                guest,
                                clientIp,
                                macAddress,
                                linkLogin,
                                authMethod);

                            if (mikrotikResult.Success)
                            {
                                _logger.LogInformation("=== MikroTik API Authentication SUCCESS ===");
                                _logger.LogInformation("Method: {Method}", mikrotikResult.Method);

                                await CreateWifiSessionAsync(guest, macAddress, mikrotikResult.Method);
                                return RedirectToAction(nameof(Success), new { returnUrl = linkOrig });
                            }
                            else
                            {
                                _logger.LogWarning("MikroTik API auth failed: {Error}", mikrotikResult.Error);
                                TempData["Warning"] = $"WiFi authentication issue: {mikrotikResult.Error}";
                            }
                        }
                    }
                    break;

                case "RuckusZD":
                    // Ruckus flow - WISPr redirect
                    var wisprResult = await TryRuckusWisprAuthAsync(model.RoomNumber, model.Password);
                    if (wisprResult != null)
                    {
                        if (!string.IsNullOrEmpty(macAddress))
                            await CreateWifiSessionAsync(guest, macAddress, "RuckusWISPr");
                        return wisprResult;
                    }
                    break;

                case "RADIUS":
                default:
                    // RADIUS-only mode - already authenticated above
                    // Just redirect to success
                    break;
            }

            // Fallback: Try MikroTik if we have MAC/IP (backward compatibility)
            if (!string.IsNullOrEmpty(macAddress) && !string.IsNullOrEmpty(clientIp) && activeController != "Mikrotik")
            {
                var authMethod = await _dbContext.SystemSettings
                    .Where(s => s.Key == "MikrotikAuthMethod")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync();

                var authResult = await _mikrotikAuth.AuthenticateGuestAsync(
                    guest,
                    clientIp,
                    macAddress,
                    linkLogin,
                    authMethod);

                if (authResult.Success)
                {
                    _logger.LogInformation("=== WiFi Authentication SUCCESS ===");
                    _logger.LogInformation("Method: {Method}", authResult.Method);
                    _logger.LogInformation("Redirect: {Url}", authResult.RedirectUrl);

                    // Create WiFi session record
                    await CreateWifiSessionAsync(guest, macAddress, authResult.Method);

                    // Determine redirect
                    if (!string.IsNullOrEmpty(authResult.RedirectUrl))
                    {
                        // For HotspotLogin/HotspotUser, redirect back to MikroTik
                        if (authResult.Method == "HotspotUser" || authResult.Method == "HotspotLogin")
                        {
                            _logger.LogInformation("Redirecting to MikroTik login: {Url}", authResult.RedirectUrl);
                            return Redirect(authResult.RedirectUrl);
                        }
                    }

                    // For RADIUS/MacBinding, redirect to success page
                    // Decode and validate the return URL
                    var redirectUrl = linkOrig;
                    if (!string.IsNullOrEmpty(redirectUrl))
                    {
                        try
                        {
                            // URL decode if needed
                            redirectUrl = System.Net.WebUtility.UrlDecode(redirectUrl);

                            // Skip if it's a portal/login URL or invalid
                            if (redirectUrl.Contains("/portal", StringComparison.OrdinalIgnoreCase) ||
                                redirectUrl.Contains("/login", StringComparison.OrdinalIgnoreCase) ||
                                redirectUrl.Contains("192.168.") || // Skip internal IPs
                                !Uri.TryCreate(redirectUrl, UriKind.Absolute, out _))
                            {
                                redirectUrl = null;
                            }
                        }
                        catch
                        {
                            redirectUrl = null;
                        }
                    }

                    // Redirect to success page - guest now has internet access
                    return RedirectToAction(nameof(Success), new { returnUrl = redirectUrl });
                }
                else
                {
                    _logger.LogWarning("=== WiFi Authentication FAILED ===");
                    _logger.LogWarning("Method: {Method}, Error: {Error}", authResult.Method, authResult.Error);

                    // Still allow dashboard access but warn user
                    TempData["Warning"] = "WiFi authentication had issues. You may need to reconnect to the network.";
                }
            }
            else
            {
                // No MAC/IP - this is likely a RADIUS-based setup where the controller handles auth
                // The guest authenticated via the portal, so they should have access now
                _logger.LogInformation("No MAC/IP provided - assuming RADIUS controller handles access");
                return RedirectToAction(nameof(Success));
            }

            // Redirect to dashboard as fallback
            return RedirectToAction(nameof(Dashboard));
        }

        /// <summary>
        /// Detect which WiFi controller is active based on parameters and settings
        /// </summary>
        private async Task<string> DetectActiveControllerAsync(string? linkLogin, string? uamIp)
        {
            // Check for MikroTik-specific parameters
            if (!string.IsNullOrEmpty(linkLogin) && linkLogin.Contains("/login"))
            {
                _logger.LogDebug("Detected MikroTik from link-login parameter");
                return "Mikrotik";
            }

            // Check for Ruckus-specific parameters
            if (!string.IsNullOrEmpty(uamIp))
            {
                _logger.LogDebug("Detected RuckusZD from uamip parameter");
                return "RuckusZD";
            }

            // Check what controllers are enabled in the database
            var enabledControllers = await _dbContext.WifiControllerSettings
                .Where(c => c.IsEnabled)
                .Select(c => new { c.ControllerType, c.IsDefault })
                .ToListAsync();

            // Return the default controller if one is set
            var defaultController = enabledControllers.FirstOrDefault(c => c.IsDefault);
            if (defaultController != null)
            {
                _logger.LogDebug("Using default controller: {Controller}", defaultController.ControllerType);
                return defaultController.ControllerType;
            }

            // Return the first enabled controller
            var firstEnabled = enabledControllers.FirstOrDefault();
            if (firstEnabled != null)
            {
                _logger.LogDebug("Using first enabled controller: {Controller}", firstEnabled.ControllerType);
                return firstEnabled.ControllerType;
            }

            // Default to RADIUS-only mode
            _logger.LogDebug("No controller configured, using RADIUS-only mode");
            return "RADIUS";
        }

        /// <summary>
        /// Authenticate user via RADIUS - sends Access-Request to FreeRADIUS
        /// This is the key method that tells the network the user is authenticated!
        /// </summary>
        private async Task<RadiusAuthResult> AuthenticateViaRadiusAsync(
            string username,
            string password,
            string? clientIp,
            string? clientMac)
        {
            try
            {
                // Get RADIUS server settings from database
                var radiusServer = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusServer" || s.Key == "RadiusServer")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "192.168.2.252";

                var radiusPortStr = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusAuthPort" || s.Key == "RadiusAuthPort")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "1812";

                var radiusPort = int.TryParse(radiusPortStr, out var port) ? port : 1812;

                var radiusSecret = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusNasSecret" || s.Key == "RadiusSecret")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "testing123";

                var radiusEnabled = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusEnabled")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync();

                _logger.LogInformation("=== RADIUS Authentication ===");
                _logger.LogInformation("Server: {Server}:{Port}", radiusServer, radiusPort);
                _logger.LogInformation("Secret: {Secret}", new string('*', radiusSecret.Length));
                _logger.LogInformation("Username: {Username}", username);
                _logger.LogInformation("Client IP: {ClientIp}", clientIp ?? "unknown");
                _logger.LogInformation("Client MAC: {ClientMac}", clientMac ?? "unknown");

                if (radiusEnabled?.ToLower() != "true")
                {
                    _logger.LogWarning("FreeRADIUS is not enabled in settings");
                    return new RadiusAuthResult
                    {
                        Success = false,
                        Error = "RADIUS authentication is not enabled. Enable it in Admin > Settings > RADIUS."
                    };
                }

                // Create RADIUS client
                var loggerFactory = HttpContext.RequestServices.GetService<ILoggerFactory>();
                var radiusLogger = loggerFactory?.CreateLogger<RadiusClient>()
                    ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<RadiusClient>.Instance;

                var radiusClient = new RadiusClient(
                    radiusLogger,
                    radiusServer,
                    radiusPort,
                    radiusSecret,
                    timeout: 5000);

                // Get NAS IP (this server's IP)
                var nasIp = Request.HttpContext.Connection.LocalIpAddress?.ToString();

                // Send RADIUS Access-Request
                var result = await radiusClient.AuthenticateAsync(
                    username,
                    password,
                    clientIp,
                    clientMac,
                    nasIp);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during RADIUS authentication");
                return new RadiusAuthResult
                {
                    Success = false,
                    Error = $"RADIUS error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Try to authenticate with Ruckus ZoneDirector using WISPr protocol
        /// This redirects back to the Ruckus controller with credentials for RADIUS auth
        /// </summary>
        private async Task<IActionResult?> TryRuckusWisprAuthAsync(string username, string password)
        {
            try
            {
                var uamIp = HttpContext.Session.GetString("UamIp");
                var uamPort = HttpContext.Session.GetString("UamPort") ?? "9997";
                var challenge = HttpContext.Session.GetString("WisprChallenge");
                var userUrl = HttpContext.Session.GetString("OriginalUrl") ?? HttpContext.Session.GetString("LinkOrig");
                var clientMac = HttpContext.Session.GetString("MacAddress");
                var clientIp = HttpContext.Session.GetString("ClientIp");

                _logger.LogInformation("=== Trying Ruckus WISPr Auth ===");
                _logger.LogInformation("UAM IP: {UamIp}", uamIp);
                _logger.LogInformation("Challenge: {Challenge}", challenge);
                _logger.LogInformation("Client MAC: {Mac}", clientMac);

                // If we have UAM IP, we can redirect back to Ruckus with credentials
                if (!string.IsNullOrEmpty(uamIp))
                {
                    // Build the Ruckus login URL
                    // Ruckus ZD expects: http://<uamip>:<uamport>/login?username=XXX&password=XXX
                    var loginUrl = $"http://{uamIp}:{uamPort}/login?" +
                        $"username={Uri.EscapeDataString(username)}&" +
                        $"password={Uri.EscapeDataString(password)}";

                    if (!string.IsNullOrEmpty(userUrl))
                    {
                        loginUrl += $"&userurl={Uri.EscapeDataString(userUrl)}";
                    }

                    _logger.LogInformation("Redirecting to Ruckus login: {Url}", loginUrl);
                    return Redirect(loginUrl);
                }

                // Alternative: Try using the Ruckus controller API directly
                var ruckusController = await GetRuckusControllerAsync();
                if (ruckusController != null && !string.IsNullOrEmpty(clientMac))
                {
                    var authResult = await ruckusController.AuthenticateUserAsync(clientMac, username, password);
                    if (authResult)
                    {
                        _logger.LogInformation("Ruckus API auth successful for MAC {Mac}", clientMac);
                        return RedirectToAction(nameof(Success), new { returnUrl = userUrl });
                    }
                }

                // No UAM IP or controller - fall back to default flow
                _logger.LogInformation("No Ruckus WISPr parameters found, using default flow");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Ruckus WISPr authentication");
                return null;
            }
        }

        /// <summary>
        /// Get Ruckus ZoneDirector controller if configured
        /// </summary>
        private async Task<RuckusZoneDirectorController?> GetRuckusControllerAsync()
        {
            try
            {
                var wifiConfig = await _dbContext.WifiControllerSettings
                    .FirstOrDefaultAsync(w => w.IsEnabled && w.ControllerType == "RuckusZD");

                if (wifiConfig == null)
                    return null;

                var httpClientFactory = HttpContext.RequestServices.GetService<IHttpClientFactory>();
                var logger = HttpContext.RequestServices.GetService<ILogger<RuckusZoneDirectorController>>();

                if (httpClientFactory == null || logger == null)
                    return null;

                return new RuckusZoneDirectorController(wifiConfig, logger, httpClientFactory);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting Ruckus controller");
                return null;
            }
        }

        private async Task CreateWifiSessionAsync(Guest guest, string macAddress, string authMethod)
        {
            try
            {
                // Get bandwidth profile
                var profile = await _dbContext.BandwidthProfiles
                    .FirstOrDefaultAsync(p => p.IsActive && p.IsDefault);

                var session = new WifiSession
                {
                    GuestId = guest.Id,
                    RoomNumber = guest.RoomNumber,
                    GuestName = guest.GuestName,
                    MacAddress = macAddress,
                    Status = "Active",
                    ControllerType = "Mikrotik",
                    AuthMethod = authMethod,
                    BandwidthProfileId = profile?.Id,
                    SessionStart = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow
                };

                _dbContext.WifiSessions.Add(session);
                guest.LastWifiLogin = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync();

                _logger.LogInformation("WiFi session created: SessionId={Id}", session.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating WiFi session");
            }
        }

        [HttpGet("Dashboard")]
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

        [HttpGet("Paywall")]
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

        [HttpPost("PurchasePackage")]
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

        [HttpGet("PurchaseConfirm")]
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

        [HttpGet("Usage")]
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

        [HttpPost("Logout")]
        [Authorize(Roles = "Guest,LocalUser")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction(nameof(Index));
        }

        // Success page after WiFi authentication
        [HttpGet("Success")]
        [AllowAnonymous] // Allow anonymous since guest just authenticated
        public IActionResult Success(string? returnUrl)
        {
            _logger.LogInformation("=== Success Page ===");
            _logger.LogInformation("Return URL: {Url}", returnUrl ?? "none");
            _logger.LogInformation("User authenticated: {Auth}", User.Identity?.IsAuthenticated);

            // Clean up and validate return URL
            if (!string.IsNullOrEmpty(returnUrl))
            {
                try
                {
                    returnUrl = System.Net.WebUtility.UrlDecode(returnUrl);

                    // Only use valid external URLs
                    if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri) &&
                        (uri.Scheme == "http" || uri.Scheme == "https") &&
                        !uri.Host.StartsWith("192.168.") &&
                        !uri.Host.StartsWith("10.") &&
                        !uri.Host.StartsWith("172."))
                    {
                        ViewBag.ReturnUrl = returnUrl;
                    }
                }
                catch
                {
                    // Invalid URL, ignore
                }
            }

            return View();
        }

        // Error page
        [HttpGet("Error")]
        [AllowAnonymous]
        public IActionResult Error(string? message)
        {
            ViewBag.ErrorMessage = message ?? "An error occurred.";
            return View();
        }

        // Status endpoint for AJAX checks
        [HttpGet("Status")]
        [AllowAnonymous]
        public async Task<IActionResult> Status()
        {
            var mac = HttpContext.Session.GetString("MacAddress");
            var isAuthenticated = User.Identity?.IsAuthenticated == true;

            Guest? guest = null;
            if (isAuthenticated)
            {
                var guestId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "0");
                guest = await _dbContext.Guests.FindAsync(guestId);
            }

            return Json(new
            {
                authenticated = isAuthenticated,
                mac = mac,
                room = guest?.RoomNumber,
                name = guest?.GuestName,
                quotaUsed = guest?.UsedQuotaGB ?? 0,
                quotaTotal = guest?.TotalQuotaGB ?? 0,
                quotaRemaining = guest?.RemainingQuotaGB ?? 0
            });
        }

        /// <summary>
        /// Debug endpoint to see what parameters were captured from the controller redirect
        /// Access via: /Portal/Debug
        /// </summary>
        [HttpGet("Debug")]
        [AllowAnonymous]
        public IActionResult Debug()
        {
            var debugInfo = new
            {
                // Session data captured from controller redirect
                Session = new
                {
                    MacAddress = HttpContext.Session.GetString("MacAddress"),
                    ClientIp = HttpContext.Session.GetString("ClientIp"),
                    UamIp = HttpContext.Session.GetString("UamIp"),
                    UamPort = HttpContext.Session.GetString("UamPort"),
                    WisprChallenge = HttpContext.Session.GetString("WisprChallenge"),
                    LinkLogin = HttpContext.Session.GetString("LinkLogin"),
                    LinkOrig = HttpContext.Session.GetString("LinkOrig"),
                    OriginalUrl = HttpContext.Session.GetString("OriginalUrl")
                },
                // Current request info
                Request = new
                {
                    RemoteIp = Request.HttpContext.Connection.RemoteIpAddress?.ToString(),
                    QueryString = Request.QueryString.ToString(),
                    UserAgent = Request.Headers["User-Agent"].ToString(),
                    Referer = Request.Headers["Referer"].ToString()
                },
                // Authentication status
                Auth = new
                {
                    IsAuthenticated = User.Identity?.IsAuthenticated,
                    UserName = User.Identity?.Name,
                    Roles = User.Claims.Where(c => c.Type == System.Security.Claims.ClaimTypes.Role).Select(c => c.Value).ToList()
                },
                // Instructions
                Instructions = new
                {
                    Step1 = "Check if UamIp is populated - this is needed for WISPr redirect",
                    Step2 = "Check if MacAddress is captured - needed for session tracking",
                    Step3 = "If UamIp is empty, Ruckus may not be sending it in the redirect URL",
                    Step4 = "Check Ruckus ZD Hotspot settings: External Portal URL should include parameters"
                }
            };

            return Json(debugInfo);
        }

        /// <summary>
        /// Test RADIUS authentication directly
        /// Access via: /Portal/TestRadius?username=101&password=test123
        /// </summary>
        [HttpGet("TestRadius")]
        [AllowAnonymous]
        public async Task<IActionResult> TestRadius(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return Json(new { error = "Please provide username and password parameters" });
            }

            try
            {
                // Check if user exists in radcheck table via FreeRADIUS service
                var freeRadiusService = HttpContext.RequestServices.GetService<HotelWifiPortal.Services.Radius.FreeRadiusService>();
                if (freeRadiusService == null)
                {
                    return Json(new { error = "FreeRADIUS service not available" });
                }

                // Get FreeRADIUS connection info
                var freeRadiusEnabled = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusEnabled")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync();

                var radiusServer = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusServer" || s.Key == "RadiusServer")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "192.168.2.252";

                var radiusSecret = await _dbContext.SystemSettings
                    .Where(s => s.Key == "FreeRadiusNasSecret" || s.Key == "RadiusSecret")
                    .Select(s => s.Value)
                    .FirstOrDefaultAsync() ?? "testing123";

                return Json(new
                {
                    message = "RADIUS test info",
                    freeRadiusEnabled = freeRadiusEnabled,
                    radiusServer = radiusServer,
                    note = "To test RADIUS authentication, use radtest command on the FreeRADIUS server:",
                    command = $"radtest {username} {password} {radiusServer} 0 {radiusSecret}",
                    explanation = new
                    {
                        problem = "Your external portal validates users locally, but doesn't send RADIUS requests",
                        solution1 = "Use Ruckus built-in login page (Ruckus sends RADIUS requests)",
                        solution2 = "Configure Ruckus to send uamip parameter so portal can redirect back with credentials"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { error = ex.Message });
            }
        }
    }
}