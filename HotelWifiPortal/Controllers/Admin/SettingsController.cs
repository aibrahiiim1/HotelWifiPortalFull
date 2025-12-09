using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services.PMS;
using HotelWifiPortal.Services.Radius;
using HotelWifiPortal.Services.WiFi;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Controllers.Admin
{
    [Route("Admin/[controller]/[action]")]
    [Authorize(Roles = "Admin,SuperAdmin")]
    public class SettingsController : Controller
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly FiasSocketServer _fiasServer;
        private readonly WifiService _wifiService;
        private readonly ILogger<SettingsController> _logger;
        private readonly IConfiguration _configuration;

        public SettingsController(
            ApplicationDbContext dbContext,
            FiasSocketServer fiasServer,
            WifiService wifiService,
            ILogger<SettingsController> logger,
            IConfiguration configuration)
        {
            _dbContext = dbContext;
            _fiasServer = fiasServer;
            _wifiService = wifiService;
            _logger = logger;
            _configuration = configuration;
        }

        // General Settings
        public async Task<IActionResult> Index()
        {
            var settings = await _dbContext.SystemSettings.ToListAsync();

            var model = new SystemSettingsViewModel
            {
                HotelName = settings.FirstOrDefault(s => s.Key == "HotelName")?.Value ?? "",
                HotelLogo = settings.FirstOrDefault(s => s.Key == "HotelLogo")?.Value,
                WelcomeMessage = settings.FirstOrDefault(s => s.Key == "WelcomeMessage")?.Value,
                SupportEmail = settings.FirstOrDefault(s => s.Key == "SupportEmail")?.Value,
                SupportPhone = settings.FirstOrDefault(s => s.Key == "SupportPhone")?.Value,
                SessionTimeoutMinutes = int.TryParse(settings.FirstOrDefault(s => s.Key == "SessionTimeoutMinutes")?.Value, out var timeout) ? timeout : 1440,
                MaxDevicesPerGuest = int.TryParse(settings.FirstOrDefault(s => s.Key == "MaxDevicesPerGuest")?.Value, out var max) ? max : 5,
                EnableStandaloneMode = settings.FirstOrDefault(s => s.Key == "EnableStandaloneMode")?.Value?.ToLower() == "true",
                DefaultLanguage = settings.FirstOrDefault(s => s.Key == "DefaultLanguage")?.Value ?? "en",
                TimeZone = settings.FirstOrDefault(s => s.Key == "TimeZone")?.Value ?? "UTC",
                RequirePasswordResetOnFirstLogin = settings.FirstOrDefault(s => s.Key == "RequirePasswordResetOnFirstLogin")?.Value?.ToLower() != "false", // Default true
                RequireTermsAcceptance = settings.FirstOrDefault(s => s.Key == "RequireTermsAcceptance")?.Value?.ToLower() == "true",
                AllowGuestRegistration = settings.FirstOrDefault(s => s.Key == "AllowGuestRegistration")?.Value?.ToLower() == "true",
                EnablePaywall = settings.FirstOrDefault(s => s.Key == "EnablePaywall")?.Value?.ToLower() != "false", // Default true
                EnableBandwidthLimiting = settings.FirstOrDefault(s => s.Key == "EnableBandwidthLimiting")?.Value?.ToLower() != "false", // Default true
                TermsAndConditions = settings.FirstOrDefault(s => s.Key == "TermsAndConditions")?.Value
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(SystemSettingsViewModel model)
        {
            var settingsToUpdate = new Dictionary<string, string?>
            {
                { "HotelName", model.HotelName },
                { "HotelLogo", model.HotelLogo },
                { "WelcomeMessage", model.WelcomeMessage },
                { "SupportEmail", model.SupportEmail },
                { "SupportPhone", model.SupportPhone },
                { "SessionTimeoutMinutes", model.SessionTimeoutMinutes.ToString() },
                { "MaxDevicesPerGuest", model.MaxDevicesPerGuest.ToString() },
                { "EnableStandaloneMode", model.EnableStandaloneMode.ToString().ToLower() },
                { "DefaultLanguage", model.DefaultLanguage },
                { "TimeZone", model.TimeZone },
                { "RequirePasswordResetOnFirstLogin", model.RequirePasswordResetOnFirstLogin.ToString().ToLower() },
                { "RequireTermsAcceptance", model.RequireTermsAcceptance.ToString().ToLower() },
                { "AllowGuestRegistration", model.AllowGuestRegistration.ToString().ToLower() },
                { "EnablePaywall", model.EnablePaywall.ToString().ToLower() },
                { "EnableBandwidthLimiting", model.EnableBandwidthLimiting.ToString().ToLower() },
                { "TermsAndConditions", model.TermsAndConditions }
            };

            foreach (var kvp in settingsToUpdate)
            {
                var setting = await _dbContext.SystemSettings.FindAsync(kvp.Key);
                if (setting != null)
                {
                    setting.Value = kvp.Value;
                    setting.UpdatedAt = DateTime.UtcNow;
                }
                else
                {
                    _dbContext.SystemSettings.Add(new SystemSetting
                    {
                        Key = kvp.Key,
                        Value = kvp.Value,
                        UpdatedAt = DateTime.UtcNow
                    });
                }
            }

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("System settings updated");
            TempData["Success"] = "Settings saved successfully.";

            return RedirectToAction(nameof(Index));
        }

        // PMS Settings
        public async Task<IActionResult> Pms()
        {
            var pmsSettings = await _dbContext.PmsSettings.FirstOrDefaultAsync() ?? new PmsSettings();
            var status = _fiasServer.GetStatus();

            var model = new PmsSettingsViewModel
            {
                Id = pmsSettings.Id,
                PmsType = pmsSettings.PmsType,
                Name = pmsSettings.Name,
                ListenPort = pmsSettings.ListenPort,
                ListenIpAddress = pmsSettings.ListenIpAddress,
                IsEnabled = pmsSettings.IsEnabled,
                IsPmsModeEnabled = pmsSettings.IsPmsModeEnabled,
                AutoPostCharges = pmsSettings.AutoPostCharges,
                PostByReservationNumber = pmsSettings.PostByReservationNumber,
                PostingCurrency = pmsSettings.PostingCurrency,
                PostingDescription = pmsSettings.PostingDescription,
                IsConnected = status.IsConnected,
                LastConnectionTime = status.LastConnectionTime,
                MessagesSent = status.MessagesSent,
                MessagesReceived = status.MessagesReceived,
                ClientIpAddress = status.ClientIpAddress
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Pms(PmsSettingsViewModel model)
        {
            var pmsSettings = await _dbContext.PmsSettings.FirstOrDefaultAsync();

            if (pmsSettings == null)
            {
                pmsSettings = new PmsSettings();
                _dbContext.PmsSettings.Add(pmsSettings);
            }

            pmsSettings.PmsType = model.PmsType;
            pmsSettings.Name = model.Name;
            pmsSettings.ListenPort = model.ListenPort;
            pmsSettings.ListenIpAddress = model.ListenIpAddress;
            pmsSettings.IsEnabled = model.IsEnabled;
            pmsSettings.IsPmsModeEnabled = model.IsPmsModeEnabled;
            pmsSettings.AutoPostCharges = model.AutoPostCharges;
            pmsSettings.PostByReservationNumber = model.PostByReservationNumber;
            pmsSettings.PostingCurrency = model.PostingCurrency;
            pmsSettings.PostingDescription = model.PostingDescription;
            pmsSettings.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("PMS settings updated. PostByReservationNumber: {Mode}", model.PostByReservationNumber);
            TempData["Success"] = "PMS settings saved. Restart application to apply port changes.";

            return RedirectToAction(nameof(Pms));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> PmsRequestResync()
        {
            if (!_fiasServer.IsConnected)
            {
                TempData["Error"] = "PMS is not connected.";
                return RedirectToAction(nameof(Pms));
            }

            await _fiasServer.RequestDatabaseResyncAsync();
            TempData["Success"] = "Database resync requested.";

            return RedirectToAction(nameof(Pms));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult PmsDisconnect()
        {
            _fiasServer.Disconnect();
            TempData["Success"] = "PMS client disconnected.";
            return RedirectToAction(nameof(Pms));
        }

        // WiFi Controllers
        public async Task<IActionResult> Wifi()
        {
            var controllers = await _dbContext.WifiControllerSettings
                .OrderBy(c => c.ControllerType)
                .ToListAsync();

            return View(controllers);
        }

        // MikroTik Configuration
        public async Task<IActionResult> ConfigureMikrotik()
        {
            var existing = await _dbContext.WifiControllerSettings
                .FirstOrDefaultAsync(w => w.ControllerType == "Mikrotik");

            var model = existing != null ? new WifiSettingsViewModel
            {
                Id = existing.Id,
                ControllerType = existing.ControllerType,
                Name = existing.Name,
                IpAddress = existing.IpAddress,
                Port = existing.Port,
                Username = existing.Username,
                Password = existing.Password,
                HotspotServer = existing.HotspotServer,
                UserProfile = existing.UserProfile,
                UseHttps = existing.UseHttps,
                IgnoreSslErrors = existing.IgnoreSslErrors,
                IsEnabled = existing.IsEnabled,
                IsDefault = existing.IsDefault,
                ConnectionStatus = existing.ConnectionStatus,
                LastConnectionTest = existing.LastConnectionTest
            } : new WifiSettingsViewModel
            {
                Name = "MikroTik Router",
                ControllerType = "Mikrotik",
                UseHttps = false,
                IgnoreSslErrors = true,
                IsEnabled = true,
                UserProfile = "default"
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SaveMikrotik(WifiSettingsViewModel model)
        {
            _logger.LogInformation("SaveMikrotik called");
            PopulateModelFromForm(model);
            model.ControllerType = "Mikrotik";
            ModelState.Clear();
            return await SaveControllerAsync(model, "Mikrotik", nameof(ConfigureMikrotik));
        }

        // Test MikroTik API Connection
        [HttpPost]
        public async Task<IActionResult> TestMikrotikApi(int id)
        {
            try
            {
                var settings = await _dbContext.WifiControllerSettings.FindAsync(id);
                if (settings == null)
                {
                    return Json(new { success = false, error = "Controller not found" });
                }

                if (string.IsNullOrEmpty(settings.IpAddress) || string.IsNullOrEmpty(settings.Username))
                {
                    return Json(new { success = false, error = "API credentials not configured. IP address and username are required for API mode." });
                }

                var handler = new HttpClientHandler();
                if (settings.IgnoreSslErrors)
                {
                    handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
                }

                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

                // Add basic auth
                var credentials = Convert.ToBase64String(
                    System.Text.Encoding.ASCII.GetBytes($"{settings.Username}:{settings.Password}"));
                client.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);

                var protocol = settings.UseHttps ? "https" : "http";
                var port = settings.Port.HasValue ? $":{settings.Port}" : (settings.UseHttps ? ":443" : ":80");
                var url = $"{protocol}://{settings.IpAddress}{port}/rest/system/resource";

                _logger.LogInformation("Testing MikroTik API at: {Url}", url);

                var response = await client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    // Parse response
                    try
                    {
                        var json = System.Text.Json.JsonDocument.Parse(content);
                        var root = json.RootElement;

                        // Update connection status
                        settings.ConnectionStatus = "connected";
                        settings.LastConnectionTest = DateTime.UtcNow;
                        await _dbContext.SaveChangesAsync();

                        return Json(new
                        {
                            success = true,
                            routerName = root.TryGetProperty("board-name", out var bn) ? bn.GetString() : "Unknown",
                            version = root.TryGetProperty("version", out var v) ? v.GetString() : "Unknown",
                            uptime = root.TryGetProperty("uptime", out var u) ? u.GetString() : "Unknown"
                        });
                    }
                    catch
                    {
                        return Json(new { success = true, routerName = "Connected", version = "N/A", uptime = "N/A" });
                    }
                }
                else
                {
                    settings.ConnectionStatus = "error";
                    settings.LastConnectionTest = DateTime.UtcNow;
                    await _dbContext.SaveChangesAsync();

                    return Json(new
                    {
                        success = false,
                        error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}"
                    });
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "MikroTik API connection failed");

                var innerMsg = ex.InnerException?.Message ?? ex.Message;
                string errorDetail;

                if (innerMsg.Contains("SSL") || innerMsg.Contains("TLS") || innerMsg.Contains("certificate"))
                {
                    errorDetail = "SSL/TLS Error. Try: 1) Disable 'Use HTTPS', 2) Enable 'Ignore SSL Errors', or 3) Use port 80";
                }
                else if (innerMsg.Contains("refused") || innerMsg.Contains("actively refused"))
                {
                    errorDetail = "Connection refused. Check: 1) IP address is correct, 2) www/www-ssl service is enabled on MikroTik, 3) Firewall allows connection";
                }
                else if (innerMsg.Contains("timeout") || innerMsg.Contains("timed out"))
                {
                    errorDetail = "Connection timed out. Check: 1) MikroTik is reachable, 2) Network connectivity, 3) Firewall rules";
                }
                else
                {
                    errorDetail = innerMsg;
                }

                return Json(new { success = false, error = errorDetail });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik API test error");
                return Json(new { success = false, error = ex.Message });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SaveRuckusZD(WifiSettingsViewModel model)
        {
            _logger.LogInformation("SaveRuckusZD called");
            PopulateModelFromForm(model);
            ModelState.Clear();
            return await SaveControllerAsync(model, "RuckusZD", nameof(ConfigureRuckusZD));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SaveRuckusCloud(WifiSettingsViewModel model)
        {
            _logger.LogInformation("SaveRuckusCloud called");
            PopulateModelFromForm(model);
            ModelState.Clear();
            return await SaveControllerAsync(model, "Ruckus", nameof(ConfigureRuckusCloud));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SaveExtremeCloud(WifiSettingsViewModel model)
        {
            _logger.LogInformation("SaveExtremeCloud called");
            PopulateModelFromForm(model);
            ModelState.Clear();
            return await SaveControllerAsync(model, "ExtremeCloud", nameof(ConfigureExtremeCloud));
        }

        // Helper method to populate model from form (handles checkbox binding issues)
        private void PopulateModelFromForm(WifiSettingsViewModel model)
        {
            var form = Request.Form;

            // String fields
            if (form.ContainsKey("Name")) model.Name = form["Name"].ToString();
            if (form.ContainsKey("IpAddress")) model.IpAddress = form["IpAddress"].ToString();
            if (form.ContainsKey("Username")) model.Username = form["Username"].ToString();
            if (form.ContainsKey("Password")) model.Password = form["Password"].ToString();
            if (form.ContainsKey("ApiKey")) model.ApiKey = form["ApiKey"].ToString();
            if (form.ContainsKey("ApiUrl")) model.ApiUrl = form["ApiUrl"].ToString();
            if (form.ContainsKey("HotspotServer")) model.HotspotServer = form["HotspotServer"].ToString();
            if (form.ContainsKey("UserProfile")) model.UserProfile = form["UserProfile"].ToString();

            // Port
            if (int.TryParse(form["Port"].ToString(), out int port))
                model.Port = port;

            // Id
            if (int.TryParse(form["Id"].ToString(), out int id))
                model.Id = id;

            // Boolean fields - checkbox sends "true,false" or just "false"
            model.IsEnabled = form["IsEnabled"].ToString().Contains("true");
            model.IsDefault = form["IsDefault"].ToString().Contains("true");
            model.UseHttps = form["UseHttps"].ToString().Contains("true");
            model.IgnoreSslErrors = form["IgnoreSslErrors"].ToString().Contains("true");

            _logger.LogInformation("Form populated - Name: {Name}, IsEnabled: {IsEnabled}, IsDefault: {IsDefault}",
                model.Name, model.IsEnabled, model.IsDefault);
        }

        // Ruckus ZoneDirector Configuration
        public async Task<IActionResult> ConfigureRuckusZD()
        {
            var existing = await _dbContext.WifiControllerSettings
                .FirstOrDefaultAsync(w => w.ControllerType == "RuckusZD");

            var model = existing != null ? new WifiSettingsViewModel
            {
                Id = existing.Id,
                ControllerType = existing.ControllerType,
                Name = existing.Name,
                IpAddress = existing.IpAddress,
                Port = existing.Port,
                Username = existing.Username,
                Password = existing.Password,
                UseHttps = existing.UseHttps,
                IgnoreSslErrors = existing.IgnoreSslErrors,
                IsEnabled = existing.IsEnabled,
                IsDefault = existing.IsDefault,
                ConnectionStatus = existing.ConnectionStatus,
                LastConnectionTest = existing.LastConnectionTest
            } : new WifiSettingsViewModel { Name = "Ruckus ZoneDirector", ControllerType = "RuckusZD", UseHttps = true, IgnoreSslErrors = true };

            return View(model);
        }

        // Ruckus Cloud Configuration
        public async Task<IActionResult> ConfigureRuckusCloud()
        {
            var existing = await _dbContext.WifiControllerSettings
                .FirstOrDefaultAsync(w => w.ControllerType == "Ruckus");

            var model = existing != null ? new WifiSettingsViewModel
            {
                Id = existing.Id,
                ControllerType = existing.ControllerType,
                Name = existing.Name,
                ApiUrl = existing.ApiUrl,
                ApiKey = existing.ApiKey,
                IsEnabled = existing.IsEnabled,
                IsDefault = existing.IsDefault,
                ConnectionStatus = existing.ConnectionStatus,
                LastConnectionTest = existing.LastConnectionTest
            } : new WifiSettingsViewModel { Name = "Ruckus Cloud", ControllerType = "Ruckus" };

            return View(model);
        }

        // ExtremeCloud IQ Configuration
        public async Task<IActionResult> ConfigureExtremeCloud()
        {
            var existing = await _dbContext.WifiControllerSettings
                .FirstOrDefaultAsync(w => w.ControllerType == "ExtremeCloud");

            var model = existing != null ? new WifiSettingsViewModel
            {
                Id = existing.Id,
                ControllerType = existing.ControllerType,
                Name = existing.Name,
                ApiUrl = existing.ApiUrl,
                ApiKey = existing.ApiKey,
                IsEnabled = existing.IsEnabled,
                IsDefault = existing.IsDefault,
                ConnectionStatus = existing.ConnectionStatus,
                LastConnectionTest = existing.LastConnectionTest
            } : new WifiSettingsViewModel { Name = "ExtremeCloud IQ", ControllerType = "ExtremeCloud", ApiUrl = "https://api.extremecloudiq.com" };

            return View(model);
        }

        // Generic save controller helper
        private async Task<IActionResult> SaveControllerAsync(WifiSettingsViewModel model, string controllerType, string redirectAction)
        {
            _logger.LogInformation("SaveControllerAsync - Type: {Type}, Name: {Name}, IP: {IP}, IsEnabled: {IsEnabled}",
                controllerType, model.Name, model.IpAddress, model.IsEnabled);

            WifiControllerSettings? controller;

            if (model.Id > 0)
            {
                controller = await _dbContext.WifiControllerSettings.FindAsync(model.Id);
                if (controller == null) return NotFound();
            }
            else
            {
                // Check if one already exists
                controller = await _dbContext.WifiControllerSettings
                    .FirstOrDefaultAsync(w => w.ControllerType == controllerType);

                if (controller == null)
                {
                    controller = new WifiControllerSettings { ControllerType = controllerType, CreatedAt = DateTime.UtcNow };
                    _dbContext.WifiControllerSettings.Add(controller);
                }
            }

            // If setting as default, unset other defaults
            if (model.IsDefault)
            {
                var existingDefaults = await _dbContext.WifiControllerSettings
                    .Where(w => w.IsDefault && w.Id != controller.Id)
                    .ToListAsync();
                foreach (var w in existingDefaults) w.IsDefault = false;
            }

            // Map all properties
            controller.Name = model.Name ?? "";
            controller.IpAddress = model.IpAddress;
            controller.Port = model.Port;
            controller.Username = model.Username;
            controller.Password = model.Password;
            controller.ApiKey = model.ApiKey;
            controller.ApiUrl = model.ApiUrl;
            controller.HotspotServer = model.HotspotServer;
            controller.UserProfile = model.UserProfile;
            controller.UseHttps = model.UseHttps;
            controller.IgnoreSslErrors = model.IgnoreSslErrors;
            controller.IsEnabled = model.IsEnabled;
            controller.IsDefault = model.IsDefault;
            controller.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("{ControllerType} controller saved successfully - ID: {Id}, Name: {Name}, IsEnabled: {IsEnabled}",
                controllerType, controller.Id, controller.Name, controller.IsEnabled);
            TempData["Success"] = $"{controllerType} configuration saved successfully.";

            return RedirectToAction(redirectAction);
        }

        // Toggle controller enabled/disabled
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleController(int id)
        {
            var controller = await _dbContext.WifiControllerSettings.FindAsync(id);
            if (controller == null) return NotFound();

            controller.IsEnabled = !controller.IsEnabled;
            controller.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("{ControllerType} {Action}: {Name}",
                controller.ControllerType,
                controller.IsEnabled ? "enabled" : "disabled",
                controller.Name);

            TempData["Success"] = $"{controller.Name} {(controller.IsEnabled ? "enabled" : "disabled")}.";
            return RedirectToAction(nameof(Wifi));
        }

        public IActionResult CreateWifi()
        {
            return View(new WifiSettingsViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateWifi(WifiSettingsViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // If setting as default, unset other defaults
            if (model.IsDefault)
            {
                var existingDefaults = await _dbContext.WifiControllerSettings
                    .Where(w => w.IsDefault)
                    .ToListAsync();

                foreach (var w in existingDefaults)
                {
                    w.IsDefault = false;
                }
            }

            var controller = new WifiControllerSettings
            {
                ControllerType = model.ControllerType,
                Name = model.Name,
                IpAddress = model.IpAddress,
                Port = model.Port,
                Username = model.Username,
                Password = model.Password,
                ApiKey = model.ApiKey,
                ApiUrl = model.ApiUrl,
                UseHttps = model.UseHttps,
                IgnoreSslErrors = model.IgnoreSslErrors,
                IsEnabled = model.IsEnabled,
                IsDefault = model.IsDefault,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _dbContext.WifiControllerSettings.Add(controller);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("WiFi controller created: {Type} - {Name}", model.ControllerType, model.Name);
            TempData["Success"] = "WiFi controller created successfully.";

            return RedirectToAction(nameof(Wifi));
        }

        public async Task<IActionResult> EditWifi(int id)
        {
            var controller = await _dbContext.WifiControllerSettings.FindAsync(id);
            if (controller == null)
            {
                return NotFound();
            }

            var model = new WifiSettingsViewModel
            {
                Id = controller.Id,
                ControllerType = controller.ControllerType,
                Name = controller.Name,
                IpAddress = controller.IpAddress,
                Port = controller.Port,
                Username = controller.Username,
                Password = controller.Password,
                ApiKey = controller.ApiKey,
                ApiUrl = controller.ApiUrl,
                UseHttps = controller.UseHttps,
                IgnoreSslErrors = controller.IgnoreSslErrors,
                IsEnabled = controller.IsEnabled,
                IsDefault = controller.IsDefault
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditWifi(int id, WifiSettingsViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var controller = await _dbContext.WifiControllerSettings.FindAsync(id);
            if (controller == null)
            {
                return NotFound();
            }

            // If setting as default, unset other defaults
            if (model.IsDefault && !controller.IsDefault)
            {
                var existingDefaults = await _dbContext.WifiControllerSettings
                    .Where(w => w.IsDefault && w.Id != id)
                    .ToListAsync();

                foreach (var w in existingDefaults)
                {
                    w.IsDefault = false;
                }
            }

            controller.ControllerType = model.ControllerType;
            controller.Name = model.Name;
            controller.IpAddress = model.IpAddress;
            controller.Port = model.Port;
            controller.Username = model.Username;

            if (!string.IsNullOrEmpty(model.Password))
            {
                controller.Password = model.Password;
            }

            controller.ApiKey = model.ApiKey;
            controller.ApiUrl = model.ApiUrl;
            controller.UseHttps = model.UseHttps;
            controller.IgnoreSslErrors = model.IgnoreSslErrors;
            controller.IsEnabled = model.IsEnabled;
            controller.IsDefault = model.IsDefault;
            controller.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            TempData["Success"] = "WiFi controller updated successfully.";
            return RedirectToAction(nameof(Wifi));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteWifi(int id)
        {
            var controller = await _dbContext.WifiControllerSettings.FindAsync(id);
            if (controller == null)
            {
                return NotFound();
            }

            _dbContext.WifiControllerSettings.Remove(controller);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("WiFi controller deleted: {Type} - {Name}", controller.ControllerType, controller.Name);
            TempData["Success"] = "WiFi controller deleted successfully.";

            return RedirectToAction(nameof(Wifi));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> TestWifiConnection(int id)
        {
            var controller = await _dbContext.WifiControllerSettings.FindAsync(id);
            if (controller == null)
            {
                return NotFound();
            }

            var success = await _wifiService.TestControllerAsync(controller.ControllerType);

            controller.LastConnectionTest = DateTime.UtcNow;
            controller.ConnectionStatus = success ? "connected" : "failed";
            await _dbContext.SaveChangesAsync();

            if (success)
            {
                TempData["Success"] = $"Connection to {controller.Name} successful!";
            }
            else
            {
                TempData["Error"] = $"Connection to {controller.Name} failed.";
            }

            return RedirectToAction(nameof(Wifi));
        }

        /// <summary>
        /// AJAX endpoint for detailed connection test
        /// </summary>
        [HttpPost]
        public async Task<IActionResult> TestWifiConnectionJson(int id)
        {
            var settings = await _dbContext.WifiControllerSettings.FindAsync(id);
            if (settings == null)
            {
                return Json(new
                {
                    success = false,
                    message = "Controller not found",
                    details = (object?)null
                });
            }

            // Log the settings being used
            _logger.LogInformation("Testing connection - ID: {Id}, IP: {IP}, UseHttps: {UseHttps}, Port: {Port}, IgnoreSSL: {IgnoreSSL}",
                settings.Id, settings.IpAddress, settings.UseHttps, settings.Port, settings.IgnoreSslErrors);

            var result = new ConnectionTestResult
            {
                ControllerType = settings.ControllerType,
                ControllerName = settings.Name,
                IpAddress = settings.IpAddress,
                TestStarted = DateTime.UtcNow
            };

            try
            {
                // Test basic connectivity first
                result.Steps.Add(new TestStep { Name = "DNS/Network", Status = "testing" });

                HttpClientHandler? handler = null;
                if (settings.IgnoreSslErrors)
                {
                    handler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
                    };
                }

                using var httpClient = handler != null
                    ? new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) }
                    : new HttpClient() { Timeout = TimeSpan.FromSeconds(10) };

                var protocol = settings.UseHttps ? "https" : "http";
                var port = settings.Port.HasValue ? $":{settings.Port}" : (settings.UseHttps ? "" : ":80");
                var baseUrl = $"{protocol}://{settings.IpAddress}{port}";

                _logger.LogInformation("Testing URL: {BaseUrl}", baseUrl);

                result.Steps[0].Status = "success";
                result.Steps[0].Message = $"Base URL: {baseUrl}";

                // Test HTTP connectivity
                result.Steps.Add(new TestStep { Name = "HTTP Connection", Status = "testing" });

                if (!string.IsNullOrEmpty(settings.Username) && !string.IsNullOrEmpty(settings.Password))
                {
                    var credentials = Convert.ToBase64String(
                        System.Text.Encoding.ASCII.GetBytes($"{settings.Username}:{settings.Password}"));
                    httpClient.DefaultRequestHeaders.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
                }

                // Test endpoint based on controller type
                HttpResponseMessage response;
                string testEndpoint;

                if (settings.ControllerType == "Mikrotik")
                {
                    // Try REST API first (RouterOS 6.45+)
                    testEndpoint = "/rest/system/resource";
                    response = await httpClient.GetAsync($"{baseUrl}{testEndpoint}");

                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // REST API not available, try root page
                        result.Steps[1].Message = "REST API returned 404 - trying web interface...";
                        testEndpoint = "/";
                        response = await httpClient.GetAsync($"{baseUrl}{testEndpoint}");

                        if (response.IsSuccessStatusCode)
                        {
                            result.Steps[1].Status = "warning";
                            result.Steps[1].Message = $"Web interface accessible, but REST API not available. RouterOS 6.45+ required for REST API.";
                            result.Steps.Add(new TestStep
                            {
                                Name = "REST API",
                                Status = "failed",
                                Message = "REST API not available. Your RouterOS version may be older than 6.45. " +
                                         "Consider upgrading or use API-based integration instead."
                            });

                            result.Success = false;
                            result.Message = "MikroTik reachable but REST API not available";

                            settings.LastConnectionTest = DateTime.UtcNow;
                            settings.ConnectionStatus = "failed";
                            await _dbContext.SaveChangesAsync();

                            return Json(result);
                        }
                    }
                }
                else
                {
                    switch (settings.ControllerType)
                    {
                        case "RuckusZD":
                            testEndpoint = "/admin/status.jsp";
                            break;
                        case "Ruckus":
                            testEndpoint = "/api/public/v5_0/system/systemSummary";
                            break;
                        default:
                            testEndpoint = "/";
                            break;
                    }
                    response = await httpClient.GetAsync($"{baseUrl}{testEndpoint}");
                }

                result.Steps[1].Status = response.IsSuccessStatusCode ? "success" : "warning";
                result.Steps[1].Message = $"HTTP {(int)response.StatusCode} {response.StatusCode} - {testEndpoint}";

                // Try to get system info
                result.Steps.Add(new TestStep { Name = "API Response", Status = "testing" });

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();

                    if (settings.ControllerType == "Mikrotik")
                    {
                        try
                        {
                            var json = System.Text.Json.JsonDocument.Parse(content);
                            var root = json.RootElement;

                            result.SystemInfo = new Dictionary<string, string>();

                            if (root.TryGetProperty("board-name", out var boardName))
                                result.SystemInfo["Board"] = boardName.GetString() ?? "";
                            if (root.TryGetProperty("version", out var version))
                                result.SystemInfo["Version"] = version.GetString() ?? "";
                            if (root.TryGetProperty("cpu", out var cpu))
                                result.SystemInfo["CPU"] = cpu.GetString() ?? "";
                            if (root.TryGetProperty("cpu-load", out var cpuLoad))
                                result.SystemInfo["CPU Load"] = cpuLoad.GetString() ?? "";
                            if (root.TryGetProperty("uptime", out var uptime))
                                result.SystemInfo["Uptime"] = uptime.GetString() ?? "";
                            if (root.TryGetProperty("free-memory", out var freeMem))
                                result.SystemInfo["Free Memory"] = FormatBytes(freeMem.GetInt64());
                            if (root.TryGetProperty("total-memory", out var totalMem))
                                result.SystemInfo["Total Memory"] = FormatBytes(totalMem.GetInt64());

                            result.Steps[2].Status = "success";
                            result.Steps[2].Message = $"RouterOS {result.SystemInfo.GetValueOrDefault("Version", "unknown")}";
                        }
                        catch
                        {
                            result.Steps[2].Status = "warning";
                            result.Steps[2].Message = "Could not parse system info";
                        }
                    }
                    else
                    {
                        result.Steps[2].Status = "success";
                        result.Steps[2].Message = $"Response received ({content.Length} bytes)";
                    }

                    result.Success = true;
                    result.Message = "Connection successful!";
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    result.Steps[2].Status = "failed";
                    result.Steps[2].Message = $"Error: {errorContent.Substring(0, Math.Min(200, errorContent.Length))}";
                    result.Success = false;
                    result.Message = $"HTTP Error: {response.StatusCode}";
                }

                // Test hotspot if MikroTik
                if (settings.ControllerType == "Mikrotik" && result.Success)
                {
                    result.Steps.Add(new TestStep { Name = "Hotspot Service", Status = "testing" });

                    try
                    {
                        var hsResponse = await httpClient.GetAsync($"{baseUrl}/rest/ip/hotspot");
                        if (hsResponse.IsSuccessStatusCode)
                        {
                            var hsContent = await hsResponse.Content.ReadAsStringAsync();
                            var hsJson = System.Text.Json.JsonDocument.Parse(hsContent);
                            var hsCount = hsJson.RootElement.GetArrayLength();

                            result.Steps[3].Status = hsCount > 0 ? "success" : "warning";
                            result.Steps[3].Message = hsCount > 0
                                ? $"{hsCount} hotspot server(s) configured"
                                : "No hotspot servers configured";
                        }
                        else
                        {
                            result.Steps[3].Status = "warning";
                            result.Steps[3].Message = "Could not check hotspot status";
                        }
                    }
                    catch
                    {
                        result.Steps[3].Status = "warning";
                        result.Steps[3].Message = "Hotspot check skipped";
                    }

                    // Test active sessions
                    result.Steps.Add(new TestStep { Name = "Active Sessions", Status = "testing" });

                    try
                    {
                        var activeResponse = await httpClient.GetAsync($"{baseUrl}/rest/ip/hotspot/active");
                        if (activeResponse.IsSuccessStatusCode)
                        {
                            var activeContent = await activeResponse.Content.ReadAsStringAsync();
                            var activeJson = System.Text.Json.JsonDocument.Parse(activeContent);
                            var activeCount = activeJson.RootElement.GetArrayLength();

                            result.Steps[4].Status = "success";
                            result.Steps[4].Message = $"{activeCount} active session(s)";
                            result.ActiveSessions = activeCount;
                        }
                        else
                        {
                            result.Steps[4].Status = "warning";
                            result.Steps[4].Message = "Could not get active sessions";
                        }
                    }
                    catch
                    {
                        result.Steps[4].Status = "warning";
                        result.Steps[4].Message = "Session check skipped";
                    }
                }

                // Update database
                settings.LastConnectionTest = DateTime.UtcNow;
                settings.ConnectionStatus = result.Success ? "connected" : "failed";
                await _dbContext.SaveChangesAsync();
            }
            catch (HttpRequestException ex)
            {
                result.Success = false;

                // Provide more helpful error messages
                var innerMsg = ex.InnerException?.Message ?? "";

                if (innerMsg.Contains("SSL") || innerMsg.Contains("TLS") || innerMsg.Contains("certificate"))
                {
                    result.Message = "SSL/TLS Error - Try these solutions:";
                    result.Steps.Add(new TestStep
                    {
                        Name = "SSL Issue",
                        Status = "failed",
                        Message = "1. Enable 'Ignore SSL Errors' in controller settings\n" +
                                  "2. Or use HTTP instead of HTTPS\n" +
                                  "3. Or install a valid SSL certificate on MikroTik"
                    });
                }
                else if (innerMsg.Contains("connection") || innerMsg.Contains("refused") || innerMsg.Contains("unreachable"))
                {
                    result.Message = "Connection refused - Check:";
                    result.Steps.Add(new TestStep
                    {
                        Name = "Connection Issue",
                        Status = "failed",
                        Message = "1. MikroTik IP address is correct\n" +
                                  "2. Port is correct (default: 443 for HTTPS, 80 for HTTP)\n" +
                                  "3. Firewall allows connection from this server\n" +
                                  "4. www-ssl or www service is enabled on MikroTik"
                    });
                }
                else if (innerMsg.Contains("timeout") || innerMsg.Contains("timed out"))
                {
                    result.Message = "Connection timed out - Check:";
                    result.Steps.Add(new TestStep
                    {
                        Name = "Timeout",
                        Status = "failed",
                        Message = "1. MikroTik is powered on and accessible\n" +
                                  "2. Network route exists between portal and MikroTik\n" +
                                  "3. No firewall blocking the connection"
                    });
                }
                else
                {
                    result.Message = $"Connection failed: {ex.Message}";
                }

                _logger.LogError(ex, "WiFi controller connection test failed: {InnerMessage}", innerMsg);
                result.Steps.Last().Status = "failed";
                result.Steps.Last().Message = ex.Message;

                settings.LastConnectionTest = DateTime.UtcNow;
                settings.ConnectionStatus = "failed";
                await _dbContext.SaveChangesAsync();
            }
            catch (TaskCanceledException)
            {
                result.Success = false;
                result.Message = "Connection timeout - device not reachable";
                result.Steps.Last().Status = "failed";
                result.Steps.Last().Message = "Request timed out after 10 seconds";

                settings.LastConnectionTest = DateTime.UtcNow;
                settings.ConnectionStatus = "timeout";
                await _dbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Error: {ex.Message}";
                result.Steps.Last().Status = "failed";
                result.Steps.Last().Message = ex.Message;

                _logger.LogError(ex, "Connection test failed for {Controller}", settings.Name);

                settings.LastConnectionTest = DateTime.UtcNow;
                settings.ConnectionStatus = "error";
                await _dbContext.SaveChangesAsync();
            }

            result.TestCompleted = DateTime.UtcNow;
            result.Duration = (result.TestCompleted - result.TestStarted).TotalMilliseconds;

            return Json(result);
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:0.##} {sizes[order]}";
        }

        // RADIUS Settings
        public async Task<IActionResult> Radius()
        {
            var settings = await _dbContext.SystemSettings.ToListAsync();

            ViewBag.RadiusMode = settings.FirstOrDefault(s => s.Key == "RadiusMode")?.Value ?? "builtin";
            ViewBag.BuiltinEnabled = true; // Built-in is always active when in builtin mode
            ViewBag.FreeRadiusEnabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value?.ToLower() == "true";
            ViewBag.SharedSecret = settings.FirstOrDefault(s => s.Key == "RadiusSharedSecret")?.Value ?? "radius_secret";
            ViewBag.AuthPort = int.TryParse(settings.FirstOrDefault(s => s.Key == "RadiusAuthPort")?.Value, out var ap) ? ap : 1812;
            ViewBag.AcctPort = int.TryParse(settings.FirstOrDefault(s => s.Key == "RadiusAcctPort")?.Value, out var acp) ? acp : 1813;
            ViewBag.CoAPort = int.TryParse(settings.FirstOrDefault(s => s.Key == "RadiusCoAPort")?.Value, out var cp) ? cp : 3799;
            ViewBag.FreeRadiusConnection = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value ?? "";
            ViewBag.TablePrefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

            // Generate SQL schema
            using var scope = HttpContext.RequestServices.CreateScope();
            var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();
            ViewBag.SqlSchema = freeRadiusService.GetDatabaseSchema();

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RadiusSaveMode(string radiusMode)
        {
            await SaveSettingAsync("RadiusMode", radiusMode);
            TempData["Success"] = "RADIUS mode updated. Restart application to apply changes.";
            return RedirectToAction(nameof(Radius));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RadiusSaveBuiltin(string sharedSecret, int authPort, int acctPort, int coaPort)
        {
            await SaveSettingAsync("RadiusSharedSecret", sharedSecret);
            await SaveSettingAsync("RadiusAuthPort", authPort.ToString());
            await SaveSettingAsync("RadiusAcctPort", acctPort.ToString());
            await SaveSettingAsync("RadiusCoAPort", coaPort.ToString());

            TempData["Success"] = "Built-in RADIUS settings saved. Restart application to apply port changes.";
            return RedirectToAction(nameof(Radius));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RadiusSaveFreeRadius(bool freeRadiusEnabled, string connectionString, string tablePrefix)
        {
            await SaveSettingAsync("FreeRadiusEnabled", freeRadiusEnabled.ToString().ToLower());
            await SaveSettingAsync("FreeRadiusConnectionString", connectionString);
            await SaveSettingAsync("FreeRadiusTablePrefix", tablePrefix);

            TempData["Success"] = "FreeRADIUS settings saved.";
            return RedirectToAction(nameof(Radius));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RadiusSyncUsers()
        {
            using var scope = HttpContext.RequestServices.CreateScope();
            var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

            await freeRadiusService.SyncAllGuestsAsync();

            TempData["Success"] = "Users synced to RADIUS.";
            return RedirectToAction(nameof(Radius));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RadiusSyncProfiles()
        {
            using var scope = HttpContext.RequestServices.CreateScope();
            var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

            await freeRadiusService.SyncBandwidthProfilesAsync();

            TempData["Success"] = "Bandwidth profiles synced to RADIUS.";
            return RedirectToAction(nameof(Radius));
        }

        // RADIUS Diagnostic endpoint
        [HttpGet]
        public IActionResult TestRadiusServer()
        {
            var result = new
            {
                serverTime = DateTime.UtcNow,
                authPort = _configuration.GetValue("Radius:AuthPort", 1812),
                acctPort = _configuration.GetValue("Radius:AcctPort", 1813),
                coaPort = _configuration.GetValue("Radius:CoAPort", 3799),
                sharedSecret = _configuration["Radius:SharedSecret"] ?? "radius_secret_change_me",
                mode = _configuration["Radius:Mode"] ?? "builtin",
                tests = new List<object>()
            };

            // Test if ports are listening
            var tests = new List<object>();

            // Test Auth Port
            try
            {
                using var testClient = new System.Net.Sockets.UdpClient();
                testClient.Client.ReceiveTimeout = 1000;
                testClient.Connect("127.0.0.1", result.authPort);
                tests.Add(new { port = result.authPort, name = "Auth", status = "Port accessible", success = true });
            }
            catch (Exception ex)
            {
                tests.Add(new { port = result.authPort, name = "Auth", status = ex.Message, success = false });
            }

            // Test Acct Port
            try
            {
                using var testClient = new System.Net.Sockets.UdpClient();
                testClient.Client.ReceiveTimeout = 1000;
                testClient.Connect("127.0.0.1", result.acctPort);
                tests.Add(new { port = result.acctPort, name = "Acct", status = "Port accessible", success = true });
            }
            catch (Exception ex)
            {
                tests.Add(new { port = result.acctPort, name = "Acct", status = ex.Message, success = false });
            }

            return Json(new
            {
                result.serverTime,
                result.authPort,
                result.acctPort,
                result.coaPort,
                sharedSecretConfigured = !string.IsNullOrEmpty(result.sharedSecret) && result.sharedSecret != "radius_secret_change_me",
                result.mode,
                tests,
                instructions = new
                {
                    step1 = "Configure MikroTik RADIUS to point to this server IP",
                    step2 = $"Use shared secret: {result.sharedSecret}",
                    step3 = $"Authentication port: {result.authPort}",
                    step4 = $"Accounting port: {result.acctPort}",
                    linuxTest = $"echo 'User-Name=test,User-Password=test' | radtest test test 127.0.0.1 0 {result.sharedSecret}"
                }
            });
        }

        // Debug/Troubleshooting page
        public async Task<IActionResult> Debug()
        {
            var settings = await _dbContext.SystemSettings.ToListAsync();
            var mikrotik = await _dbContext.WifiControllerSettings
                .FirstOrDefaultAsync(w => w.ControllerType == "Mikrotik" && w.IsEnabled);

            ViewBag.BuiltinRadiusRunning = true; // BackgroundService is always running
            ViewBag.FreeRadiusEnabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value?.ToLower() == "true";
            ViewBag.MikrotikConnected = mikrotik?.ConnectionStatus == "connected";
            ViewBag.MikrotikIp = mikrotik?.IpAddress;
            ViewBag.MikrotikApiConfigured = !string.IsNullOrEmpty(mikrotik?.IpAddress) && !string.IsNullOrEmpty(mikrotik?.Username);
            ViewBag.AuthPort = settings.FirstOrDefault(s => s.Key == "RadiusAuthPort")?.Value ?? "1812";
            ViewBag.AcctPort = settings.FirstOrDefault(s => s.Key == "RadiusAcctPort")?.Value ?? "1813";
            ViewBag.CoAPort = settings.FirstOrDefault(s => s.Key == "RadiusCoAPort")?.Value ?? "3799";
            ViewBag.AuthMethod = settings.FirstOrDefault(s => s.Key == "MikrotikAuthMethod")?.Value ?? "RADIUS";

            // Get recent sessions as auth history
            var recentSessions = await _dbContext.WifiSessions
                .OrderByDescending(s => s.SessionStart)
                .Take(20)
                .Select(s => new
                {
                    Time = s.SessionStart,
                    Username = s.RoomNumber,
                    Mac = s.MacAddress,
                    Method = s.AuthMethod ?? "Unknown",
                    Success = s.Status == "Active" || s.Status == "Disconnected",
                    Details = s.Status
                })
                .ToListAsync();

            ViewBag.RecentAuths = recentSessions;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SetAuthMethod(string method)
        {
            await SaveSettingAsync("MikrotikAuthMethod", method);
            TempData["Success"] = $"Auth method set to: {method}";
            return RedirectToAction(nameof(Debug));
        }

        [HttpGet]
        public IActionResult GetRecentLogs(int since = 0)
        {
            // This would connect to a log provider - simplified for now
            var logs = new List<object>
            {
                new { id = 1, time = DateTime.UtcNow.ToString("HH:mm:ss"), level = "Information", category = "RADIUS", message = "Server listening on ports 1812, 1813" },
            };
            return Json(new { logs, lastId = 1 });
        }

        [HttpPost]
        public async Task<IActionResult> TestRadiusAuth(string username, string password, string mac)
        {
            try
            {
                // Test authentication against database
                var guest = await _dbContext.Guests
                    .FirstOrDefaultAsync(g => g.RoomNumber == username &&
                        g.ReservationNumber == password &&
                        g.Status == "checked-in");

                if (guest != null)
                {
                    return Json(new
                    {
                        success = true,
                        message = $"Guest found: {guest.GuestName}, Room {guest.RoomNumber}, Quota: {guest.TotalQuotaGB:F1} GB"
                    });
                }

                return Json(new { success = false, error = "Invalid credentials or guest not checked in" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> QueryMikrotik(string endpoint)
        {
            try
            {
                var settings = await _dbContext.WifiControllerSettings
                    .FirstOrDefaultAsync(w => w.ControllerType == "Mikrotik" && w.IsEnabled);

                if (settings == null)
                    return Json(new
                    {
                        error = "MikroTik controller not configured or not enabled",
                        hint = "Go to Settings > WiFi Controllers > Add MikroTik to configure"
                    });

                // Check if API credentials are configured
                if (string.IsNullOrEmpty(settings.IpAddress) || string.IsNullOrEmpty(settings.Username))
                {
                    return Json(new
                    {
                        info = "MikroTik API not configured - using RADIUS-only mode",
                        radiusMode = true,
                        hint = "In RADIUS mode, MikroTik communicates directly with the RADIUS server. Direct API queries are not available."
                    });
                }

                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
                };

                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

                if (!string.IsNullOrEmpty(settings.Username) && !string.IsNullOrEmpty(settings.Password))
                {
                    var credentials = Convert.ToBase64String(
                        System.Text.Encoding.ASCII.GetBytes($"{settings.Username}:{settings.Password}"));
                    client.DefaultRequestHeaders.Authorization =
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
                }

                var protocol = settings.UseHttps ? "https" : "http";
                var port = settings.Port.HasValue ? $":{settings.Port}" : "";
                var url = $"{protocol}://{settings.IpAddress}{port}/rest/{endpoint}";

                _logger.LogInformation("Querying MikroTik: {Url}", url);

                var response = await client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var json = System.Text.Json.JsonSerializer.Deserialize<object>(content);
                    return Json(json);
                }

                return Json(new { error = $"HTTP {(int)response.StatusCode}: {content}" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MikroTik query failed");
                return Json(new { error = ex.Message });
            }
        }

        [HttpPost]
        public async Task<IActionResult> CreateMacBinding(string mac, string? ip, string? comment)
        {
            try
            {
                using var scope = HttpContext.RequestServices.CreateScope();
                var mikrotikAuth = scope.ServiceProvider.GetRequiredService<Services.WiFi.MikrotikAuthService>();

                var result = await mikrotikAuth.AuthenticateViaMacBindingAsync(
                    ip ?? "0.0.0.0",
                    mac,
                    comment ?? $"Manual binding - {DateTime.UtcNow:g}");

                return Json(new { success = result.Success, error = result.Error });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = ex.Message });
            }
        }

        private async Task SaveSettingAsync(string key, string? value)
        {
            var setting = await _dbContext.SystemSettings.FindAsync(key);
            if (setting != null)
            {
                setting.Value = value;
                setting.UpdatedAt = DateTime.UtcNow;
            }
            else
            {
                _dbContext.SystemSettings.Add(new SystemSetting
                {
                    Key = key,
                    Value = value,
                    Category = "RADIUS",
                    UpdatedAt = DateTime.UtcNow
                });
            }
            await _dbContext.SaveChangesAsync();
        }

        #region FreeRADIUS Management Endpoints

        /// <summary>
        /// FreeRADIUS Management Page
        /// </summary>
        [HttpGet]
        public IActionResult FreeRadius()
        {
            return View();
        }

        /// <summary>
        /// Get FreeRADIUS configuration - API endpoint
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> FreeRadiusGetConfig()
        {
            try
            {
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value ?? "";

                // Parse connection string
                var parts = new Dictionary<string, string>();
                foreach (var segment in connStr.Split(';'))
                {
                    var kv = segment.Split('=');
                    if (kv.Length == 2)
                        parts[kv[0].Trim()] = kv[1].Trim();
                }

                return Json(new
                {
                    success = true,
                    config = new
                    {
                        enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value?.ToLower() == "true",
                        disableBuiltin = settings.FirstOrDefault(s => s.Key == "FreeRadiusDisableBuiltin")?.Value?.ToLower() == "true",
                        server = parts.GetValueOrDefault("Server", "localhost"),
                        port = parts.GetValueOrDefault("Port", "3306"),
                        database = parts.GetValueOrDefault("Database", "radius"),
                        user = parts.GetValueOrDefault("User", "radius"),
                        password = parts.GetValueOrDefault("Password", ""),
                        tablePrefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad",
                        nasSecret = settings.FirstOrDefault(s => s.Key == "FreeRadiusNasSecret")?.Value ?? "",
                        syncInterval = settings.FirstOrDefault(s => s.Key == "FreeRadiusSyncInterval")?.Value ?? "5",
                        coaPort = settings.FirstOrDefault(s => s.Key == "FreeRadiusCoAPort")?.Value ?? "3799",
                        authPort = settings.FirstOrDefault(s => s.Key == "FreeRadiusAuthPort")?.Value ?? "1812",
                        acctPort = settings.FirstOrDefault(s => s.Key == "FreeRadiusAcctPort")?.Value ?? "1813",
                        defaultProtocol = settings.FirstOrDefault(s => s.Key == "FreeRadiusDefaultProtocol")?.Value ?? "PAP",
                        radiusServer = settings.FirstOrDefault(s => s.Key == "FreeRadiusServerIp")?.Value ?? "127.0.0.1"
                    }
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Save FreeRADIUS configuration
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusSaveConfig([FromBody] FreeRadiusConfigModel? config)
        {
            try
            {
                if (config == null)
                {
                    return Json(new { success = false, message = "Invalid configuration data" });
                }

                await SaveSettingAsync("FreeRadiusEnabled", config.Enabled.ToString().ToLower());
                await SaveSettingAsync("FreeRadiusDisableBuiltin", config.DisableBuiltin.ToString().ToLower());
                await SaveSettingAsync("FreeRadiusConnectionString", config.ConnectionString ?? "");
                await SaveSettingAsync("FreeRadiusTablePrefix", config.TablePrefix ?? "rad");
                await SaveSettingAsync("FreeRadiusNasSecret", config.NasSecret ?? "");
                await SaveSettingAsync("FreeRadiusSyncInterval", config.SyncInterval.ToString());
                await SaveSettingAsync("FreeRadiusCoAPort", config.CoAPort.ToString());
                await SaveSettingAsync("FreeRadiusAuthPort", config.AuthPort.ToString());
                await SaveSettingAsync("FreeRadiusAcctPort", config.AcctPort.ToString());
                await SaveSettingAsync("FreeRadiusDefaultProtocol", config.DefaultProtocol ?? "PAP");
                await SaveSettingAsync("FreeRadiusServerIp", config.RadiusServer ?? "127.0.0.1");

                _logger.LogInformation("FreeRADIUS configuration saved: Enabled={Enabled}", config.Enabled);
                return Json(new { success = true, message = "Configuration saved successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving FreeRADIUS configuration");
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Test FreeRADIUS database connection
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusTestConnection([FromBody] ConnectionStringModel? model)
        {
            try
            {
                if (model == null || string.IsNullOrEmpty(model.ConnectionString))
                {
                    return Json(new { success = false, message = "Connection string is required" });
                }

                using var connection = new MySqlConnector.MySqlConnection(model.ConnectionString);
                await connection.OpenAsync();

                // Test query
                using var cmd = new MySqlConnector.MySqlCommand("SELECT 1", connection);
                await cmd.ExecuteScalarAsync();

                return Json(new { success = true, message = "Connection successful!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Get FreeRADIUS status
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> FreeRadiusGetStatus()
        {
            try
            {
                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                var testResult = await freeRadiusService.TestConnectionAsync();

                return Json(new
                {
                    success = testResult.Success,
                    enabled = testResult.IsEnabled,
                    databaseConnected = testResult.DatabaseConnected,
                    tablesExist = testResult.TablesExist,
                    userCount = testResult.UserCount,
                    activeSessions = testResult.ActiveSessions,
                    nasCount = testResult.NasCount,
                    message = testResult.Message,
                    lastSync = DateTime.UtcNow.ToString("g") // TODO: track actual sync time
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Test RADIUS authentication
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusTestAuth([FromBody] AuthTestModel? model)
        {
            try
            {
                if (model == null || string.IsNullOrEmpty(model.Username))
                    return Json(new { success = false, message = "Username is required" });

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                if (!freeRadiusService.IsEnabled)
                    return Json(new { success = false, message = "FreeRADIUS is not enabled" });

                // Check if user exists in radcheck
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (string.IsNullOrEmpty(connStr))
                    return Json(new { success = false, message = "No connection string configured" });

                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();

                using var cmd = new MySqlConnector.MySqlCommand(
                    $"SELECT value FROM {prefix}check WHERE username = @username AND attribute = 'Cleartext-Password'",
                    connection);
                cmd.Parameters.AddWithValue("@username", model.Username);

                var storedPassword = await cmd.ExecuteScalarAsync() as string;

                if (storedPassword == null)
                    return Json(new { success = false, message = $"User '{model.Username}' not found in radcheck" });

                if (storedPassword == model.Password)
                    return Json(new { success = true, message = $"Authentication successful for user '{model.Username}'" });
                else
                    return Json(new { success = false, message = $"Password mismatch for user '{model.Username}'" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Test CoA/Disconnect
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusTestCoa([FromBody] CoaTestModel? model)
        {
            try
            {
                if (model == null || string.IsNullOrEmpty(model.Username))
                    return Json(new { success = false, message = "Username is required" });

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                bool result;
                if (model.Action == "disconnect")
                {
                    result = await freeRadiusService.DisconnectUserAsync(model.NasIp ?? "127.0.0.1", model.Username);
                    return Json(new { success = result, message = result ? "Disconnect request sent" : "Disconnect failed" });
                }
                else // coa
                {
                    result = await freeRadiusService.ChangeAuthorizationAsync(model.NasIp ?? "127.0.0.1", model.Username, model.DownloadKbps, model.UploadKbps);
                    return Json(new { success = result, message = result ? "CoA request sent" : "CoA failed" });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Sync all users to FreeRADIUS
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusSyncUsers()
        {
            var logs = new List<string>();
            try
            {
                logs.Add("Starting guest sync...");

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                // Force reload configuration from database
                await freeRadiusService.LoadConfigurationFromDatabaseAsync();
                logs.Add("Configuration loaded");

                // Count checked-in guests (matching the service query)
                var guests = await _dbContext.Guests
                    .Where(g => g.Status.ToLower() == "checked-in" ||
                               g.Status.ToLower() == "checkedin" ||
                               g.Status == "CheckedIn")
                    .ToListAsync();

                logs.Add($"Found {guests.Count} checked-in guests");

                if (guests.Count == 0)
                {
                    // Debug: show what statuses exist
                    var allStatuses = await _dbContext.Guests
                        .Select(g => g.Status)
                        .Distinct()
                        .ToListAsync();

                    var totalGuests = await _dbContext.Guests.CountAsync();
                    logs.Add($"Total guests in database: {totalGuests}");
                    logs.Add($"Existing statuses: [{string.Join(", ", allStatuses)}]");

                    return Json(new
                    {
                        success = true,
                        message = $"No checked-in guests found. Total guests: {totalGuests}. Existing statuses: [{string.Join(", ", allStatuses)}]",
                        syncedCount = 0,
                        logs
                    });
                }

                // Log each guest being synced
                foreach (var g in guests.Take(10))
                {
                    logs.Add($"Syncing: Room {g.RoomNumber} - {g.GuestName}");
                }
                if (guests.Count > 10) logs.Add($"... and {guests.Count - 10} more");

                await freeRadiusService.SyncAllGuestsAsync();
                logs.Add("Sync completed successfully");

                return Json(new
                {
                    success = true,
                    message = $"Synced {guests.Count} guests to FreeRADIUS",
                    syncedCount = guests.Count,
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                _logger.LogError(ex, "Error syncing users to FreeRADIUS");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        /// <summary>
        /// Sync bandwidth profiles
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusSyncProfiles()
        {
            var logs = new List<string>();
            try
            {
                logs.Add("Starting profile sync...");

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                // Get active profiles
                var profiles = await _dbContext.BandwidthProfiles.Where(p => p.IsActive).ToListAsync();
                logs.Add($"Found {profiles.Count} active bandwidth profiles");

                foreach (var p in profiles)
                {
                    logs.Add($"Profile: {p.Name} ({p.DownloadSpeedKbps}kbps down / {p.UploadSpeedKbps}kbps up)");
                }

                await freeRadiusService.SyncBandwidthProfilesAsync();
                logs.Add("Profiles synced to FreeRADIUS radgroupreply");

                return Json(new
                {
                    success = true,
                    message = $"Synced {profiles.Count} profiles successfully",
                    syncedCount = profiles.Count,
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        /// <summary>
        /// Sync accounting data from FreeRADIUS radacct table to update guest usage
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusSyncAccounting()
        {
            var logs = new List<string>();
            try
            {
                logs.Add("Starting sync...");

                // Get settings directly
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var enabled = settings.FirstOrDefault(s => s.Key == "FreeRadiusEnabled")?.Value;
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                logs.Add($"FreeRadiusEnabled: {enabled ?? "null"}");
                logs.Add($"ConnectionString: {(string.IsNullOrEmpty(connStr) ? "EMPTY" : "SET (" + connStr.Length + " chars)")}");
                logs.Add($"TablePrefix: {prefix}");

                if (enabled?.ToLower() != "true")
                {
                    return Json(new { success = false, message = "FreeRADIUS is not enabled", logs });
                }

                if (string.IsNullOrEmpty(connStr))
                {
                    return Json(new { success = false, message = "Connection string is empty", logs });
                }

                // Connect to FreeRADIUS database
                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();
                logs.Add("Connected to FreeRADIUS database");

                // Get checked-in guests
                var guests = await _dbContext.Guests
                    .Where(g => g.Status.ToLower() == "checked-in" || g.Status.ToLower() == "checkedin")
                    .ToListAsync();
                logs.Add($"Found {guests.Count} checked-in guests");

                // Get active sessions
                var sessions = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active")
                    .ToListAsync();
                logs.Add($"Found {sessions.Count} active sessions");

                int updatedGuests = 0;
                int updatedSessions = 0;

                // Sync each guest
                foreach (var guest in guests)
                {
                    var sql = $@"
                        SELECT 
                            COALESCE(SUM(acctinputoctets), 0) as total_input,
                            COALESCE(SUM(acctoutputoctets), 0) as total_output
                        FROM {prefix}acct WHERE username = @username";

                    using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                    cmd.Parameters.AddWithValue("@username", guest.RoomNumber);

                    using var reader = await cmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        var inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                        var outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                        var totalBytes = inputBytes + outputBytes;

                        if (totalBytes > 0)
                        {
                            var oldUsage = guest.UsedQuotaBytes;
                            guest.UsedQuotaBytes = totalBytes;
                            updatedGuests++;
                            logs.Add($"Guest {guest.RoomNumber}: {oldUsage / 1048576.0:N2}MB -> {totalBytes / 1048576.0:N2}MB");
                        }
                    }
                }

                // Sync each session
                foreach (var session in sessions)
                {
                    var sql = $@"
                        SELECT 
                            COALESCE(SUM(acctinputoctets), 0) as total_input,
                            COALESCE(SUM(acctoutputoctets), 0) as total_output
                        FROM {prefix}acct WHERE username = @username";

                    using var cmd = new MySqlConnector.MySqlCommand(sql, connection);
                    cmd.Parameters.AddWithValue("@username", session.RoomNumber);

                    using var reader = await cmd.ExecuteReaderAsync();
                    if (await reader.ReadAsync())
                    {
                        var inputBytes = reader.IsDBNull(0) ? 0L : reader.GetInt64(0);
                        var outputBytes = reader.IsDBNull(1) ? 0L : reader.GetInt64(1);
                        var totalBytes = inputBytes + outputBytes;

                        if (totalBytes > 0)
                        {
                            var oldUsage = session.BytesUsed;
                            session.BytesDownloaded = inputBytes;
                            session.BytesUploaded = outputBytes;
                            session.BytesUsed = totalBytes;
                            session.LastActivity = DateTime.UtcNow;
                            updatedSessions++;
                            logs.Add($"Session {session.Id} (Room {session.RoomNumber}): {oldUsage / 1048576.0:N2}MB -> {totalBytes / 1048576.0:N2}MB");
                        }
                    }
                }

                // Save changes
                var changes = await _dbContext.SaveChangesAsync();
                logs.Add($"Saved {changes} changes to database");

                return Json(new
                {
                    success = true,
                    message = $"Synced {updatedGuests} guests and {updatedSessions} sessions",
                    updatedGuests,
                    updatedSessions,
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                _logger.LogError(ex, "Error syncing accounting from FreeRADIUS");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        /// <summary>
        /// Initialize FreeRADIUS database
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusInitDatabase()
        {
            var logs = new List<string>();
            try
            {
                logs.Add("Starting database initialization...");

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                logs.Add("Connecting to MySQL...");
                var result = await freeRadiusService.InitializeDatabaseAsync();

                if (result)
                {
                    logs.Add("Created/verified tables: radcheck, radreply, radgroupcheck, radgroupreply, radusergroup, radacct, radpostauth, nas");
                    logs.Add("Database initialization completed successfully");
                }
                else
                {
                    logs.Add("Database initialization returned false - check connection settings");
                }

                return Json(new
                {
                    success = result,
                    message = result ? "Database initialized successfully" : "Database initialization failed",
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        /// <summary>
        /// Cleanup checked-out guests
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusCleanup()
        {
            var logs = new List<string>();
            try
            {
                logs.Add("Starting cleanup of checked-out guests...");

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                // Count checked-out guests
                var checkedOutGuests = await _dbContext.Guests
                    .Where(g => g.Status.ToLower() == "checked-out" || g.Status.ToLower() == "checkedout")
                    .CountAsync();
                logs.Add($"Found {checkedOutGuests} checked-out guests to remove");

                await freeRadiusService.CleanupCheckedOutGuestsAsync();
                logs.Add("Cleanup completed - removed from radcheck and radreply tables");

                return Json(new
                {
                    success = true,
                    message = $"Cleanup completed - removed {checkedOutGuests} users",
                    removedCount = checkedOutGuests,
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        /// <summary>
        /// Delete a specific user from FreeRADIUS
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusDeleteUser([FromBody] DeleteUserRequest request)
        {
            var logs = new List<string>();
            try
            {
                if (string.IsNullOrEmpty(request?.Username))
                {
                    return Json(new { success = false, message = "Username is required" });
                }

                logs.Add($"Deleting user: {request.Username}");

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                var result = await freeRadiusService.DeleteUserAsync(request.Username);

                if (result)
                {
                    logs.Add("User deleted from radcheck, radreply, radusergroup");

                    // Also update portal database if guest exists
                    var guest = await _dbContext.Guests.FirstOrDefaultAsync(g => g.RoomNumber == request.Username);
                    if (guest != null && request.ResetUsage)
                    {
                        guest.UsedQuotaBytes = 0;
                        await _dbContext.SaveChangesAsync();
                        logs.Add($"Reset usage for guest in Room {request.Username}");
                    }
                }

                return Json(new
                {
                    success = result,
                    message = result ? $"User {request.Username} deleted successfully" : "Failed to delete user",
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        /// <summary>
        /// Delete ALL users from FreeRADIUS
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusDeleteAllUsers()
        {
            var logs = new List<string>();
            try
            {
                logs.Add("Starting deletion of ALL users from FreeRADIUS...");

                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                var (deleted, message) = await freeRadiusService.DeleteAllUsersAsync();

                logs.Add(message);
                logs.Add("Tables cleared: radcheck, radreply, radusergroup");

                return Json(new
                {
                    success = deleted > 0 || message.Contains("Deleted"),
                    message = message,
                    deletedCount = deleted,
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        /// <summary>
        /// Clear all Mikrotik-Total-Limit entries from radreply
        /// This enables room-level quota enforcement by the portal
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusClearQuotaLimits()
        {
            try
            {
                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                var count = await freeRadiusService.ClearAllQuotaLimitsAsync();

                return Json(new
                {
                    success = true,
                    message = count > 0
                        ? $"Cleared {count} Mikrotik-Total-Limit entries. Room-level quota will now be enforced by the portal."
                        : "No quota limit entries found in radreply.",
                    clearedCount = count
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Get FreeRADIUS table statistics
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> FreeRadiusTableStats()
        {
            try
            {
                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                var stats = await freeRadiusService.GetTableStatsAsync();

                return Json(new { success = true, stats });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Test CoA (Disconnect) to a specific session
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusTestCoA([FromBody] TestCoARequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request?.NasIp))
                {
                    return Json(new { success = false, message = "NAS IP is required" });
                }

                var logs = new List<string>();
                logs.Add($"Testing CoA Disconnect to NAS: {request.NasIp}");
                logs.Add($"MAC: {request.MacAddress ?? "Not specified"}");
                logs.Add($"Session ID: {request.SessionId ?? "Not specified"}");

                using var scope = HttpContext.RequestServices.CreateScope();
                var radiusServer = scope.ServiceProvider.GetRequiredService<RadiusServer>();

                var result = await radiusServer.DisconnectUserAsync(
                    request.NasIp,
                    request.MacAddress ?? "",
                    request.SessionId ?? "");

                logs.Add($"CoA Result: {(result ? "SUCCESS (Disconnect-ACK received)" : "FAILED (Timeout or NAK)")}");

                return Json(new
                {
                    success = result,
                    message = result ? "Disconnect successful!" : "Disconnect failed - check logs for details",
                    logs
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        public class TestCoARequest
        {
            public string? NasIp { get; set; }
            public string? MacAddress { get; set; }
            public string? SessionId { get; set; }
        }

        /// <summary>
        /// Force check quota and disconnect exceeded sessions
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusForceQuotaCheck()
        {
            try
            {
                var logs = new List<string>();
                logs.Add("=== Starting Manual Quota Check ===");

                using var scope = HttpContext.RequestServices.CreateScope();
                var wifiService = scope.ServiceProvider.GetRequiredService<WifiService>();

                logs.Add("Calling CheckQuotaExceededAsync...");
                await wifiService.CheckQuotaExceededAsync();
                logs.Add("Quota check completed - check server logs for details");

                return Json(new { success = true, message = "Quota check completed", logs });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Reset guest usage in portal and optionally FreeRADIUS
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusResetGuestUsage([FromBody] DeleteUserRequest request)
        {
            var logs = new List<string>();
            try
            {
                if (string.IsNullOrEmpty(request?.Username))
                {
                    return Json(new { success = false, message = "Username/Room number is required" });
                }

                logs.Add($"Resetting usage for: {request.Username}");

                // Reset in portal database
                var guest = await _dbContext.Guests.FirstOrDefaultAsync(g => g.RoomNumber == request.Username);
                if (guest != null)
                {
                    var oldUsage = guest.UsedQuotaBytes;
                    guest.UsedQuotaBytes = 0;
                    await _dbContext.SaveChangesAsync();
                    logs.Add($"Portal: Reset usage from {oldUsage / 1048576.0:N2}MB to 0");
                }
                else
                {
                    logs.Add($"Guest not found in portal: {request.Username}");
                }

                // Reset in FreeRADIUS radacct
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (!string.IsNullOrEmpty(connStr))
                {
                    using var connection = new MySqlConnector.MySqlConnection(connStr);
                    await connection.OpenAsync();

                    // Update existing accounting records to zero
                    using var cmd = new MySqlConnector.MySqlCommand(
                        $"UPDATE {prefix}acct SET acctinputoctets = 0, acctoutputoctets = 0 WHERE username = @username",
                        connection);
                    cmd.Parameters.AddWithValue("@username", request.Username);
                    var updated = await cmd.ExecuteNonQueryAsync();
                    logs.Add($"FreeRADIUS: Reset {updated} accounting records");
                }

                return Json(new
                {
                    success = true,
                    message = $"Usage reset for {request.Username}",
                    logs
                });
            }
            catch (Exception ex)
            {
                logs.Add($"ERROR: {ex.Message}");
                return Json(new { success = false, message = ex.Message, logs });
            }
        }

        public class DeleteUserRequest
        {
            public string Username { get; set; } = "";
            public bool ResetUsage { get; set; }
        }

        /// <summary>
        /// Get RADIUS users from database
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> FreeRadiusGetUsers()
        {
            try
            {
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (string.IsNullOrEmpty(connStr))
                    return Json(new { success = false, message = "Not configured" });

                var users = new List<object>();
                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();

                using var cmd = new MySqlConnector.MySqlCommand(
                    $"SELECT username, attribute, value FROM {prefix}check ORDER BY username LIMIT 100",
                    connection);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    users.Add(new
                    {
                        username = reader.GetString("username"),
                        attribute = reader.GetString("attribute"),
                        value = reader.GetString("value").Length > 20 ? reader.GetString("value").Substring(0, 20) + "..." : reader.GetString("value")
                    });
                }

                return Json(new { success = true, users });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Get active sessions
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> FreeRadiusGetSessions()
        {
            try
            {
                using var scope = HttpContext.RequestServices.CreateScope();
                var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

                var sessions = await freeRadiusService.GetActiveSessionsAsync();

                return Json(new
                {
                    success = true,
                    sessions = sessions.Select(s => new {
                        s.Username,
                        s.FramedIpAddress,
                        duration = s.Duration.ToString(@"hh\:mm\:ss"),
                        usage = FormatBytes(s.TotalBytes)
                    })
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Get accounting data from radacct table for debugging
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> FreeRadiusGetAccounting()
        {
            try
            {
                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (string.IsNullOrEmpty(connStr))
                    return Json(new { success = false, message = "FreeRADIUS connection string not configured" });

                var records = new List<object>();
                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();

                // Get accounting summary grouped by username
                using var cmd = new MySqlConnector.MySqlCommand($@"
                    SELECT 
                        username,
                        COUNT(*) as session_count,
                        SUM(acctinputoctets) as total_input,
                        SUM(acctoutputoctets) as total_output,
                        MAX(acctstarttime) as last_session,
                        MAX(acctstoptime) as last_stop
                    FROM {prefix}acct 
                    GROUP BY username
                    ORDER BY last_session DESC
                    LIMIT 50", connection);

                using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var inputBytes = reader.IsDBNull(reader.GetOrdinal("total_input")) ? 0L : reader.GetInt64("total_input");
                    var outputBytes = reader.IsDBNull(reader.GetOrdinal("total_output")) ? 0L : reader.GetInt64("total_output");

                    records.Add(new
                    {
                        username = reader.GetString("username"),
                        sessionCount = reader.GetInt32("session_count"),
                        inputMB = (inputBytes / 1048576.0).ToString("N2"),
                        outputMB = (outputBytes / 1048576.0).ToString("N2"),
                        totalMB = ((inputBytes + outputBytes) / 1048576.0).ToString("N2"),
                        lastSession = reader.IsDBNull(reader.GetOrdinal("last_session")) ? "N/A" : reader.GetDateTime("last_session").ToString("yyyy-MM-dd HH:mm"),
                        isActive = reader.IsDBNull(reader.GetOrdinal("last_stop"))
                    });
                }

                // Also get app's active sessions for comparison
                var appSessions = await _dbContext.WifiSessions
                    .Where(s => s.Status == "Active")
                    .Select(s => new {
                        s.Id,
                        s.RoomNumber,
                        s.MacAddress,
                        s.GuestId,
                        s.Status,
                        s.BytesUsed,
                        s.BytesDownloaded,
                        s.BytesUploaded
                    })
                    .ToListAsync();

                // And checked-in guests
                var guests = await _dbContext.Guests
                    .Where(g => g.Status.ToLower() == "checked-in" || g.Status.ToLower() == "checkedin")
                    .Select(g => new {
                        g.Id,
                        g.RoomNumber,
                        g.Status,
                        g.UsedQuotaBytes,
                        g.TotalQuotaBytes
                    })
                    .ToListAsync();

                return Json(new
                {
                    success = true,
                    radacctRecords = records,
                    appSessions = appSessions.Select(s => new {
                        s.Id,
                        s.RoomNumber,
                        s.MacAddress,
                        s.GuestId,
                        s.Status,
                        usageMB = (s.BytesUsed / 1048576.0).ToString("N2"),
                        downloadMB = (s.BytesDownloaded / 1048576.0).ToString("N2"),
                        uploadMB = (s.BytesUploaded / 1048576.0).ToString("N2")
                    }),
                    guests = guests.Select(g => new {
                        g.Id,
                        g.RoomNumber,
                        g.Status,
                        usageMB = (g.UsedQuotaBytes / 1048576.0).ToString("N2"),
                        quotaMB = (g.TotalQuotaBytes / 1048576.0).ToString("N2")
                    }),
                    troubleshooting = new
                    {
                        tip1 = "For sync to work: radacct.username must match WifiSession.RoomNumber",
                        tip2 = "Session must have Status='Active' to be synced",
                        tip3 = "Session must have valid GuestId > 0 to update guest usage",
                        tip4 = "Guest must be 'checked-in' status"
                    },
                    message = $"Found {records.Count} usernames in radacct, {appSessions.Count} active sessions, {guests.Count} checked-in guests"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting accounting data");
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Create test user
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusCreateUser([FromBody] CreateUserModel? model)
        {
            try
            {
                if (model == null || string.IsNullOrEmpty(model.Username))
                    return Json(new { success = false, message = "Username is required" });

                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;
                var prefix = settings.FirstOrDefault(s => s.Key == "FreeRadiusTablePrefix")?.Value ?? "rad";

                if (string.IsNullOrEmpty(connStr))
                    return Json(new { success = false, message = "Not configured" });

                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();

                // Delete existing
                using (var delCmd = new MySqlConnector.MySqlCommand($"DELETE FROM {prefix}check WHERE username = @username", connection))
                {
                    delCmd.Parameters.AddWithValue("@username", model.Username);
                    await delCmd.ExecuteNonQueryAsync();
                }
                using (var delCmd = new MySqlConnector.MySqlCommand($"DELETE FROM {prefix}reply WHERE username = @username", connection))
                {
                    delCmd.Parameters.AddWithValue("@username", model.Username);
                    await delCmd.ExecuteNonQueryAsync();
                }

                // Insert radcheck
                using (var insCmd = new MySqlConnector.MySqlCommand(
                    $"INSERT INTO {prefix}check (username, attribute, op, value) VALUES (@username, 'Cleartext-Password', ':=', @password)",
                    connection))
                {
                    insCmd.Parameters.AddWithValue("@username", model.Username);
                    insCmd.Parameters.AddWithValue("@password", model.Password ?? "password");
                    await insCmd.ExecuteNonQueryAsync();
                }

                // Insert radreply
                var downloadKbps = model.DownloadKbps > 0 ? model.DownloadKbps : 2048;
                var uploadKbps = model.UploadKbps > 0 ? model.UploadKbps : 1024;
                using (var insCmd = new MySqlConnector.MySqlCommand(
                    $"INSERT INTO {prefix}reply (username, attribute, op, value) VALUES (@username, 'Mikrotik-Rate-Limit', ':=', @rateLimit)",
                    connection))
                {
                    insCmd.Parameters.AddWithValue("@username", model.Username);
                    insCmd.Parameters.AddWithValue("@rateLimit", $"{uploadKbps}k/{downloadKbps}k");
                    await insCmd.ExecuteNonQueryAsync();
                }

                return Json(new { success = true, message = $"User '{model.Username}' created" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Get database schema
        /// </summary>
        [HttpGet]
        public IActionResult FreeRadiusGetSchema()
        {
            using var scope = HttpContext.RequestServices.CreateScope();
            var freeRadiusService = scope.ServiceProvider.GetRequiredService<FreeRadiusService>();

            return Json(new { schema = freeRadiusService.GetDatabaseSchema() });
        }

        /// <summary>
        /// Execute custom query
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusExecuteQuery([FromBody] QueryModel? model)
        {
            try
            {
                if (model == null || string.IsNullOrEmpty(model.Query))
                {
                    return Json(new { success = false, message = "Query is required" });
                }

                // Security: Only allow SELECT queries
                if (!model.Query.Trim().StartsWith("SELECT", StringComparison.OrdinalIgnoreCase))
                    return Json(new { success = false, message = "Only SELECT queries are allowed" });

                var settings = await _dbContext.SystemSettings.ToListAsync();
                var connStr = settings.FirstOrDefault(s => s.Key == "FreeRadiusConnectionString")?.Value;

                if (string.IsNullOrEmpty(connStr))
                    return Json(new { success = false, message = "Not configured" });

                var rows = new List<Dictionary<string, object?>>();

                using var connection = new MySqlConnector.MySqlConnection(connStr);
                await connection.OpenAsync();

                // Only add LIMIT if not already present
                var query = model.Query.Trim().TrimEnd(';');
                if (!query.Contains("LIMIT", StringComparison.OrdinalIgnoreCase))
                    query += " LIMIT 100";

                using var cmd = new MySqlConnector.MySqlCommand(query, connection);
                using var reader = await cmd.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var row = new Dictionary<string, object?>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
                    }
                    rows.Add(row);
                }

                return Json(new { success = true, rows });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        /// <summary>
        /// Get debug logs
        /// </summary>
        [HttpGet]
        public IActionResult FreeRadiusGetDebugLogs()
        {
            // Return recent system logs related to FreeRADIUS
            var recentLogs = _dbContext.SystemLogs
                .Where(l => l.Category == "FreeRADIUS" || l.Category == "RADIUS")
                .OrderByDescending(l => l.Timestamp)
                .Take(20)
                .Select(l => new { level = l.Level.ToLower(), message = l.Message, time = l.Timestamp.ToString("HH:mm:ss") })
                .ToList();

            return Json(new { logs = recentLogs });
        }

        /// <summary>
        /// Send RADIUS packet for testing - supports PAP, CHAP, accounting, status-server
        /// </summary>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> FreeRadiusSendPacket([FromBody] RadiusPacketModel? model)
        {
            if (model == null)
                return Json(new { success = false, error = "Invalid request", message = "No packet data provided" });

            try
            {
                var serverIp = model.ServerIp ?? "127.0.0.1";
                var serverPort = model.ServerPort > 0 ? model.ServerPort : 1812;
                var secret = model.Secret ?? "";
                var timeout = Math.Min(Math.Max(model.Timeout, 1), 30) * 1000;

                using var udpClient = new System.Net.Sockets.UdpClient();
                udpClient.Client.ReceiveTimeout = timeout;

                var requestPacket = BuildRadiusPacket(model, secret);
                var requestHex = BitConverter.ToString(requestPacket).Replace("-", " ");

                var startTime = DateTime.UtcNow;
                await udpClient.SendAsync(requestPacket, requestPacket.Length, serverIp, serverPort);

                try
                {
                    var remoteEp = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
                    var responseData = udpClient.Receive(ref remoteEp);
                    var roundTripMs = (DateTime.UtcNow - startTime).TotalMilliseconds;

                    var responseHex = BitConverter.ToString(responseData).Replace("-", " ");
                    var (responseCode, attributes) = ParseRadiusResponse(responseData, secret);

                    _logger.LogInformation("RADIUS packet test: {RequestType} to {Server}:{Port} - {ResponseCode} in {RoundTripMs}ms",
                        model.RequestType, serverIp, serverPort, responseCode, roundTripMs);

                    return Json(new
                    {
                        success = true,
                        responseCode,
                        roundTripMs = Math.Round(roundTripMs, 2),
                        attributes,
                        requestHex,
                        responseHex,
                        message = $"Response received from {serverIp}:{serverPort}"
                    });
                }
                catch (System.Net.Sockets.SocketException ex) when (ex.SocketErrorCode == System.Net.Sockets.SocketError.TimedOut)
                {
                    return Json(new
                    {
                        success = false,
                        error = "Timeout",
                        message = $"No response received within {model.Timeout} seconds",
                        requestHex
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RADIUS packet test failed");
                return Json(new { success = false, error = "Error", message = ex.Message });
            }
        }

        private byte[] BuildRadiusPacket(RadiusPacketModel model, string secret)
        {
            var packet = new List<byte>();
            var authenticator = new byte[16];
            new Random().NextBytes(authenticator);

            byte code = model.RequestType switch
            {
                "access-request" => 1,
                "accounting-start" or "accounting-stop" or "accounting-update" => 4,
                "status-server" => 12,
                "coa-request" => 43,
                "disconnect-request" => 40,
                _ => 1
            };

            packet.Add(code);
            packet.Add((byte)new Random().Next(1, 255));
            packet.AddRange(new byte[] { 0, 0 });
            packet.AddRange(authenticator);

            if (code == 1)
            {
                if (!string.IsNullOrEmpty(model.Username))
                    AddRadiusAttribute(packet, 1, System.Text.Encoding.UTF8.GetBytes(model.Username));

                if (model.AuthProtocol == "CHAP")
                {
                    var chapId = (byte)new Random().Next(0, 255);
                    var chapResponse = ComputeChapResponse(chapId, model.Password ?? "", authenticator);
                    var chapPassword = new byte[17];
                    chapPassword[0] = chapId;
                    Array.Copy(chapResponse, 0, chapPassword, 1, 16);
                    AddRadiusAttribute(packet, 3, chapPassword);
                }
                else
                {
                    var encryptedPassword = EncryptPapPassword(model.Password ?? "", secret, authenticator);
                    AddRadiusAttribute(packet, 2, encryptedPassword);
                }
            }
            else if (code == 4)
            {
                int statusType = model.RequestType switch
                {
                    "accounting-start" => 1,
                    "accounting-stop" => 2,
                    "accounting-update" => 3,
                    _ => 1
                };
                AddRadiusAttribute(packet, 40, BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(statusType)));

                if (!string.IsNullOrEmpty(model.Username))
                    AddRadiusAttribute(packet, 1, System.Text.Encoding.UTF8.GetBytes(model.Username));

                if (!string.IsNullOrEmpty(model.SessionId))
                    AddRadiusAttribute(packet, 44, System.Text.Encoding.UTF8.GetBytes(model.SessionId));

                if (model.SessionTime > 0)
                    AddRadiusAttribute(packet, 46, BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(model.SessionTime)));

                if (model.InputBytes > 0)
                    AddRadiusAttribute(packet, 42, BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(model.InputBytes)));

                if (model.OutputBytes > 0)
                    AddRadiusAttribute(packet, 43, BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(model.OutputBytes)));
            }

            if (!string.IsNullOrEmpty(model.NasIdentifier))
                AddRadiusAttribute(packet, 32, System.Text.Encoding.UTF8.GetBytes(model.NasIdentifier));

            if (!string.IsNullOrEmpty(model.NasIpAddress) && System.Net.IPAddress.TryParse(model.NasIpAddress, out var nasIp))
                AddRadiusAttribute(packet, 4, nasIp.GetAddressBytes());

            if (!string.IsNullOrEmpty(model.CallingStationId))
                AddRadiusAttribute(packet, 31, System.Text.Encoding.UTF8.GetBytes(model.CallingStationId));

            var packetArray = packet.ToArray();
            var length = (ushort)packetArray.Length;
            packetArray[2] = (byte)(length >> 8);
            packetArray[3] = (byte)(length & 0xFF);

            if (code == 4)
            {
                Array.Clear(packetArray, 4, 16);
                using var md5 = System.Security.Cryptography.MD5.Create();
                var hashInput = packetArray.Concat(System.Text.Encoding.UTF8.GetBytes(secret)).ToArray();
                var hash = md5.ComputeHash(hashInput);
                Array.Copy(hash, 0, packetArray, 4, 16);
            }

            return packetArray;
        }

        private void AddRadiusAttribute(List<byte> packet, byte type, byte[] value)
        {
            if (value.Length > 253) return;
            packet.Add(type);
            packet.Add((byte)(value.Length + 2));
            packet.AddRange(value);
        }

        private byte[] EncryptPapPassword(string password, string secret, byte[] authenticator)
        {
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            var paddedPassword = new byte[((passwordBytes.Length + 15) / 16) * 16];
            if (paddedPassword.Length == 0) paddedPassword = new byte[16];
            Array.Copy(passwordBytes, paddedPassword, Math.Min(passwordBytes.Length, paddedPassword.Length));

            using var md5 = System.Security.Cryptography.MD5.Create();
            var result = new byte[paddedPassword.Length];
            var lastBlock = authenticator;

            for (int i = 0; i < paddedPassword.Length; i += 16)
            {
                var hashInput = System.Text.Encoding.UTF8.GetBytes(secret).Concat(lastBlock).ToArray();
                var hash = md5.ComputeHash(hashInput);

                for (int j = 0; j < 16; j++)
                    result[i + j] = (byte)(paddedPassword[i + j] ^ hash[j]);

                lastBlock = new byte[16];
                Array.Copy(result, i, lastBlock, 0, 16);
            }

            return result;
        }

        private byte[] ComputeChapResponse(byte chapId, string password, byte[] challenge)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            var input = new byte[] { chapId }.Concat(System.Text.Encoding.UTF8.GetBytes(password)).Concat(challenge).ToArray();
            return md5.ComputeHash(input);
        }

        private (string code, List<object> attributes) ParseRadiusResponse(byte[] data, string secret)
        {
            if (data.Length < 20) return ("Invalid", new List<object>());

            var code = data[0] switch
            {
                2 => "Access-Accept",
                3 => "Access-Reject",
                5 => "Accounting-Response",
                11 => "Access-Challenge",
                _ => $"Code-{data[0]}"
            };

            var attributes = new List<object>();
            int pos = 20;

            while (pos < data.Length - 1)
            {
                var attrType = data[pos];
                var attrLen = data[pos + 1];
                if (attrLen < 2 || pos + attrLen > data.Length) break;

                var value = new byte[attrLen - 2];
                Array.Copy(data, pos + 2, value, 0, attrLen - 2);

                var attrName = GetRadiusAttributeName(attrType);
                var attrValue = FormatRadiusAttributeValue(attrType, value);

                attributes.Add(new { name = attrName, value = attrValue });
                pos += attrLen;
            }

            return (code, attributes);
        }

        private string GetRadiusAttributeName(byte type) => type switch
        {
            1 => "User-Name",
            2 => "User-Password",
            3 => "CHAP-Password",
            4 => "NAS-IP-Address",
            5 => "NAS-Port",
            6 => "Service-Type",
            8 => "Framed-IP-Address",
            18 => "Reply-Message",
            24 => "State",
            25 => "Class",
            26 => "Vendor-Specific",
            27 => "Session-Timeout",
            28 => "Idle-Timeout",
            31 => "Calling-Station-Id",
            32 => "NAS-Identifier",
            40 => "Acct-Status-Type",
            42 => "Acct-Input-Octets",
            43 => "Acct-Output-Octets",
            44 => "Acct-Session-Id",
            46 => "Acct-Session-Time",
            _ => $"Attribute-{type}"
        };

        private string FormatRadiusAttributeValue(byte type, byte[] value)
        {
            if ((type == 4 || type == 8) && value.Length == 4)
                return new System.Net.IPAddress(value).ToString();
            if ((type == 5 || type == 6 || type == 27 || type == 28 || type == 40 || type == 42 || type == 43 || type == 46) && value.Length == 4)
                return System.Net.IPAddress.NetworkToHostOrder(BitConverter.ToInt32(value, 0)).ToString();
            return System.Text.Encoding.UTF8.GetString(value).TrimEnd('\0');
        }

        #endregion
    }

    public class RadiusPacketModel
    {
        public string? ServerIp { get; set; }
        public int ServerPort { get; set; } = 1812;
        public string? Secret { get; set; }
        public string? RequestType { get; set; }
        public string? AuthProtocol { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? SessionId { get; set; }
        public string? FramedIp { get; set; }
        public int SessionTime { get; set; }
        public int InputBytes { get; set; }
        public int OutputBytes { get; set; }
        public string? NasIdentifier { get; set; }
        public string? NasIpAddress { get; set; }
        public string? CallingStationId { get; set; }
        public int Timeout { get; set; } = 5;
    }

    public class ConnectionTestResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string ControllerType { get; set; } = "";
        public string ControllerName { get; set; } = "";
        public string? IpAddress { get; set; }
        public DateTime TestStarted { get; set; }
        public DateTime TestCompleted { get; set; }
        public double Duration { get; set; }
        public int ActiveSessions { get; set; }
        public List<TestStep> Steps { get; set; } = new();
        public Dictionary<string, string>? SystemInfo { get; set; }
    }

    public class TestStep
    {
        public string Name { get; set; } = "";
        public string Status { get; set; } = "pending"; // pending, testing, success, warning, failed
        public string? Message { get; set; }
    }

    public class FreeRadiusConfigModel
    {
        public bool Enabled { get; set; }
        public bool DisableBuiltin { get; set; }
        public string ConnectionString { get; set; } = "";
        public string TablePrefix { get; set; } = "rad";
        public string NasSecret { get; set; } = "";
        public int SyncInterval { get; set; } = 5;
        public int CoAPort { get; set; } = 3799;
        public int AuthPort { get; set; } = 1812;
        public int AcctPort { get; set; } = 1813;
        public string DefaultProtocol { get; set; } = "PAP";
        public string RadiusServer { get; set; } = "127.0.0.1";
    }

    public class ConnectionStringModel
    {
        public string ConnectionString { get; set; } = "";
    }

    public class QueryModel
    {
        public string Query { get; set; } = "";
    }

    public class AuthTestModel
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }

    public class CoaTestModel
    {
        public string? NasIp { get; set; }
        public string? Username { get; set; }
        public string? Action { get; set; }
        public int? DownloadKbps { get; set; }
        public int? UploadKbps { get; set; }
    }

    public class CreateUserModel
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
        public int DownloadKbps { get; set; }
        public int UploadKbps { get; set; }
    }
}