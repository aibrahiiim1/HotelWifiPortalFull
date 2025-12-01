using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using HotelWifiPortal.Models.ViewModels;
using HotelWifiPortal.Services.PMS;
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

        public SettingsController(
            ApplicationDbContext dbContext,
            FiasSocketServer fiasServer,
            WifiService wifiService,
            ILogger<SettingsController> logger)
        {
            _dbContext = dbContext;
            _fiasServer = fiasServer;
            _wifiService = wifiService;
            _logger = logger;
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
                TimeZone = settings.FirstOrDefault(s => s.Key == "TimeZone")?.Value ?? "UTC"
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
                { "TimeZone", model.TimeZone }
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
            pmsSettings.PostingCurrency = model.PostingCurrency;
            pmsSettings.PostingDescription = model.PostingDescription;
            pmsSettings.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("PMS settings updated");
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
    }
}
