using HotelWifiPortal.Data;
using HotelWifiPortal.Services;
using HotelWifiPortal.Services.PMS;
using HotelWifiPortal.Services.Radius;
using HotelWifiPortal.Services.WiFi;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllersWithViews()
    .AddRazorOptions(options =>
    {
        options.ViewLocationFormats.Add("/Views/Admin/{1}/{0}.cshtml");
        options.ViewLocationFormats.Add("/Views/Admin/Shared/{0}.cshtml");
    });

// Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=hotelwifi.db"));

// Authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Portal";
        options.LogoutPath = "/Portal/Logout";
        options.AccessDeniedPath = "/Portal/Error";
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;
        options.Events.OnRedirectToLogin = context =>
        {
            // For API requests, return 401 instead of redirect
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = 401;
                return Task.CompletedTask;
            }

            // Redirect admin area to admin login
            if (context.Request.Path.StartsWithSegments("/Admin"))
            {
                var returnUrl = context.Request.Path + context.Request.QueryString;
                context.Response.Redirect($"/Admin/Dashboard/Login?ReturnUrl={Uri.EscapeDataString(returnUrl)}");
            }
            else
            {
                context.Response.Redirect(context.RedirectUri);
            }
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            // For API requests, return 403 instead of redirect
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = 403;
                return Task.CompletedTask;
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization();

// Session
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(24);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// HTTP Client Factory for WiFi controllers
builder.Services.AddHttpClient("RuckusClient")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
    });

builder.Services.AddHttpClient("MikrotikClient")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
    });

builder.Services.AddHttpClient("ExtremeCloudClient")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
    });

// Core Services
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<QuotaService>();
builder.Services.AddScoped<PaymentService>();

// PMS Services
builder.Services.AddSingleton<FiasProtocolService>();
builder.Services.AddSingleton<FiasSocketServer>();
builder.Services.AddHostedService<FiasServerBackgroundService>();

// RADIUS Server (for MikroTik/NAS authentication)
// Built-in RADIUS server
builder.Services.AddSingleton<RadiusServer>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<RadiusServer>());

// FreeRADIUS integration (optional external RADIUS)
builder.Services.AddScoped<FreeRadiusService>();
builder.Services.AddHostedService<FreeRadiusSyncService>();

// WiFi Services
builder.Services.AddSingleton<WifiControllerFactory>();
builder.Services.AddScoped<WifiService>();
builder.Services.AddScoped<MikrotikAuthService>();
builder.Services.AddHostedService<WifiMonitoringService>();

// PMS Auto-Posting Service (monitors PMS connection and posts pending payments)
builder.Services.AddHostedService<PmsPostingService>();

// SignalR
builder.Services.AddSignalR();

// Logging
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
});

var app = builder.Build();

// Initialize database
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    try
    {
        dbContext.Database.EnsureCreated();

        // Ensure admin user exists
        if (!dbContext.AdminUsers.Any(u => u.Username == "admin"))
        {
            logger.LogInformation("Creating default admin user...");
            dbContext.AdminUsers.Add(new HotelWifiPortal.Models.Entities.AdminUser
            {
                Username = "admin",
                PasswordHash = HotelWifiPortal.Data.BCryptHelper.HashPassword("admin123"),
                Email = "admin@hotel.com",
                FullName = "System Administrator",
                Role = "SuperAdmin",
                IsActive = true
            });
            dbContext.SaveChanges();
            logger.LogInformation("Default admin user created: admin / admin123");
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error initializing database");
    }
}

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

// Route configuration
app.MapControllers(); // For attribute-routed API controllers

// Portal routes should come FIRST (guest-facing)
app.MapControllerRoute(
    name: "portal",
    pattern: "Portal/{action=Index}/{id?}",
    defaults: new { controller = "Portal" });

// Admin routes (staff-facing)
app.MapControllerRoute(
    name: "admin",
    pattern: "Admin/{controller=Dashboard}/{action=Index}/{id?}");

// Default route
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Portal}/{action=Index}/{id?}");

// Captive portal detection URLs
app.MapGet("/generate_204", () => Results.Redirect("/Portal"));
app.MapGet("/hotspot-detect.html", () => Results.Redirect("/Portal"));
app.MapGet("/connecttest.txt", () => Results.Redirect("/Portal"));
app.MapGet("/ncsi.txt", () => Results.Redirect("/Portal"));
app.MapGet("/success.txt", () => Results.Ok("success"));

// Admin shortcut
app.MapGet("/Admin", () => Results.Redirect("/Admin/Dashboard"));
app.MapGet("/Admin/Login", () => Results.Redirect("/Admin/Dashboard/Login"));

app.Run();