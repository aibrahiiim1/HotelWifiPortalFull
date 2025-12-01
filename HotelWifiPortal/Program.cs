using HotelWifiPortal.Data;
using HotelWifiPortal.Services;
using HotelWifiPortal.Services.PMS;
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

// WiFi Services
builder.Services.AddSingleton<WifiControllerFactory>();
builder.Services.AddScoped<WifiService>();
builder.Services.AddHostedService<WifiMonitoringService>();

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
    dbContext.Database.EnsureCreated();
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
app.MapControllerRoute(
    name: "admin",
    pattern: "Admin/{controller=Dashboard}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "portal",
    pattern: "Portal/{action=Index}/{id?}",
    defaults: new { controller = "Portal" });

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