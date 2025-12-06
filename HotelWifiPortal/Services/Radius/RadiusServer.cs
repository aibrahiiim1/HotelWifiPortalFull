using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using HotelWifiPortal.Data;
using HotelWifiPortal.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace HotelWifiPortal.Services.Radius
{
    /// <summary>
    /// RADIUS Protocol Constants
    /// </summary>
    public static class RadiusCode
    {
        public const byte AccessRequest = 1;
        public const byte AccessAccept = 2;
        public const byte AccessReject = 3;
        public const byte AccountingRequest = 4;
        public const byte AccountingResponse = 5;
        public const byte AccessChallenge = 11;
        public const byte DisconnectRequest = 40;
        public const byte DisconnectAck = 41;
        public const byte DisconnectNak = 42;
        public const byte CoARequest = 43;
        public const byte CoAAck = 44;
        public const byte CoANak = 45;
    }

    /// <summary>
    /// RADIUS Attribute Types
    /// </summary>
    public static class RadiusAttribute
    {
        public const byte UserName = 1;
        public const byte UserPassword = 2;
        public const byte ChapPassword = 3;
        public const byte NasIpAddress = 4;
        public const byte NasPort = 5;
        public const byte ServiceType = 6;
        public const byte FramedProtocol = 7;
        public const byte FramedIpAddress = 8;
        public const byte FramedIpNetmask = 9;
        public const byte FramedRouting = 10;
        public const byte FilterId = 11;
        public const byte FramedMtu = 12;
        public const byte FramedCompression = 13;
        public const byte LoginIpHost = 14;
        public const byte LoginService = 15;
        public const byte LoginTcpPort = 16;
        public const byte ReplyMessage = 18;
        public const byte CallbackNumber = 19;
        public const byte CallbackId = 20;
        public const byte FramedRoute = 22;
        public const byte FramedIpxNetwork = 23;
        public const byte State = 24;
        public const byte Class = 25;
        public const byte VendorSpecific = 26;
        public const byte SessionTimeout = 27;
        public const byte IdleTimeout = 28;
        public const byte TerminationAction = 29;
        public const byte CalledStationId = 30;
        public const byte CallingStationId = 31;
        public const byte NasIdentifier = 32;
        public const byte ProxyState = 33;
        public const byte AcctStatusType = 40;
        public const byte AcctDelayTime = 41;
        public const byte AcctInputOctets = 42;
        public const byte AcctOutputOctets = 43;
        public const byte AcctSessionId = 44;
        public const byte AcctAuthentic = 45;
        public const byte AcctSessionTime = 46;
        public const byte AcctInputPackets = 47;
        public const byte AcctOutputPackets = 48;
        public const byte AcctTerminateCause = 49;
        public const byte AcctMultiSessionId = 50;
        public const byte AcctLinkCount = 51;
        public const byte AcctInputGigawords = 52;
        public const byte AcctOutputGigawords = 53;
        public const byte EventTimestamp = 55;
        public const byte ChapChallenge = 60;
        public const byte NasPortType = 61;
        public const byte PortLimit = 62;
        public const byte LoginLatPort = 63;
        
        // MikroTik Vendor Specific Attributes (Vendor ID: 14988)
        public const int MikroTikVendorId = 14988;
        public const byte MikroTikRecvLimit = 1;
        public const byte MikroTikXmitLimit = 2;
        public const byte MikroTikGroup = 3;
        public const byte MikroTikWirelessForward = 4;
        public const byte MikroTikWirelessSkipDot1x = 5;
        public const byte MikroTikWirelessEncAlgo = 6;
        public const byte MikroTikWirelessEncKey = 7;
        public const byte MikroTikRateLimit = 8;
        public const byte MikroTikRealm = 9;
        public const byte MikroTikHostIp = 10;
        public const byte MikroTikMarkId = 11;
        public const byte MikroTikAdvertiseUrl = 12;
        public const byte MikroTikAdvertiseInterval = 13;
        public const byte MikroTikRecvLimitGigawords = 14;
        public const byte MikroTikXmitLimitGigawords = 15;
        public const byte MikroTikWirelessPsk = 16;
        public const byte MikroTikTotalLimit = 17;
        public const byte MikroTikTotalLimitGigawords = 18;
        public const byte MikroTikAddressList = 19;
        public const byte MikroTikWirelessMpKey = 20;
        public const byte MikroTikWirelessComment = 21;
        public const byte MikroTikDelegatedIpv6Pool = 22;
        public const byte MikroTikDhcpOptionSet = 23;
        public const byte MikroTikDhcpOptionParamStr1 = 24;
        public const byte MikroTikDhcpOptionParamStr2 = 25;
        public const byte MikroTikWirelessVlanId = 26;
        public const byte MikroTikWirelessVlanIdType = 27;
        public const byte MikroTikWirelessMinSignal = 28;
        public const byte MikroTikWirelessMaxSignal = 29;
    }

    /// <summary>
    /// Accounting Status Types
    /// </summary>
    public static class AcctStatusType
    {
        public const int Start = 1;
        public const int Stop = 2;
        public const int InterimUpdate = 3;
        public const int AccountingOn = 7;
        public const int AccountingOff = 8;
    }

    /// <summary>
    /// RADIUS Packet Parser/Builder
    /// </summary>
    public class RadiusPacket
    {
        public byte Code { get; set; }
        public byte Identifier { get; set; }
        public byte[] Authenticator { get; set; } = new byte[16];
        public Dictionary<byte, List<byte[]>> Attributes { get; set; } = new();
        public List<(int vendorId, byte type, byte[] value)> VendorAttributes { get; set; } = new();

        public static RadiusPacket Parse(byte[] data)
        {
            var packet = new RadiusPacket
            {
                Code = data[0],
                Identifier = data[1]
            };
            
            var length = (data[2] << 8) | data[3];
            Array.Copy(data, 4, packet.Authenticator, 0, 16);

            int pos = 20;
            while (pos < length)
            {
                byte attrType = data[pos];
                byte attrLen = data[pos + 1];
                byte[] attrValue = new byte[attrLen - 2];
                Array.Copy(data, pos + 2, attrValue, 0, attrLen - 2);

                if (attrType == RadiusAttribute.VendorSpecific && attrLen >= 8)
                {
                    // Parse Vendor-Specific attribute
                    int vendorId = (attrValue[0] << 24) | (attrValue[1] << 16) | (attrValue[2] << 8) | attrValue[3];
                    int vendorPos = 4;
                    while (vendorPos < attrValue.Length)
                    {
                        byte vsaType = attrValue[vendorPos];
                        byte vsaLen = attrValue[vendorPos + 1];
                        byte[] vsaValue = new byte[vsaLen - 2];
                        Array.Copy(attrValue, vendorPos + 2, vsaValue, 0, vsaLen - 2);
                        packet.VendorAttributes.Add((vendorId, vsaType, vsaValue));
                        vendorPos += vsaLen;
                    }
                }
                else
                {
                    if (!packet.Attributes.ContainsKey(attrType))
                        packet.Attributes[attrType] = new List<byte[]>();
                    packet.Attributes[attrType].Add(attrValue);
                }

                pos += attrLen;
            }

            return packet;
        }

        public byte[] ToBytes(string sharedSecret)
        {
            var attrs = new List<byte>();

            foreach (var kvp in Attributes)
            {
                foreach (var value in kvp.Value)
                {
                    attrs.Add(kvp.Key);
                    attrs.Add((byte)(value.Length + 2));
                    attrs.AddRange(value);
                }
            }

            // Add Vendor-Specific attributes
            foreach (var vsa in VendorAttributes)
            {
                var vsaData = new List<byte>();
                vsaData.Add((byte)((vsa.vendorId >> 24) & 0xFF));
                vsaData.Add((byte)((vsa.vendorId >> 16) & 0xFF));
                vsaData.Add((byte)((vsa.vendorId >> 8) & 0xFF));
                vsaData.Add((byte)(vsa.vendorId & 0xFF));
                vsaData.Add(vsa.type);
                vsaData.Add((byte)(vsa.value.Length + 2));
                vsaData.AddRange(vsa.value);

                attrs.Add(RadiusAttribute.VendorSpecific);
                attrs.Add((byte)(vsaData.Count + 2));
                attrs.AddRange(vsaData);
            }

            int length = 20 + attrs.Count;
            var packet = new byte[length];
            packet[0] = Code;
            packet[1] = Identifier;
            packet[2] = (byte)((length >> 8) & 0xFF);
            packet[3] = (byte)(length & 0xFF);

            // For response packets, calculate response authenticator
            if (Code == RadiusCode.AccessAccept || Code == RadiusCode.AccessReject || 
                Code == RadiusCode.AccountingResponse)
            {
                Array.Copy(Authenticator, 0, packet, 4, 16);
                attrs.CopyTo(packet, 20);

                // Calculate response authenticator: MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
                using var md5 = MD5.Create();
                var toHash = new byte[length + sharedSecret.Length];
                Array.Copy(packet, 0, toHash, 0, length);
                Encoding.ASCII.GetBytes(sharedSecret).CopyTo(toHash, length);
                var hash = md5.ComputeHash(toHash);
                Array.Copy(hash, 0, packet, 4, 16);
            }
            else
            {
                Array.Copy(Authenticator, 0, packet, 4, 16);
                attrs.CopyTo(packet, 20);
            }

            return packet;
        }

        public string? GetString(byte attrType)
        {
            if (Attributes.TryGetValue(attrType, out var values) && values.Count > 0)
                return Encoding.UTF8.GetString(values[0]);
            return null;
        }

        public int? GetInt(byte attrType)
        {
            if (Attributes.TryGetValue(attrType, out var values) && values.Count > 0)
            {
                var v = values[0];
                if (v.Length >= 4)
                    return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
            }
            return null;
        }

        public IPAddress? GetIpAddress(byte attrType)
        {
            if (Attributes.TryGetValue(attrType, out var values) && values.Count > 0 && values[0].Length == 4)
                return new IPAddress(values[0]);
            return null;
        }

        public void AddString(byte attrType, string value)
        {
            if (!Attributes.ContainsKey(attrType))
                Attributes[attrType] = new List<byte[]>();
            Attributes[attrType].Add(Encoding.UTF8.GetBytes(value));
        }

        public void AddInt(byte attrType, int value)
        {
            if (!Attributes.ContainsKey(attrType))
                Attributes[attrType] = new List<byte[]>();
            Attributes[attrType].Add(new byte[]
            {
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF)
            });
        }

        public void AddMikroTikAttribute(byte type, string value)
        {
            VendorAttributes.Add((RadiusAttribute.MikroTikVendorId, type, Encoding.UTF8.GetBytes(value)));
        }

        public void AddMikroTikAttribute(byte type, int value)
        {
            VendorAttributes.Add((RadiusAttribute.MikroTikVendorId, type, new byte[]
            {
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF)
            }));
        }

        public string DecryptPassword(string sharedSecret)
        {
            if (!Attributes.TryGetValue(RadiusAttribute.UserPassword, out var values) || values.Count == 0)
                return "";

            var encryptedPassword = values[0];
            var decrypted = new byte[encryptedPassword.Length];
            
            using var md5 = MD5.Create();
            var secretBytes = Encoding.ASCII.GetBytes(sharedSecret);
            
            // First block: MD5(Secret + Authenticator)
            var toHash = new byte[secretBytes.Length + 16];
            secretBytes.CopyTo(toHash, 0);
            Authenticator.CopyTo(toHash, secretBytes.Length);
            var hash = md5.ComputeHash(toHash);

            for (int i = 0; i < encryptedPassword.Length; i += 16)
            {
                for (int j = 0; j < 16 && i + j < encryptedPassword.Length; j++)
                {
                    decrypted[i + j] = (byte)(encryptedPassword[i + j] ^ hash[j]);
                }

                if (i + 16 < encryptedPassword.Length)
                {
                    // Next block: MD5(Secret + Previous Cipher Block)
                    toHash = new byte[secretBytes.Length + 16];
                    secretBytes.CopyTo(toHash, 0);
                    Array.Copy(encryptedPassword, i, toHash, secretBytes.Length, 16);
                    hash = md5.ComputeHash(toHash);
                }
            }

            // Remove null padding
            int len = Array.IndexOf(decrypted, (byte)0);
            if (len < 0) len = decrypted.Length;
            
            return Encoding.UTF8.GetString(decrypted, 0, len);
        }
    }

    /// <summary>
    /// RADIUS Server for MikroTik Integration
    /// Handles Authentication, Authorization, and Accounting (AAA)
    /// </summary>
    public class RadiusServer : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<RadiusServer> _logger;
        private readonly IConfiguration _configuration;
        
        private UdpClient? _authServer;
        private UdpClient? _acctServer;
        private UdpClient? _coaClient;
        
        private string _sharedSecret = "radius_secret";
        private int _authPort = 1812;
        private int _acctPort = 1813;
        private int _coaPort = 3799;
        
        private readonly Dictionary<string, BuiltinRadiusSession> _activeSessions = new();
        private readonly object _sessionLock = new();

        public RadiusServer(IServiceProvider serviceProvider, ILogger<RadiusServer> logger, IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _configuration = configuration;
            
            // Load configuration
            _sharedSecret = _configuration["Radius:SharedSecret"] ?? "radius_secret";
            _authPort = _configuration.GetValue("Radius:AuthPort", 1812);
            _acctPort = _configuration.GetValue("Radius:AcctPort", 1813);
            _coaPort = _configuration.GetValue("Radius:CoAPort", 3799);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("RADIUS Server starting on Auth:{AuthPort}, Acct:{AcctPort}", _authPort, _acctPort);

            try
            {
                _authServer = new UdpClient(_authPort);
                _acctServer = new UdpClient(_acctPort);
                _coaClient = new UdpClient();

                var authTask = HandleAuthenticationAsync(stoppingToken);
                var acctTask = HandleAccountingAsync(stoppingToken);

                await Task.WhenAll(authTask, acctTask);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RADIUS Server error");
            }
            finally
            {
                _authServer?.Close();
                _acctServer?.Close();
                _coaClient?.Close();
            }
        }

        private async Task HandleAuthenticationAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = await _authServer!.ReceiveAsync(stoppingToken);
                    _ = ProcessAuthRequestAsync(result.Buffer, result.RemoteEndPoint);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error receiving auth packet");
                }
            }
        }

        private async Task HandleAccountingAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = await _acctServer!.ReceiveAsync(stoppingToken);
                    _ = ProcessAccountingRequestAsync(result.Buffer, result.RemoteEndPoint);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error receiving accounting packet");
                }
            }
        }

        private async Task ProcessAuthRequestAsync(byte[] data, IPEndPoint remoteEndPoint)
        {
            try
            {
                var request = RadiusPacket.Parse(data);
                
                if (request.Code != RadiusCode.AccessRequest)
                    return;

                var username = request.GetString(RadiusAttribute.UserName) ?? "";
                var password = request.DecryptPassword(_sharedSecret);
                var callingStationId = request.GetString(RadiusAttribute.CallingStationId) ?? ""; // MAC address
                var calledStationId = request.GetString(RadiusAttribute.CalledStationId) ?? ""; // AP MAC
                var nasIdentifier = request.GetString(RadiusAttribute.NasIdentifier) ?? "";
                var nasIp = request.GetIpAddress(RadiusAttribute.NasIpAddress);

                _logger.LogInformation("RADIUS Auth Request: User={User}, MAC={MAC}, NAS={NAS}", 
                    username, callingStationId, nasIdentifier);

                // Authenticate user
                var (success, guest, profile, sessionTimeout, quotaBytes) = await AuthenticateUserAsync(username, password, callingStationId);

                var response = new RadiusPacket
                {
                    Code = success ? RadiusCode.AccessAccept : RadiusCode.AccessReject,
                    Identifier = request.Identifier,
                    Authenticator = request.Authenticator
                };

                if (success && guest != null)
                {
                    // Session timeout (in seconds)
                    if (sessionTimeout > 0)
                    {
                        response.AddInt(RadiusAttribute.SessionTimeout, sessionTimeout);
                    }

                    // Idle timeout (30 minutes)
                    response.AddInt(RadiusAttribute.IdleTimeout, 1800);

                    // Apply bandwidth limits via MikroTik-Rate-Limit
                    // Format: "rx-rate[/tx-rate] [rx-burst-rate/tx-burst-rate] [rx-burst-threshold/tx-burst-threshold] [rx-burst-time/tx-burst-time] [priority] [rx-rate-min/tx-rate-min]"
                    if (profile != null)
                    {
                        var rateLimit = $"{profile.UploadSpeedKbps}k/{profile.DownloadSpeedKbps}k";
                        response.AddMikroTikAttribute(RadiusAttribute.MikroTikRateLimit, rateLimit);
                    }

                    // Data limit (quota) - MikroTik-Total-Limit
                    if (quotaBytes > 0)
                    {
                        // Split into gigawords and bytes
                        var gigawords = (int)(quotaBytes / 4294967296); // 4GB in bytes
                        var bytes = (int)(quotaBytes % 4294967296);
                        
                        if (gigawords > 0)
                        {
                            response.AddMikroTikAttribute(RadiusAttribute.MikroTikTotalLimitGigawords, gigawords);
                        }
                        response.AddMikroTikAttribute(RadiusAttribute.MikroTikTotalLimit, bytes);
                    }

                    // Reply message
                    response.AddString(RadiusAttribute.ReplyMessage, $"Welcome {guest.GuestName}! Room {guest.RoomNumber}");

                    // Store session info
                    lock (_sessionLock)
                    {
                        _activeSessions[callingStationId] = new BuiltinRadiusSession
                        {
                            Username = username,
                            MacAddress = callingStationId,
                            GuestId = guest.Id,
                            NasIp = nasIp?.ToString() ?? "",
                            StartTime = DateTime.UtcNow
                        };
                    }

                    _logger.LogInformation("RADIUS Auth Accept: User={User}, MAC={MAC}, Rate={Rate}", 
                        username, callingStationId, profile != null ? $"{profile.DownloadSpeedKbps}k/{profile.UploadSpeedKbps}k" : "unlimited");
                }
                else
                {
                    response.AddString(RadiusAttribute.ReplyMessage, "Authentication failed. Please check your credentials.");
                    _logger.LogWarning("RADIUS Auth Reject: User={User}, MAC={MAC}", username, callingStationId);
                }

                var responseData = response.ToBytes(_sharedSecret);
                await _authServer!.SendAsync(responseData, responseData.Length, remoteEndPoint);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing auth request");
            }
        }

        private async Task ProcessAccountingRequestAsync(byte[] data, IPEndPoint remoteEndPoint)
        {
            try
            {
                var request = RadiusPacket.Parse(data);
                
                if (request.Code != RadiusCode.AccountingRequest)
                    return;

                var statusType = request.GetInt(RadiusAttribute.AcctStatusType) ?? 0;
                var username = request.GetString(RadiusAttribute.UserName) ?? "";
                var sessionId = request.GetString(RadiusAttribute.AcctSessionId) ?? "";
                var callingStationId = request.GetString(RadiusAttribute.CallingStationId) ?? "";
                
                var inputOctets = (long)(request.GetInt(RadiusAttribute.AcctInputOctets) ?? 0);
                var outputOctets = (long)(request.GetInt(RadiusAttribute.AcctOutputOctets) ?? 0);
                var inputGigawords = (long)(request.GetInt(RadiusAttribute.AcctInputGigawords) ?? 0);
                var outputGigawords = (long)(request.GetInt(RadiusAttribute.AcctOutputGigawords) ?? 0);
                var sessionTime = request.GetInt(RadiusAttribute.AcctSessionTime) ?? 0;
                var terminateCause = request.GetInt(RadiusAttribute.AcctTerminateCause);

                // Calculate total bytes (with gigawords)
                var totalInputBytes = inputOctets + (inputGigawords * 4294967296);
                var totalOutputBytes = outputOctets + (outputGigawords * 4294967296);

                _logger.LogInformation("RADIUS Acct: Type={Type}, User={User}, MAC={MAC}, In={In}MB, Out={Out}MB, Time={Time}s",
                    statusType, username, callingStationId, 
                    totalInputBytes / 1048576, totalOutputBytes / 1048576, sessionTime);

                // Process based on status type
                switch (statusType)
                {
                    case AcctStatusType.Start:
                        await HandleAccountingStartAsync(username, sessionId, callingStationId);
                        break;
                    
                    case AcctStatusType.Stop:
                        await HandleAccountingStopAsync(username, sessionId, callingStationId, 
                            totalInputBytes, totalOutputBytes, sessionTime, terminateCause);
                        break;
                    
                    case AcctStatusType.InterimUpdate:
                        await HandleAccountingUpdateAsync(username, sessionId, callingStationId,
                            totalInputBytes, totalOutputBytes, sessionTime);
                        break;
                }

                // Send Accounting-Response
                var response = new RadiusPacket
                {
                    Code = RadiusCode.AccountingResponse,
                    Identifier = request.Identifier,
                    Authenticator = request.Authenticator
                };

                var responseData = response.ToBytes(_sharedSecret);
                await _acctServer!.SendAsync(responseData, responseData.Length, remoteEndPoint);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing accounting request");
            }
        }

        private async Task<(bool success, Guest? guest, BandwidthProfile? profile, int sessionTimeout, long quotaBytes)> 
            AuthenticateUserAsync(string username, string password, string macAddress)
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            // Username format: RoomNumber or RoomNumber@hotel
            var roomNumber = username.Split('@')[0];

            // Find guest by room number
            var guest = await dbContext.Guests
                .FirstOrDefaultAsync(g => g.RoomNumber == roomNumber && g.Status == "checked-in");

            if (guest == null)
            {
                _logger.LogWarning("Guest not found for room: {Room}", roomNumber);
                return (false, null, null, 0, 0);
            }

            // Verify password (reservation number or local password)
            bool passwordValid = false;
            if (!string.IsNullOrEmpty(guest.LocalPassword))
            {
                passwordValid = guest.LocalPassword == password;
            }
            else
            {
                passwordValid = guest.ReservationNumber == password;
            }

            if (!passwordValid)
            {
                _logger.LogWarning("Invalid password for room: {Room}", roomNumber);
                return (false, null, null, 0, 0);
            }

            // Get bandwidth profile
            var profile = await GetBandwidthProfileAsync(dbContext, guest);

            // Calculate session timeout (until checkout)
            var sessionTimeout = (int)(guest.DepartureDate - DateTime.UtcNow).TotalSeconds;
            if (sessionTimeout < 0) sessionTimeout = 86400; // 24 hours default

            // Calculate remaining quota
            var remainingQuota = guest.TotalQuotaBytes - guest.UsedQuotaBytes;
            if (remainingQuota < 0) remainingQuota = 0;

            // Create or update WiFi session
            var existingSession = await dbContext.WifiSessions
                .FirstOrDefaultAsync(s => s.MacAddress == macAddress && s.Status == "Active");

            if (existingSession == null)
            {
                var session = new WifiSession
                {
                    GuestId = guest.Id,
                    RoomNumber = guest.RoomNumber,
                    GuestName = guest.GuestName,
                    MacAddress = macAddress,
                    Status = "Active",
                    ControllerType = "Mikrotik",
                    BandwidthProfileId = profile?.Id,
                    SessionStart = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow
                };
                dbContext.WifiSessions.Add(session);
            }
            else
            {
                existingSession.LastActivity = DateTime.UtcNow;
            }

            guest.LastWifiLogin = DateTime.UtcNow;
            await dbContext.SaveChangesAsync();

            // Log the authentication
            dbContext.SystemLogs.Add(new SystemLog
            {
                Level = "INFO",
                Category = "RADIUS",
                Source = "Authentication",
                Message = $"User authenticated: Room {roomNumber}, MAC {macAddress}",
                Timestamp = DateTime.UtcNow
            });
            await dbContext.SaveChangesAsync();

            return (true, guest, profile, sessionTimeout, remainingQuota);
        }

        private async Task<BandwidthProfile?> GetBandwidthProfileAsync(ApplicationDbContext dbContext, Guest guest)
        {
            // Check for VIP profile
            if (!string.IsNullOrEmpty(guest.VipStatus))
            {
                var vipProfile = await dbContext.BandwidthProfiles
                    .FirstOrDefaultAsync(p => p.IsActive && p.Name.Contains("VIP"));
                if (vipProfile != null) return vipProfile;
            }

            // Return default profile
            return await dbContext.BandwidthProfiles
                .FirstOrDefaultAsync(p => p.IsActive && p.IsDefault);
        }

        private async Task HandleAccountingStartAsync(string username, string sessionId, string macAddress)
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var session = await dbContext.WifiSessions
                .FirstOrDefaultAsync(s => s.MacAddress == macAddress && s.Status == "Active");

            if (session != null)
            {
                session.LastActivity = DateTime.UtcNow;
                await dbContext.SaveChangesAsync();
            }

            _logger.LogInformation("Accounting Start: User={User}, Session={Session}", username, sessionId);
        }

        private async Task HandleAccountingStopAsync(string username, string sessionId, string macAddress,
            long inputBytes, long outputBytes, int sessionTime, int? terminateCause)
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var session = await dbContext.WifiSessions
                .Include(s => s.Guest)
                .FirstOrDefaultAsync(s => s.MacAddress == macAddress && s.Status == "Active");

            if (session != null)
            {
                // Update session
                session.Status = "Disconnected";
                session.SessionEnd = DateTime.UtcNow;
                session.BytesDownloaded = inputBytes;  // From NAS perspective: input = download
                session.BytesUploaded = outputBytes;   // From NAS perspective: output = upload
                session.BytesUsed = inputBytes + outputBytes;

                // Update guest usage
                if (session.Guest != null)
                {
                    // Calculate new usage since last update
                    var previousUsage = session.BytesUsed;
                    var newUsage = inputBytes + outputBytes;
                    var delta = newUsage - previousUsage;
                    
                    if (delta > 0)
                    {
                        session.Guest.UsedQuotaBytes += delta;
                    }
                }

                await dbContext.SaveChangesAsync();

                // Log the disconnection
                var cause = terminateCause switch
                {
                    1 => "User Request",
                    2 => "Lost Carrier",
                    3 => "Lost Service",
                    4 => "Idle Timeout",
                    5 => "Session Timeout",
                    6 => "Admin Reset",
                    7 => "Admin Reboot",
                    8 => "Port Error",
                    9 => "NAS Error",
                    10 => "NAS Request",
                    11 => "NAS Reboot",
                    12 => "Port Unneeded",
                    13 => "Port Preempted",
                    14 => "Port Suspended",
                    15 => "Service Unavailable",
                    16 => "Callback",
                    17 => "User Error",
                    18 => "Host Request",
                    _ => $"Unknown ({terminateCause})"
                };

                _logger.LogInformation("Accounting Stop: User={User}, MAC={MAC}, Time={Time}s, In={In}MB, Out={Out}MB, Cause={Cause}",
                    username, macAddress, sessionTime, inputBytes / 1048576, outputBytes / 1048576, cause);
            }

            // Remove from active sessions
            lock (_sessionLock)
            {
                _activeSessions.Remove(macAddress);
            }
        }

        private async Task HandleAccountingUpdateAsync(string username, string sessionId, string macAddress,
            long inputBytes, long outputBytes, int sessionTime)
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var session = await dbContext.WifiSessions
                .Include(s => s.Guest)
                .FirstOrDefaultAsync(s => s.MacAddress == macAddress && s.Status == "Active");

            if (session != null)
            {
                // Calculate delta since last update
                var previousTotal = session.BytesUsed;
                var currentTotal = inputBytes + outputBytes;
                var delta = currentTotal - previousTotal;

                // Update session stats
                session.BytesDownloaded = inputBytes;
                session.BytesUploaded = outputBytes;
                session.BytesUsed = currentTotal;
                session.LastActivity = DateTime.UtcNow;

                // Update guest usage
                if (session.Guest != null && delta > 0)
                {
                    session.Guest.UsedQuotaBytes += delta;

                    // Check if quota exceeded
                    if (session.Guest.UsedQuotaBytes >= session.Guest.TotalQuotaBytes)
                    {
                        _logger.LogWarning("Quota exceeded for Room {Room}, initiating disconnect", session.RoomNumber);
                        // The MikroTik will disconnect automatically based on the quota limit we sent
                    }
                }

                await dbContext.SaveChangesAsync();
            }

            _logger.LogDebug("Accounting Update: User={User}, MAC={MAC}, Total={Total}MB",
                username, macAddress, (inputBytes + outputBytes) / 1048576);
        }

        /// <summary>
        /// Send Disconnect-Request (CoA) to MikroTik to disconnect a user
        /// </summary>
        public async Task<bool> DisconnectUserAsync(string nasIp, string macAddress, string sessionId = "")
        {
            try
            {
                var request = new RadiusPacket
                {
                    Code = RadiusCode.DisconnectRequest,
                    Identifier = (byte)Random.Shared.Next(256),
                    Authenticator = new byte[16]
                };
                
                // Generate random authenticator
                Random.Shared.NextBytes(request.Authenticator);

                // Add attributes to identify the session
                request.AddString(RadiusAttribute.CallingStationId, macAddress);
                if (!string.IsNullOrEmpty(sessionId))
                {
                    request.AddString(RadiusAttribute.AcctSessionId, sessionId);
                }

                var packet = request.ToBytes(_sharedSecret);
                var endpoint = new IPEndPoint(IPAddress.Parse(nasIp), _coaPort);
                
                await _coaClient!.SendAsync(packet, packet.Length, endpoint);
                
                // Wait for response (with timeout)
                var receiveTask = _coaClient.ReceiveAsync();
                if (await Task.WhenAny(receiveTask, Task.Delay(5000)) == receiveTask)
                {
                    var result = await receiveTask;
                    var response = RadiusPacket.Parse(result.Buffer);
                    
                    if (response.Code == RadiusCode.DisconnectAck)
                    {
                        _logger.LogInformation("Disconnect successful for MAC {MAC}", macAddress);
                        return true;
                    }
                    else
                    {
                        _logger.LogWarning("Disconnect failed for MAC {MAC}: Code={Code}", macAddress, response.Code);
                        return false;
                    }
                }
                else
                {
                    _logger.LogWarning("Disconnect timeout for MAC {MAC}", macAddress);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending disconnect request");
                return false;
            }
        }

        /// <summary>
        /// Send Change of Authorization to update user's rate limit
        /// </summary>
        public async Task<bool> UpdateRateLimitAsync(string nasIp, string macAddress, int downloadKbps, int uploadKbps)
        {
            try
            {
                var request = new RadiusPacket
                {
                    Code = RadiusCode.CoARequest,
                    Identifier = (byte)Random.Shared.Next(256),
                    Authenticator = new byte[16]
                };
                
                Random.Shared.NextBytes(request.Authenticator);

                request.AddString(RadiusAttribute.CallingStationId, macAddress);
                request.AddMikroTikAttribute(RadiusAttribute.MikroTikRateLimit, $"{uploadKbps}k/{downloadKbps}k");

                var packet = request.ToBytes(_sharedSecret);
                var endpoint = new IPEndPoint(IPAddress.Parse(nasIp), _coaPort);
                
                await _coaClient!.SendAsync(packet, packet.Length, endpoint);
                
                var receiveTask = _coaClient.ReceiveAsync();
                if (await Task.WhenAny(receiveTask, Task.Delay(5000)) == receiveTask)
                {
                    var result = await receiveTask;
                    var response = RadiusPacket.Parse(result.Buffer);
                    return response.Code == RadiusCode.CoAAck;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending CoA request");
                return false;
            }
        }
    }

    /// <summary>
    /// Tracks active RADIUS sessions for builtin server
    /// </summary>
    public class BuiltinRadiusSession
    {
        public string Username { get; set; } = "";
        public string MacAddress { get; set; } = "";
        public int GuestId { get; set; }
        public string NasIp { get; set; } = "";
        public string SessionId { get; set; } = "";
        public DateTime StartTime { get; set; }
        public long BytesIn { get; set; }
        public long BytesOut { get; set; }
    }
}
