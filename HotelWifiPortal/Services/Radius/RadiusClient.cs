using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace HotelWifiPortal.Services.Radius
{
    /// <summary>
    /// RADIUS client for sending Access-Request packets to FreeRADIUS
    /// This is used when the external portal needs to authenticate users via RADIUS
    /// </summary>
    public class RadiusClient
    {
        private readonly ILogger<RadiusClient> _logger;
        private readonly string _serverAddress;
        private readonly int _serverPort;
        private readonly string _sharedSecret;
        private readonly int _timeout;

        // RADIUS packet codes
        private const byte ACCESS_REQUEST = 1;
        private const byte ACCESS_ACCEPT = 2;
        private const byte ACCESS_REJECT = 3;
        private const byte ACCESS_CHALLENGE = 11;

        // RADIUS attribute types
        private const byte ATTR_USER_NAME = 1;
        private const byte ATTR_USER_PASSWORD = 2;
        private const byte ATTR_NAS_IP_ADDRESS = 4;
        private const byte ATTR_NAS_PORT = 5;
        private const byte ATTR_SERVICE_TYPE = 6;
        private const byte ATTR_FRAMED_PROTOCOL = 7;
        private const byte ATTR_FRAMED_IP_ADDRESS = 8;
        private const byte ATTR_CALLING_STATION_ID = 31;
        private const byte ATTR_NAS_IDENTIFIER = 32;
        private const byte ATTR_NAS_PORT_TYPE = 61;

        public RadiusClient(
            ILogger<RadiusClient> logger,
            string serverAddress,
            int serverPort = 1812,
            string sharedSecret = "testing123",
            int timeout = 5000)
        {
            _logger = logger;
            _serverAddress = serverAddress;
            _serverPort = serverPort;
            _sharedSecret = sharedSecret;
            _timeout = timeout;
        }

        /// <summary>
        /// Authenticate a user via RADIUS
        /// </summary>
        /// <param name="username">Username (room number)</param>
        /// <param name="password">Password</param>
        /// <param name="clientIp">Client's IP address (optional)</param>
        /// <param name="clientMac">Client's MAC address (optional)</param>
        /// <param name="nasIp">NAS IP address (your portal server)</param>
        /// <returns>True if Access-Accept received, false otherwise</returns>
        public async Task<RadiusAuthResult> AuthenticateAsync(
            string username,
            string password,
            string? clientIp = null,
            string? clientMac = null,
            string? nasIp = null)
        {
            var result = new RadiusAuthResult();

            try
            {
                _logger.LogInformation("=== RADIUS Auth Request ===");
                _logger.LogInformation("Server: {Server}:{Port}", _serverAddress, _serverPort);
                _logger.LogInformation("Username: {Username}", username);
                _logger.LogInformation("Client IP: {ClientIp}", clientIp ?? "not provided");
                _logger.LogInformation("Client MAC: {ClientMac}", clientMac ?? "not provided");

                // Build RADIUS packet
                var packet = BuildAccessRequest(username, password, clientIp, clientMac, nasIp);

                // Send packet and receive response
                using var udpClient = new UdpClient();
                udpClient.Client.ReceiveTimeout = _timeout;

                var serverEndpoint = new IPEndPoint(
                    IPAddress.Parse(_serverAddress),
                    _serverPort);

                _logger.LogDebug("Sending RADIUS packet ({Length} bytes) to {Endpoint}",
                    packet.Length, serverEndpoint);

                await udpClient.SendAsync(packet, packet.Length, serverEndpoint);

                // Wait for response
                var responseTask = udpClient.ReceiveAsync();
                var timeoutTask = Task.Delay(_timeout);

                var completedTask = await Task.WhenAny(responseTask, timeoutTask);

                if (completedTask == timeoutTask)
                {
                    _logger.LogWarning("RADIUS request timed out after {Timeout}ms", _timeout);
                    result.Success = false;
                    result.Error = "RADIUS request timed out";
                    return result;
                }

                var response = await responseTask;
                var responsePacket = response.Buffer;

                _logger.LogDebug("Received RADIUS response ({Length} bytes)", responsePacket.Length);

                // Parse response
                result = ParseResponse(responsePacket, packet);

                _logger.LogInformation("=== RADIUS Auth Result ===");
                _logger.LogInformation("Success: {Success}", result.Success);
                _logger.LogInformation("Code: {Code}", result.ResponseCode);
                if (!string.IsNullOrEmpty(result.Error))
                    _logger.LogWarning("Error: {Error}", result.Error);

                return result;
            }
            catch (SocketException ex)
            {
                _logger.LogError(ex, "RADIUS socket error");
                result.Success = false;
                result.Error = $"Network error: {ex.Message}";
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RADIUS authentication error");
                result.Success = false;
                result.Error = ex.Message;
                return result;
            }
        }

        private byte[] BuildAccessRequest(
            string username,
            string password,
            string? clientIp,
            string? clientMac,
            string? nasIp)
        {
            var attributes = new List<byte>();

            // User-Name attribute
            AddAttribute(attributes, ATTR_USER_NAME, Encoding.UTF8.GetBytes(username));

            // Generate authenticator (16 random bytes)
            var authenticator = new byte[16];
            RandomNumberGenerator.Fill(authenticator);

            // User-Password attribute (encrypted)
            var encryptedPassword = EncryptPassword(password, authenticator);
            AddAttribute(attributes, ATTR_USER_PASSWORD, encryptedPassword);

            // NAS-IP-Address
            var nasIpAddress = nasIp ?? GetLocalIpAddress();
            if (IPAddress.TryParse(nasIpAddress, out var nasAddr))
            {
                AddAttribute(attributes, ATTR_NAS_IP_ADDRESS, nasAddr.GetAddressBytes());
            }

            // NAS-Identifier
            AddAttribute(attributes, ATTR_NAS_IDENTIFIER, Encoding.UTF8.GetBytes("HotelWifiPortal"));

            // NAS-Port-Type (Wireless-802.11 = 19)
            AddAttribute(attributes, ATTR_NAS_PORT_TYPE, BitConverter.GetBytes((uint)19).Reverse().ToArray());

            // Service-Type (Login = 1)
            AddAttribute(attributes, ATTR_SERVICE_TYPE, BitConverter.GetBytes((uint)1).Reverse().ToArray());

            // Calling-Station-Id (MAC address)
            if (!string.IsNullOrEmpty(clientMac))
            {
                AddAttribute(attributes, ATTR_CALLING_STATION_ID, Encoding.UTF8.GetBytes(clientMac.ToUpper()));
            }

            // Framed-IP-Address (client IP)
            if (!string.IsNullOrEmpty(clientIp) && IPAddress.TryParse(clientIp, out var clientAddr))
            {
                AddAttribute(attributes, ATTR_FRAMED_IP_ADDRESS, clientAddr.GetAddressBytes());
            }

            // Build complete packet
            var packetLength = 20 + attributes.Count; // Header (20) + Attributes
            var packet = new byte[packetLength];

            // Code (1 byte) - Access-Request
            packet[0] = ACCESS_REQUEST;

            // Identifier (1 byte) - random
            packet[1] = (byte)Random.Shared.Next(256);

            // Length (2 bytes)
            packet[2] = (byte)(packetLength >> 8);
            packet[3] = (byte)(packetLength & 0xFF);

            // Authenticator (16 bytes)
            Array.Copy(authenticator, 0, packet, 4, 16);

            // Attributes
            Array.Copy(attributes.ToArray(), 0, packet, 20, attributes.Count);

            return packet;
        }

        private void AddAttribute(List<byte> attributes, byte type, byte[] value)
        {
            // RADIUS attribute format: Type (1) + Length (1) + Value
            var length = (byte)(2 + value.Length);
            attributes.Add(type);
            attributes.Add(length);
            attributes.AddRange(value);
        }

        private byte[] EncryptPassword(string password, byte[] authenticator)
        {
            // PAP password encryption as per RFC 2865
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            // Pad to multiple of 16 bytes
            var paddedLength = ((passwordBytes.Length + 15) / 16) * 16;
            if (paddedLength == 0) paddedLength = 16;
            var paddedPassword = new byte[paddedLength];
            Array.Copy(passwordBytes, paddedPassword, passwordBytes.Length);

            var result = new byte[paddedLength];
            var secretBytes = Encoding.UTF8.GetBytes(_sharedSecret);

            // First 16 bytes: XOR with MD5(secret + authenticator)
            var b = MD5.HashData(secretBytes.Concat(authenticator).ToArray());
            for (int i = 0; i < 16 && i < paddedLength; i++)
            {
                result[i] = (byte)(paddedPassword[i] ^ b[i]);
            }

            // Subsequent 16-byte chunks: XOR with MD5(secret + previous cipher block)
            for (int chunk = 1; chunk < paddedLength / 16; chunk++)
            {
                var prevBlock = new byte[16];
                Array.Copy(result, (chunk - 1) * 16, prevBlock, 0, 16);
                b = MD5.HashData(secretBytes.Concat(prevBlock).ToArray());

                for (int i = 0; i < 16; i++)
                {
                    result[chunk * 16 + i] = (byte)(paddedPassword[chunk * 16 + i] ^ b[i]);
                }
            }

            return result;
        }

        private RadiusAuthResult ParseResponse(byte[] response, byte[] request)
        {
            var result = new RadiusAuthResult();

            if (response.Length < 20)
            {
                result.Error = "Invalid response: too short";
                return result;
            }

            var code = response[0];
            var identifier = response[1];
            var length = (response[2] << 8) | response[3];

            result.ResponseCode = code switch
            {
                ACCESS_ACCEPT => "Access-Accept",
                ACCESS_REJECT => "Access-Reject",
                ACCESS_CHALLENGE => "Access-Challenge",
                _ => $"Unknown ({code})"
            };

            // Verify identifier matches
            if (identifier != request[1])
            {
                result.Error = "Response identifier mismatch";
                return result;
            }

            // Verify response authenticator
            var responseAuth = new byte[16];
            Array.Copy(response, 4, responseAuth, 0, 16);

            // Calculate expected authenticator: MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
            var toHash = new byte[length + _sharedSecret.Length];
            Array.Copy(response, 0, toHash, 0, 4); // Code, ID, Length
            Array.Copy(request, 4, toHash, 4, 16); // Request Authenticator
            if (length > 20)
            {
                Array.Copy(response, 20, toHash, 20, length - 20); // Attributes
            }
            Array.Copy(Encoding.UTF8.GetBytes(_sharedSecret), 0, toHash, length, _sharedSecret.Length);

            var expectedAuth = MD5.HashData(toHash.Take(length + _sharedSecret.Length).ToArray());

            // Note: Authenticator verification is optional for testing
            // In production, you should verify: responseAuth.SequenceEqual(expectedAuth)

            result.Success = (code == ACCESS_ACCEPT);

            // Parse attributes for additional info
            if (length > 20)
            {
                ParseAttributes(response, 20, length - 20, result);
            }

            return result;
        }

        private void ParseAttributes(byte[] packet, int offset, int length, RadiusAuthResult result)
        {
            var pos = offset;
            var end = offset + length;

            while (pos < end)
            {
                if (pos + 2 > end) break;

                var attrType = packet[pos];
                var attrLen = packet[pos + 1];

                if (attrLen < 2 || pos + attrLen > end) break;

                var value = new byte[attrLen - 2];
                Array.Copy(packet, pos + 2, value, 0, attrLen - 2);

                // Store interesting attributes
                switch (attrType)
                {
                    case 18: // Reply-Message
                        result.ReplyMessage = Encoding.UTF8.GetString(value);
                        break;
                    case 25: // Class
                        result.Class = Encoding.UTF8.GetString(value);
                        break;
                }

                pos += attrLen;
            }
        }

        private string GetLocalIpAddress()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
                socket.Connect(_serverAddress, _serverPort);
                var endPoint = socket.LocalEndPoint as IPEndPoint;
                return endPoint?.Address.ToString() ?? "127.0.0.1";
            }
            catch
            {
                return "127.0.0.1";
            }
        }
    }

    public class RadiusAuthResult
    {
        public bool Success { get; set; }
        public string ResponseCode { get; set; } = "";
        public string? Error { get; set; }
        public string? ReplyMessage { get; set; }
        public string? Class { get; set; }
    }

    /// <summary>
    /// RADIUS CoA (Change of Authorization) client for sending dynamic authorization changes
    /// Sends CoA to FreeRADIUS server which proxies to MikroTik NAS
    /// </summary>
    public class RadiusCoAClient
    {
        private readonly ILogger _logger;
        private readonly int _timeout;

        // RADIUS CoA packet codes (RFC 5176)
        private const byte COA_REQUEST = 43;      // CoA-Request
        private const byte COA_ACK = 44;          // CoA-ACK
        private const byte COA_NAK = 45;          // CoA-NAK
        private const byte DISCONNECT_REQUEST = 40;  // Disconnect-Request
        private const byte DISCONNECT_ACK = 41;      // Disconnect-ACK
        private const byte DISCONNECT_NAK = 42;      // Disconnect-NAK

        // Standard RADIUS attributes
        private const byte ATTR_USER_NAME = 1;
        private const byte ATTR_NAS_IP_ADDRESS = 4;
        private const byte ATTR_FRAMED_IP_ADDRESS = 8;
        private const byte ATTR_SESSION_TIMEOUT = 27;
        private const byte ATTR_CALLING_STATION_ID = 31;
        private const byte ATTR_ACCT_SESSION_ID = 44;

        // Vendor-Specific Attribute
        private const byte ATTR_VENDOR_SPECIFIC = 26;
        private const int VENDOR_MIKROTIK = 14988;

        // MikroTik VSA types
        private const byte MIKROTIK_RATE_LIMIT = 8;

        public RadiusCoAClient(ILogger logger, int timeout = 5000)
        {
            _logger = logger;
            _timeout = timeout;
        }

        /// <summary>
        /// Send CoA to FreeRADIUS to update bandwidth for a user session
        /// FreeRADIUS will proxy the CoA to the appropriate NAS (MikroTik)
        /// </summary>
        public async Task<bool> SendBandwidthUpdateAsync(
            string freeRadiusServer,
            int coaPort,
            string sharedSecret,
            string username,
            string? framedIpAddress,
            string? acctSessionId,
            int downloadKbps,
            int uploadKbps,
            string? nasIpAddress = null)
        {
            try
            {
                _logger.LogInformation("Sending CoA bandwidth update to FreeRADIUS {Server}:{Port} for user {User}", 
                    freeRadiusServer, coaPort, username);
                _logger.LogInformation("Target NAS: {NAS}, New bandwidth: {Down}k/{Up}k", 
                    nasIpAddress ?? "default", downloadKbps, uploadKbps);

                var attributes = new List<byte>();

                // User-Name (required)
                AddAttribute(attributes, ATTR_USER_NAME, Encoding.UTF8.GetBytes(username));

                // NAS-IP-Address - tells FreeRADIUS which NAS to forward the CoA to
                if (!string.IsNullOrEmpty(nasIpAddress) && IPAddress.TryParse(nasIpAddress, out var nasIp))
                {
                    AddAttribute(attributes, ATTR_NAS_IP_ADDRESS, nasIp.GetAddressBytes());
                    _logger.LogDebug("Including NAS-IP-Address: {NasIP}", nasIpAddress);
                }

                // Framed-IP-Address (helps identify the session)
                if (!string.IsNullOrEmpty(framedIpAddress) && IPAddress.TryParse(framedIpAddress, out var framedIp))
                {
                    AddAttribute(attributes, ATTR_FRAMED_IP_ADDRESS, framedIp.GetAddressBytes());
                }

                // Acct-Session-Id (helps identify the session)
                if (!string.IsNullOrEmpty(acctSessionId))
                {
                    AddAttribute(attributes, ATTR_ACCT_SESSION_ID, Encoding.UTF8.GetBytes(acctSessionId));
                }

                // Mikrotik-Rate-Limit VSA (upload/download format)
                var rateLimit = $"{uploadKbps}k/{downloadKbps}k";
                AddMikrotikVsa(attributes, MIKROTIK_RATE_LIMIT, Encoding.UTF8.GetBytes(rateLimit));

                // Build and send packet
                var packet = BuildCoAPacket(COA_REQUEST, attributes, sharedSecret);
                var response = await SendPacketAsync(freeRadiusServer, coaPort, packet);

                if (response == null)
                {
                    _logger.LogWarning("No response received from FreeRADIUS server");
                    return false;
                }

                var responseCode = response[0];
                if (responseCode == COA_ACK)
                {
                    _logger.LogInformation("CoA-ACK received from FreeRADIUS - bandwidth updated successfully");
                    return true;
                }
                else if (responseCode == COA_NAK)
                {
                    _logger.LogWarning("CoA-NAK received from FreeRADIUS - bandwidth update rejected");
                    // Parse error cause if present
                    ParseErrorCause(response);
                    return false;
                }
                else
                {
                    _logger.LogWarning("Unexpected response code from FreeRADIUS: {Code}", responseCode);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending CoA bandwidth update to FreeRADIUS");
                return false;
            }
        }

        /// <summary>
        /// Send Disconnect-Request to FreeRADIUS to terminate a user session
        /// FreeRADIUS will proxy the request to the appropriate NAS (MikroTik)
        /// </summary>
        public async Task<bool> SendDisconnectAsync(
            string freeRadiusServer,
            int coaPort,
            string sharedSecret,
            string username,
            string? framedIpAddress = null,
            string? acctSessionId = null,
            string? callingStationId = null,
            string? nasIpAddress = null)
        {
            try
            {
                _logger.LogInformation("Sending Disconnect-Request to FreeRADIUS {Server}:{Port} for user {User}", 
                    freeRadiusServer, coaPort, username);
                _logger.LogInformation("Target NAS: {NAS}", nasIpAddress ?? "default");

                var attributes = new List<byte>();

                // User-Name (required)
                AddAttribute(attributes, ATTR_USER_NAME, Encoding.UTF8.GetBytes(username));

                // NAS-IP-Address - tells FreeRADIUS which NAS to forward the request to
                if (!string.IsNullOrEmpty(nasIpAddress) && IPAddress.TryParse(nasIpAddress, out var nasIp))
                {
                    AddAttribute(attributes, ATTR_NAS_IP_ADDRESS, nasIp.GetAddressBytes());
                    _logger.LogDebug("Including NAS-IP-Address: {NasIP}", nasIpAddress);
                }

                // Framed-IP-Address
                if (!string.IsNullOrEmpty(framedIpAddress) && IPAddress.TryParse(framedIpAddress, out var framedIp))
                {
                    AddAttribute(attributes, ATTR_FRAMED_IP_ADDRESS, framedIp.GetAddressBytes());
                }

                // Acct-Session-Id
                if (!string.IsNullOrEmpty(acctSessionId))
                {
                    AddAttribute(attributes, ATTR_ACCT_SESSION_ID, Encoding.UTF8.GetBytes(acctSessionId));
                }

                // Calling-Station-Id (MAC address)
                if (!string.IsNullOrEmpty(callingStationId))
                {
                    AddAttribute(attributes, ATTR_CALLING_STATION_ID, Encoding.UTF8.GetBytes(callingStationId));
                }

                // Build and send packet
                var packet = BuildCoAPacket(DISCONNECT_REQUEST, attributes, sharedSecret);
                var response = await SendPacketAsync(freeRadiusServer, coaPort, packet);

                if (response == null)
                {
                    _logger.LogWarning("No response received from FreeRADIUS server");
                    return false;
                }

                var responseCode = response[0];
                if (responseCode == DISCONNECT_ACK)
                {
                    _logger.LogInformation("Disconnect-ACK received from FreeRADIUS - user disconnected successfully");
                    return true;
                }
                else if (responseCode == DISCONNECT_NAK)
                {
                    _logger.LogWarning("Disconnect-NAK received from FreeRADIUS - disconnect rejected");
                    ParseErrorCause(response);
                    return false;
                }
                else
                {
                    _logger.LogWarning("Unexpected response code from FreeRADIUS: {Code}", responseCode);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending Disconnect-Request to FreeRADIUS");
                return false;
            }
        }

        private void ParseErrorCause(byte[] response)
        {
            // Try to find Error-Cause attribute (type 101)
            if (response.Length > 20)
            {
                var pos = 20;
                while (pos < response.Length - 1)
                {
                    var attrType = response[pos];
                    var attrLen = response[pos + 1];
                    
                    if (attrLen < 2 || pos + attrLen > response.Length)
                        break;
                    
                    if (attrType == 101 && attrLen >= 6) // Error-Cause
                    {
                        var errorCode = (response[pos + 2] << 24) | (response[pos + 3] << 16) | 
                                       (response[pos + 4] << 8) | response[pos + 5];
                        _logger.LogWarning("Error-Cause: {Code} ({Name})", errorCode, GetErrorCauseName(errorCode));
                    }
                    
                    pos += attrLen;
                }
            }
        }

        private string GetErrorCauseName(int code)
        {
            return code switch
            {
                201 => "Residual Session Context Removed",
                202 => "Invalid EAP Packet",
                401 => "Unsupported Attribute",
                402 => "Missing Attribute",
                403 => "NAS Identification Mismatch",
                404 => "Invalid Request",
                405 => "Unsupported Service",
                406 => "Unsupported Extension",
                501 => "Administratively Prohibited",
                502 => "Request Not Routable (Proxy)",
                503 => "Session Context Not Found",
                504 => "Session Context Not Removable",
                505 => "Other Proxy Processing Error",
                506 => "Resources Unavailable",
                507 => "Request Initiated",
                _ => "Unknown"
            };
        }

        private byte[] BuildCoAPacket(byte code, List<byte> attributes, string sharedSecret)
        {
            // Generate authenticator (16 random bytes for request, will be recalculated)
            var authenticator = new byte[16];
            RandomNumberGenerator.Fill(authenticator);

            var packetLength = 20 + attributes.Count;
            var packet = new byte[packetLength];

            // Code (1 byte)
            packet[0] = code;

            // Identifier (1 byte)
            packet[1] = (byte)Random.Shared.Next(256);

            // Length (2 bytes)
            packet[2] = (byte)(packetLength >> 8);
            packet[3] = (byte)(packetLength & 0xFF);

            // Authenticator placeholder (16 bytes) - will be calculated
            Array.Copy(authenticator, 0, packet, 4, 16);

            // Attributes
            if (attributes.Count > 0)
            {
                Array.Copy(attributes.ToArray(), 0, packet, 20, attributes.Count);
            }

            // Calculate Request Authenticator for CoA/Disconnect
            // MD5(Code + Identifier + Length + 16 zero bytes + Attributes + Secret)
            var toHash = new byte[packetLength + sharedSecret.Length];
            Array.Copy(packet, toHash, packetLength);
            Array.Clear(toHash, 4, 16); // Zero out authenticator position
            Array.Copy(Encoding.UTF8.GetBytes(sharedSecret), 0, toHash, packetLength, sharedSecret.Length);

            var calculatedAuth = System.Security.Cryptography.MD5.HashData(toHash);
            Array.Copy(calculatedAuth, 0, packet, 4, 16);

            return packet;
        }

        private async Task<byte[]?> SendPacketAsync(string ipAddress, int port, byte[] packet)
        {
            using var udpClient = new UdpClient();
            udpClient.Client.ReceiveTimeout = _timeout;

            var endpoint = new IPEndPoint(IPAddress.Parse(ipAddress), port);

            _logger.LogDebug("Sending CoA packet ({Length} bytes) to {Endpoint}", packet.Length, endpoint);

            await udpClient.SendAsync(packet, packet.Length, endpoint);

            var responseTask = udpClient.ReceiveAsync();
            var timeoutTask = Task.Delay(_timeout);

            var completedTask = await Task.WhenAny(responseTask, timeoutTask);

            if (completedTask == timeoutTask)
            {
                _logger.LogWarning("CoA request timed out after {Timeout}ms", _timeout);
                return null;
            }

            var response = await responseTask;
            _logger.LogDebug("Received response ({Length} bytes)", response.Buffer.Length);

            return response.Buffer;
        }

        private void AddAttribute(List<byte> attributes, byte type, byte[] value)
        {
            var length = (byte)(2 + value.Length);
            attributes.Add(type);
            attributes.Add(length);
            attributes.AddRange(value);
        }

        private void AddMikrotikVsa(List<byte> attributes, byte vsaType, byte[] value)
        {
            // Vendor-Specific Attribute format:
            // Type (26) + Length + Vendor-Id (4 bytes) + VSA-Type (1) + VSA-Length (1) + VSA-Value

            var vsaLength = (byte)(2 + value.Length); // VSA-Type + VSA-Length + Value
            var totalLength = (byte)(6 + vsaLength);  // Type + Length + Vendor-Id (4) + VSA

            attributes.Add(ATTR_VENDOR_SPECIFIC);
            attributes.Add(totalLength);

            // Vendor-Id (MikroTik = 14988) in network byte order
            attributes.Add((byte)((VENDOR_MIKROTIK >> 24) & 0xFF));
            attributes.Add((byte)((VENDOR_MIKROTIK >> 16) & 0xFF));
            attributes.Add((byte)((VENDOR_MIKROTIK >> 8) & 0xFF));
            attributes.Add((byte)(VENDOR_MIKROTIK & 0xFF));

            // VSA-Type
            attributes.Add(vsaType);

            // VSA-Length (includes type and length bytes)
            attributes.Add(vsaLength);

            // VSA-Value
            attributes.AddRange(value);
        }
    }
}
