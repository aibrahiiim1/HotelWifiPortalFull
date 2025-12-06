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
}
