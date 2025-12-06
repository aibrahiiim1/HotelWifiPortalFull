using HotelWifiPortal.Models.Entities;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HotelWifiPortal.Services.PMS
{
    public class FiasSocketServer
    {
        private TcpListener? _listener;
        private TcpClient? _client;
        private NetworkStream? _stream;
        private bool _isRunning;
        private readonly FiasProtocolService _protocolService;
        private readonly ILogger<FiasSocketServer> _logger;
        private CancellationToken _cancellationToken;

        private DateTime? _lastConnectionTime;
        private DateTime? _lastMessageTime;
        private int _messagesSent;
        private int _messagesReceived;
        private string? _clientIpAddress;
        private int _port = 5008;

        public bool IsConnected => _client?.Connected ?? false;
        public bool IsRunning => _isRunning;

        public event Action<string>? OnConnectionStatusChanged;
        public event Action<FiasMessage>? OnMessageReceived;

        public FiasSocketServer(FiasProtocolService protocolService, ILogger<FiasSocketServer> logger)
        {
            _protocolService = protocolService;
            _logger = logger;
        }

        public void SetPort(int port) => _port = port;

        public (bool IsConnected, string Status, DateTime? LastConnectionTime, DateTime? LastMessageTime,
                int MessagesSent, int MessagesReceived, string? ClientIpAddress) GetStatus()
        {
            return (
                IsConnected,
                IsConnected ? "connected" : (_isRunning ? "listening" : "stopped"),
                _lastConnectionTime,
                _lastMessageTime,
                _messagesSent,
                _messagesReceived,
                _clientIpAddress
            );
        }

        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            _cancellationToken = cancellationToken;

            try
            {
                _listener = new TcpListener(IPAddress.Any, _port);
                _listener.Start();
                _isRunning = true;

                _logger.LogInformation("FIAS Socket Server started on port {Port}", _port);
                OnConnectionStatusChanged?.Invoke("listening");

                while (_isRunning && !cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        _logger.LogInformation("Waiting for PMS connection...");

                        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        _client = await _listener.AcceptTcpClientAsync(cts.Token);
                        _stream = _client.GetStream();
                        _lastConnectionTime = DateTime.Now;
                        _clientIpAddress = ((IPEndPoint?)_client.Client.RemoteEndPoint)?.Address.ToString();

                        _logger.LogInformation("PMS Client connected from {IP}", _clientIpAddress);
                        OnConnectionStatusChanged?.Invoke("connected");

                        await SendMessageAsync("LS", new Dictionary<string, string>
                        {
                            { "DA", DateTime.Now.ToString("yyMMdd") },
                            { "TI", DateTime.Now.ToString("HHmmss") }
                        });

                        await HandleClientAsync();

                        _logger.LogInformation("Client session ended, returning to listening state");
                        OnConnectionStatusChanged?.Invoke("listening");
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (SocketException ex)
                    {
                        if (!_isRunning || cancellationToken.IsCancellationRequested) break;
                        _logger.LogWarning("Socket exception: {Message}", ex.Message);
                        OnConnectionStatusChanged?.Invoke("listening");
                        await Task.Delay(1000, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error handling client");
                        OnConnectionStatusChanged?.Invoke("listening");
                        await Task.Delay(1000, cancellationToken);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                _logger.LogInformation("Server shutdown completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Server error");
                OnConnectionStatusChanged?.Invoke("error");
            }
            finally
            {
                _isRunning = false;
                _listener?.Stop();
            }
        }

        private async Task HandleClientAsync()
        {
            try
            {
                var buffer = new byte[8192];
                var messageBuilder = new StringBuilder();
                const char STX = (char)0x02;
                const char ETX = (char)0x03;

                while (_isRunning && _client != null && _client.Connected && _stream != null && !_cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        if (_client.Available == 0)
                        {
                            await Task.Delay(10, _cancellationToken);
                            if (_client.Client.Poll(1000, SelectMode.SelectRead) && _client.Available == 0)
                            {
                                if (!_client.Connected) break;
                            }
                            continue;
                        }

                        var bytesRead = await _stream.ReadAsync(buffer, 0, buffer.Length, _cancellationToken);
                        if (bytesRead == 0) break;

                        var data = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                        messageBuilder.Append(data);

                        var fullBuffer = messageBuilder.ToString();
                        var processedUpTo = 0;

                        while (true)
                        {
                            var stxPos = fullBuffer.IndexOf(STX, processedUpTo);
                            var etxPos = fullBuffer.IndexOf(ETX, processedUpTo);

                            if (etxPos == -1) break;

                            var messageEnd = etxPos + 1;
                            if (messageEnd < fullBuffer.Length && fullBuffer[messageEnd] != STX)
                                messageEnd++;

                            var messageStart = stxPos >= 0 && stxPos < etxPos ? stxPos : processedUpTo;
                            var singleMessage = fullBuffer.Substring(messageStart, messageEnd - messageStart);

                            _messagesReceived++;
                            _lastMessageTime = DateTime.Now;

                            var parsedMessage = _protocolService.ParseMessage(singleMessage);
                            if (parsedMessage != null)
                            {
                                OnMessageReceived?.Invoke(parsedMessage);
                                await ProcessMessageAsync(parsedMessage);
                            }

                            processedUpTo = messageEnd;
                        }

                        if (processedUpTo > 0)
                        {
                            messageBuilder.Clear();
                            if (processedUpTo < fullBuffer.Length)
                                messageBuilder.Append(fullBuffer.Substring(processedUpTo));
                        }

                        if (messageBuilder.Length > 65536)
                            messageBuilder.Clear();
                    }
                    catch (IOException)
                    {
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Client handler error");
            }
            finally
            {
                CleanupClientConnection();
            }
        }

        private async Task ProcessMessageAsync(FiasMessage message)
        {
            _logger.LogInformation("FIAS Message received: Type={Type}, Fields={Fields}",
                message.RecordId,
                string.Join(", ", message.Fields.Select(f => $"{f.Key}={f.Value}")));

            var needsAck = message.RecordId switch
            {
                "LS" or "LA" or "LE" or "PS" or "PR" or "DR" or "DS" or "DE" or "GI" or "GO" or "GC" => true,
                _ => false
            };

            if (needsAck)
                await SendAckAsync();

            if (message.RecordId == "LS")
            {
                _logger.LogInformation("Link Start received - sending handshake");
                await Task.Delay(50);
                await SendRawMessageAsync(_protocolService.BuildLinkDescription());
                await Task.Delay(50);

                foreach (var lr in _protocolService.BuildLinkRecords())
                {
                    await SendRawMessageAsync(lr);
                    await Task.Delay(20);
                }

                await SendMessageAsync("LA", new Dictionary<string, string>
                {
                    { "DA", DateTime.Now.ToString("yyMMdd") },
                    { "TI", DateTime.Now.ToString("HHmmss") }
                });

                // Wait a bit then request database resync
                _ = Task.Run(async () =>
                {
                    await Task.Delay(2000);
                    _logger.LogInformation("Requesting database resync from PMS...");
                    await RequestDatabaseResyncAsync();
                });
                return;
            }

            var response = await _protocolService.ProcessMessageAsync(message);
            if (!string.IsNullOrEmpty(response))
            {
                _logger.LogDebug("Sending response: {Response}", response);
                await SendRawMessageAsync(response);
            }
        }

        public async Task SendMessageAsync(string recordId, Dictionary<string, string> fields)
        {
            var message = _protocolService.BuildMessage(recordId, fields);
            await SendRawMessageAsync(message);
        }

        public async Task SendRawMessageAsync(string message)
        {
            if (_stream == null || _client == null || !_client.Connected) return;

            try
            {
                var bytes = Encoding.ASCII.GetBytes(message);
                await _stream.WriteAsync(bytes, 0, bytes.Length);
                await _stream.FlushAsync();
                _messagesSent++;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Send error");
            }
        }

        private async Task SendAckAsync()
        {
            if (_stream == null) return;
            await _stream.WriteAsync(new byte[] { 0x06 }, 0, 1);
            await _stream.FlushAsync();
        }

        private void CleanupClientConnection()
        {
            try { _stream?.Close(); _stream?.Dispose(); _stream = null; } catch { }
            try { _client?.Close(); _client?.Dispose(); _client = null; } catch { }
            _clientIpAddress = null;
        }

        public void Disconnect()
        {
            CleanupClientConnection();
            OnConnectionStatusChanged?.Invoke("listening");
        }

        public void Stop()
        {
            _isRunning = false;
            CleanupClientConnection();
            try { _listener?.Stop(); } catch { }
            OnConnectionStatusChanged?.Invoke("stopped");
        }

        public async Task RequestDatabaseResyncAsync()
        {
            if (!IsConnected)
            {
                _logger.LogWarning("Cannot request resync - not connected");
                return;
            }

            _logger.LogInformation("Requesting database resync from PMS");
            await SendMessageAsync("DR", new Dictionary<string, string>
            {
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") }
            });
        }

        public async Task PostChargeAsync(string roomNumber, string reservationNumber, decimal amount, string description)
        {
            if (!IsConnected)
            {
                _logger.LogWarning("Cannot post charge - not connected");
                return;
            }

            var message = _protocolService.BuildPostingMessage(roomNumber, reservationNumber, amount, description);
            await SendRawMessageAsync(message);
            _logger.LogInformation("Posted charge to PMS: Room {Room}, Amount {Amount}", roomNumber, amount);
        }
    }

    public class FiasServerBackgroundService : BackgroundService
    {
        private readonly FiasSocketServer _socketServer;
        private readonly ILogger<FiasServerBackgroundService> _logger;
        private readonly IServiceProvider _serviceProvider;

        public FiasServerBackgroundService(FiasSocketServer socketServer, ILogger<FiasServerBackgroundService> logger, IServiceProvider serviceProvider)
        {
            _socketServer = socketServer;
            _logger = logger;
            _serviceProvider = serviceProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Wait for app to start
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

            try
            {
                // Get PMS settings
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<Data.ApplicationDbContext>();
                var pmsSettings = await dbContext.PmsSettings.FirstOrDefaultAsync(stoppingToken);

                if (pmsSettings?.IsEnabled == true)
                {
                    _socketServer.SetPort(pmsSettings.ListenPort);
                    _logger.LogInformation("Starting FIAS Server on port {Port}", pmsSettings.ListenPort);
                    await _socketServer.StartAsync(stoppingToken);
                }
                else
                {
                    _logger.LogInformation("PMS integration is disabled");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting FIAS server");
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _socketServer.Stop();
            await base.StopAsync(cancellationToken);
        }
    }
}