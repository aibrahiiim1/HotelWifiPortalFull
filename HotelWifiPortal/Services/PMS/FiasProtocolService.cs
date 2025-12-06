using HotelWifiPortal.Models.Entities;
using Microsoft.EntityFrameworkCore;
using System.Text;

namespace HotelWifiPortal.Services.PMS
{
    public class FiasProtocolService
    {
        private const char STX = (char)0x02;
        private const char ETX = (char)0x03;
        private const char FIELD_SEPARATOR = '|';

        private readonly ILogger<FiasProtocolService> _logger;
        private readonly IServiceProvider _serviceProvider;

        public event Action<Guest>? OnGuestUpdated;
        public event Action<string>? OnGuestRemoved;

        private int _guestImportCount = 0;
        private DateTime _lastBatchLogTime = DateTime.MinValue;

        public FiasProtocolService(ILogger<FiasProtocolService> logger, IServiceProvider serviceProvider)
        {
            _logger = logger;
            _serviceProvider = serviceProvider;
        }

        public FiasMessage? ParseMessage(string rawMessage)
        {
            try
            {
                int stxPos = rawMessage.IndexOf(STX);
                int etxPos = rawMessage.IndexOf(ETX);

                string messageContent;
                char? lrcChar = null;

                if (stxPos >= 0 && etxPos > stxPos)
                {
                    messageContent = rawMessage.Substring(stxPos + 1, etxPos - stxPos - 1);
                    if (etxPos + 1 < rawMessage.Length)
                    {
                        lrcChar = rawMessage[etxPos + 1];
                    }
                }
                else
                {
                    messageContent = rawMessage.Trim(STX, ETX, '\r', '\n', ' ');
                }

                if (string.IsNullOrWhiteSpace(messageContent))
                    return null;

                var fields = messageContent.Split(FIELD_SEPARATOR);
                if (fields.Length < 1) return null;

                var message = new FiasMessage
                {
                    RecordId = fields[0],
                    Timestamp = DateTime.Now
                };

                for (int i = 1; i < fields.Length; i++)
                {
                    if (string.IsNullOrEmpty(fields[i])) continue;

                    if (fields[i].Length >= 2)
                    {
                        var fieldId = fields[i].Substring(0, 2);
                        var fieldValue = fields[i].Length > 2 ? fields[i].Substring(2) : string.Empty;
                        message.Fields[fieldId] = fieldValue;
                    }
                }

                return message;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing FIAS message");
                return null;
            }
        }

        public string BuildMessage(string recordId, Dictionary<string, string> fields)
        {
            var sb = new StringBuilder();
            sb.Append(recordId);
            sb.Append(FIELD_SEPARATOR);

            foreach (var field in fields)
            {
                sb.Append(field.Key);
                sb.Append(field.Value);
                sb.Append(FIELD_SEPARATOR);
            }

            var message = sb.ToString();
            var lrc = CalculateLRC(message);

            return $"{STX}{message}{ETX}{lrc}";
        }

        private char CalculateLRC(string data)
        {
            byte lrc = 0;
            foreach (char c in data)
            {
                lrc ^= (byte)c;
            }
            return (char)lrc;
        }

        public async Task<string?> ProcessMessageAsync(FiasMessage message)
        {
            return message.RecordId switch
            {
                "LS" => HandleLinkStart(message),
                "LA" => HandleLinkAlive(message),
                "LE" => HandleLinkEnd(message),
                "LD" => null,
                "LR" => null,
                "DR" => HandleDatabaseResync(message),
                "DS" => HandleDatabaseResyncStart(message),
                "DE" => HandleDatabaseResyncEnd(message),
                "GI" => await HandleGuestCheckInAsync(message),
                "GO" => await HandleGuestCheckOutAsync(message),
                "GC" => await HandleGuestChangeAsync(message),
                "PS" => HandlePostingSimple(message),
                "PR" => HandlePostingRequest(message),
                "PA" => null,
                "PL" => null,
                _ => null
            };
        }

        private string HandleLinkStart(FiasMessage message)
        {
            _logger.LogInformation("FIAS Link Start received");
            return BuildMessage("LS", new Dictionary<string, string>
            {
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") }
            });
        }

        private string HandleLinkAlive(FiasMessage message)
        {
            return BuildMessage("LA", new Dictionary<string, string>
            {
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") }
            });
        }

        private string HandleLinkEnd(FiasMessage message)
        {
            _logger.LogInformation("FIAS Link End received");
            return BuildMessage("LE", new Dictionary<string, string>
            {
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") }
            });
        }

        public string BuildLinkDescription()
        {
            return BuildMessage("LD", new Dictionary<string, string>
            {
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") },
                { "V#", "1.0" },
                { "IF", "WW" },
                { "RT", "1" }
            });
        }

        public List<string> BuildLinkRecords()
        {
            var records = new List<string>();
            var recordDefinitions = new Dictionary<string, string>
            {
                { "GI", "RNG#GNGLGAGDGSGV" },
                { "GO", "RNG#GS" },
                { "GC", "RNG#GNGLGAGDGSROGV" },
                { "PS", "RNTATIDATISOPM" },
                { "PR", "RNG#PMPITADATIWS" },
                { "PL", "RNG#GNGLDATIWS" },
                { "PA", "RNASCTDATIWS" }
            };

            foreach (var definition in recordDefinitions)
            {
                records.Add(BuildMessage("LR", new Dictionary<string, string>
                {
                    { "RI", definition.Key },
                    { "FL", definition.Value }
                }));
            }

            return records;
        }

        private string? HandleDatabaseResync(FiasMessage message)
        {
            _logger.LogInformation("Database resync requested");
            return null;
        }

        private string? HandleDatabaseResyncStart(FiasMessage message)
        {
            _guestImportCount = 0;
            _lastBatchLogTime = DateTime.Now;
            _logger.LogInformation("Database Resync Start");
            return null;
        }

        private string? HandleDatabaseResyncEnd(FiasMessage message)
        {
            _logger.LogInformation("Database Resync End - Total guests imported: {Count}", _guestImportCount);
            _guestImportCount = 0;
            return null;
        }

        private async Task<string?> HandleGuestCheckInAsync(FiasMessage message)
        {
            var roomNumber = message.GetField("RN");
            var reservationNumber = message.GetField("G#");
            var guestName = message.GetField("GN");

            _logger.LogInformation("=== Guest Check-In Received ===");
            _logger.LogInformation("Room: {Room}, Reservation: {Res}, Name: {Name}",
                roomNumber, reservationNumber, guestName);
            _logger.LogInformation("All fields: {Fields}",
                string.Join(", ", message.Fields.Select(f => $"{f.Key}={f.Value}")));

            if (string.IsNullOrEmpty(reservationNumber))
            {
                reservationNumber = !string.IsNullOrEmpty(roomNumber)
                    ? $"RES-{roomNumber}-{DateTime.Now:HHmmss}"
                    : Guid.NewGuid().ToString("N").Substring(0, 10).ToUpper();
            }

            var guestKey = !string.IsNullOrEmpty(reservationNumber) ? reservationNumber : roomNumber;
            if (string.IsNullOrEmpty(guestKey))
            {
                _logger.LogWarning("No guest key found - skipping");
                return null;
            }

            var guest = new Guest
            {
                RoomNumber = roomNumber ?? "",
                ReservationNumber = guestKey,
                GuestName = guestName ?? "Unknown Guest",
                Language = message.GetField("GL"),
                VipStatus = message.GetField("GV"),
                Status = "checked-in",
                Source = "PMS"
            };

            // Parse dates
            var arrivalStr = message.GetField("GA");
            if (!string.IsNullOrEmpty(arrivalStr))
            {
                if (DateTime.TryParseExact(arrivalStr, "yyMMdd", null, System.Globalization.DateTimeStyles.None, out var arrivalDate))
                    guest.ArrivalDate = arrivalDate;
                else if (DateTime.TryParseExact(arrivalStr, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out arrivalDate))
                    guest.ArrivalDate = arrivalDate;
                else if (DateTime.TryParse(arrivalStr, out arrivalDate))
                    guest.ArrivalDate = arrivalDate;
            }
            else
            {
                guest.ArrivalDate = DateTime.Today;
            }

            var departureStr = message.GetField("GD");
            if (!string.IsNullOrEmpty(departureStr))
            {
                if (DateTime.TryParseExact(departureStr, "yyMMdd", null, System.Globalization.DateTimeStyles.None, out var departureDate))
                    guest.DepartureDate = departureDate;
                else if (DateTime.TryParseExact(departureStr, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out departureDate))
                    guest.DepartureDate = departureDate;
                else if (DateTime.TryParse(departureStr, out departureDate))
                    guest.DepartureDate = departureDate;
            }
            else
            {
                guest.DepartureDate = DateTime.Today.AddDays(1);
            }

            // Save to database
            await SaveGuestAsync(guest);

            _guestImportCount++;
            var now = DateTime.Now;
            if (_guestImportCount % 50 == 0 || (now - _lastBatchLogTime).TotalSeconds >= 2)
            {
                _logger.LogInformation("Guests imported: {Count}", _guestImportCount);
                _lastBatchLogTime = now;
            }

            OnGuestUpdated?.Invoke(guest);
            return null;
        }

        private async Task<string?> HandleGuestCheckOutAsync(FiasMessage message)
        {
            var reservationNumber = message.GetField("G#");
            var roomNumber = message.GetField("RN");

            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<Data.ApplicationDbContext>();

            var guest = await dbContext.Guests.FirstOrDefaultAsync(g => g.ReservationNumber == reservationNumber);
            if (guest != null)
            {
                guest.Status = "checked-out";
                guest.UpdatedAt = DateTime.UtcNow;
                await dbContext.SaveChangesAsync();

                _logger.LogInformation("Guest checked out: Room {Room}", roomNumber);
            }

            return null;
        }

        private async Task<string?> HandleGuestChangeAsync(FiasMessage message)
        {
            var reservationNumber = message.GetField("G#");

            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<Data.ApplicationDbContext>();

            var guest = await dbContext.Guests.FirstOrDefaultAsync(g => g.ReservationNumber == reservationNumber);
            if (guest != null)
            {
                if (message.Fields.ContainsKey("RN"))
                    guest.RoomNumber = message.GetField("RN");
                if (message.Fields.ContainsKey("GN"))
                    guest.GuestName = message.GetField("GN");
                if (message.Fields.ContainsKey("GL"))
                    guest.Language = message.GetField("GL");
                if (message.Fields.ContainsKey("GV"))
                    guest.VipStatus = message.GetField("GV");

                guest.UpdatedAt = DateTime.UtcNow;
                await dbContext.SaveChangesAsync();

                OnGuestUpdated?.Invoke(guest);
            }

            return null;
        }

        private string HandlePostingSimple(FiasMessage message)
        {
            var roomNumber = message.GetField("RN");
            var amount = message.GetField("TA");
            _logger.LogInformation("Posting received: Room {Room}, Amount {Amount}", roomNumber, amount);

            return BuildMessage("PA", new Dictionary<string, string>
            {
                { "RN", roomNumber },
                { "AS", "OK" },
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") }
            });
        }

        private string HandlePostingRequest(FiasMessage message)
        {
            var roomNumber = message.GetField("RN");
            var amount = message.GetField("TA");

            return BuildMessage("PA", new Dictionary<string, string>
            {
                { "RN", roomNumber },
                { "AS", "OK" },
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") }
            });
        }

        public string BuildPostingMessage(string roomNumber, string reservationNumber, decimal amount, string description)
        {
            var amountCents = ((int)(amount * 100)).ToString();

            return BuildMessage("PS", new Dictionary<string, string>
            {
                { "RN", roomNumber },
                { "G#", reservationNumber },
                { "TA", amountCents },
                { "CT", description },
                { "DA", DateTime.Now.ToString("yyMMdd") },
                { "TI", DateTime.Now.ToString("HHmmss") }
            });
        }

        private async Task SaveGuestAsync(Guest guest)
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<Data.ApplicationDbContext>();
            var quotaService = scope.ServiceProvider.GetRequiredService<QuotaService>();

            var existingGuest = await dbContext.Guests.FirstOrDefaultAsync(g => g.ReservationNumber == guest.ReservationNumber);

            if (existingGuest != null)
            {
                existingGuest.RoomNumber = guest.RoomNumber;
                existingGuest.GuestName = guest.GuestName;
                existingGuest.Language = guest.Language;
                existingGuest.ArrivalDate = guest.ArrivalDate;
                existingGuest.DepartureDate = guest.DepartureDate;
                existingGuest.VipStatus = guest.VipStatus;
                existingGuest.Status = guest.Status;
                existingGuest.UpdatedAt = DateTime.UtcNow;
            }
            else
            {
                // Calculate free quota for new guest
                guest.FreeQuotaBytes = await quotaService.CalculateFreeQuotaAsync(guest.StayLength);
                guest.CreatedAt = DateTime.UtcNow;
                guest.UpdatedAt = DateTime.UtcNow;
                dbContext.Guests.Add(guest);
            }

            await dbContext.SaveChangesAsync();
        }

        public static List<string> GetSupportedRecordTypes()
        {
            return new List<string>
            {
                "LS - Link Start",
                "LA - Link Alive",
                "LE - Link End",
                "LD - Link Description",
                "LR - Link Record",
                "GI - Guest Check-in",
                "GO - Guest Check-out",
                "GC - Guest Change",
                "PS - Posting Simple",
                "PR - Posting Request",
                "PA - Posting Answer"
            };
        }
    }
}