namespace HotelWifiPortal.Models.Entities
{
    public class FiasMessage
    {
        public string RecordId { get; set; } = string.Empty;
        public Dictionary<string, string> Fields { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.Now;

        public string GetField(string fieldId) =>
            Fields.TryGetValue(fieldId, out var value) ? value : string.Empty;
    }
}
