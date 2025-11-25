using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Text.Json;

namespace ThreatIntelAPI.Models
{
    public class ThreatReport
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; } = string.Empty;
        public string Query { get; set; } = string.Empty;
        public string ResolvedIP { get; set; }
        public JsonElement? VirusTotal { get; set; }
        public JsonElement? AbuseIPDB { get; set; }
        public JsonElement? Shodan { get; set; }
        public string OverallRisk { get; set; } = "Unknown";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}