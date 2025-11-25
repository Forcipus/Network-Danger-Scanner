/*
using Microsoft.AspNetCore.Mvc;
using ThreatIntelAggregator.Models;


namespace ThreatIntelAggregator.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ThreatController : ControllerBase
    {
        private static readonly List<ThreatReport> SavedReports = new();


        [HttpGet("check")]
        public IActionResult CheckThreat(string query)
        {
            if (string.IsNullOrWhiteSpace(query))
                return BadRequest(new { error = "Invalid IP or domain." });

            // Fake data for now
            var result = new
            {
                query = query,
                virusTotal = new { maliciousVotes = 0 },
                abuseIPDB = new { reports = 3 },
                shodan = new { openPorts = new[] { 80, 443 } },
                riskScore = "Low"
            };

            return Ok(result);
        }

        [HttpPost("save")]
        public IActionResult SaveThreat([FromBody] ThreatReport report)
        {
            SavedReports.Add(report);
            return Ok(new { message = "Report saved successfully.", count = SavedReports.Count });
        }

        [HttpGet("reports")]
        public IActionResult GetReports()
        {
            return Ok(SavedReports);
        }
    }
}
*/