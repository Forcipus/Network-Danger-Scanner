using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using ThreatIntelAPI.Models;
using System;
using System.Text.RegularExpressions;
using ThreatIntelAPI.Services;
using Microsoft.Extensions.Configuration; //too many usings bruh

namespace ThreatIntelAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ThreatIntelController : ControllerBase
    {
        private readonly IHttpClientFactory _httpFactory;
        private readonly IConfiguration _config;
        private readonly MongoService _mongo;

        public ThreatIntelController(IHttpClientFactory httpFactory, IConfiguration config, MongoService mongo)
        {
            _httpFactory = httpFactory;
            _config = config;
            _mongo = mongo;
        }

        [HttpGet("lookup")]
        public async Task<IActionResult> Lookup([FromQuery] string query)
        {
            if (query == null || query == "") //empty query
                return BadRequest("query required");

            var report = new ThreatReport(); //construct report
            report.Query = query;
            report.ResolvedIP = null;

            //Console.WriteLine(report);
         

            // --- 1) Detect URL/domain/IP ---
            string ipToCheck = ExtractIP(query); //ip mi check

            if (ipToCheck == null) //url
            {
                try
                {
                    string host = ExtractHostname(query);
                    var entry = await Dns.GetHostAddressesAsync(host);

                    //Console.WriteLine(host);

                    if (entry.Length > 0)
                        ipToCheck = entry[0].ToString();

                    report.ResolvedIP = ipToCheck;
                }
                catch
                {
                    return BadRequest($"Unable URL or domain: {query}");
                }
            }
            else
            {
                report.ResolvedIP = ipToCheck; //ip
            }

            // --- 2) Now run all APIs using the resolved IP ---
            await QueryVirusTotal(report, ipToCheck);
            await QueryAbuseIPDB(report, ipToCheck);
            await QueryShodan(report, ipToCheck);

            // --- 3) Basic risk scoring ---
            try
            {
                if (report.AbuseIPDB is JsonElement abuseEl &&
                    abuseEl.TryGetProperty("data", out var dataEl) &&
                    dataEl.TryGetProperty("abuseConfidenceScore", out var confEl) &&
                    confEl.ValueKind == JsonValueKind.Number)
                {
                    int score = confEl.GetInt32();
                    report.OverallRisk = score > 50 ? "High" :
                                         score > 20 ? "Medium" :
                                         "Low";
                }
                //Console.WriteLine(report.OverallRisk);
            }
            catch
            {
                Console.WriteLine("Risk Score");
            }

            report.Timestamp = DateTime.UtcNow;
            await _mongo.SaveReport(report);
            return Ok(report);
        }


        [HttpPost("save")]
        public async Task<IActionResult> Save([FromBody] ThreatReport report)
        {
            if (report == null)
            {
                return BadRequest("report required");
            }

            report.Timestamp = DateTime.UtcNow;
            await _mongo.SaveReport(report);
            return Ok(new { message = "Rapor kaydedildi", id = report.Id });
        }

        // Frontend: GET /api/ThreatIntel/saved
        [HttpGet("saved")]
        public async Task<IActionResult> Saved()
        {
            var reports = await _mongo.GetReports();
            return Ok(reports);
        }

        // Orijinal /reports endpoint DO NOT REMOVE
        [HttpGet("reports")]
        public async Task<IActionResult> GetReports()
        {
            var reports = await _mongo.GetReports();
            return Ok(reports);
        }


        // ------------------ Functions ------------------

        private string ExtractIP(string input) //ip çıkart
        {
            IPAddress ipp;
            if (IPAddress.TryParse(input, out ipp))
            {
                return ipp.ToString();
            }
            return null;
        }

        private string ExtractHostname(string input) //url
        {
            if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
                return uri.Host;

            // No scheme → assume domain
            if (input.StartsWith("www."))
                return input;

            // Remove protocol if manually typed
            input = Regex.Replace(input, @"^https?://", "", RegexOptions.IgnoreCase);

            // Remove path
            int slash = input.IndexOf('/');
            if (slash >= 0)
                input = input.Substring(0, slash);

            return input;
        }

        // ------------------ API CALL FUNCTIONS ------------------
        private async Task QueryVirusTotal(ThreatReport report, string ip)
        {
            var vtKey = _config["VirusTotal:ApiKey"];
            if (string.IsNullOrEmpty(vtKey)) return;

            var client = _httpFactory.CreateClient("VirusTotal");
            client.DefaultRequestHeaders.Remove("x-apikey");
            client.DefaultRequestHeaders.Add("x-apikey", vtKey);

            try
            {
                var resp = await client.GetAsync($"ip_addresses/{ip}");
                if (resp.IsSuccessStatusCode)
                    report.VirusTotal = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.Clone();
            }
            catch { }
        }

        private async Task QueryAbuseIPDB(ThreatReport report, string ip)
        {
            var key = _config["AbuseIPDB:ApiKey"];
            if (string.IsNullOrEmpty(key)) return;

            var client = _httpFactory.CreateClient("AbuseIPDB");
            client.DefaultRequestHeaders.Remove("Key");
            client.DefaultRequestHeaders.Add("Key", key);

            try
            {
                var resp = await client.GetAsync($"check?ipAddress={ip}&maxAgeInDays=90");
                if (resp.IsSuccessStatusCode)
                    report.AbuseIPDB = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.Clone();
            }
            catch { }
        }

        private async Task QueryShodan(ThreatReport report, string ip)
        {
            var key = _config["Shodan:ApiKey"];
            if (string.IsNullOrEmpty(key)) return;

            var client = _httpFactory.CreateClient("Shodan");
            try
            {
                var resp = await client.GetAsync($"shodan/host/{ip}?key={key}");
                if (resp.IsSuccessStatusCode)
                    report.Shodan = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.Clone();
            }
            catch { }
        }
    }
}
