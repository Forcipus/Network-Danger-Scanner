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


            // --- 3) Comprehensive risk scoring ---
            try
            {
                int abuseScore = 0;
                int vtMaliciousCount = 0;
                bool hasShodanData = false;

                // 1. AbuseIPDB Skoru (0-100 arası)
                if (report.AbuseIPDB is JsonElement abuseEl && abuseEl.ValueKind == JsonValueKind.Object)
                {
                    if (abuseEl.TryGetProperty("data", out var dataEl) &&
                        dataEl.TryGetProperty("abuseConfidenceScore", out var confEl))
                    {
                        abuseScore = confEl.GetInt32();
                    }
                }

                // 2. VirusTotal Malicious tespiti yapan motor sayısı
                if (report.VirusTotal is JsonElement vtEl && vtEl.ValueKind == JsonValueKind.Object)
                {
                    if (vtEl.TryGetProperty("data", out var vtData) &&
                        vtData.TryGetProperty("attributes", out var vtAttrs) &&
                        vtAttrs.TryGetProperty("last_analysis_stats", out var vtStats) &&
                        vtStats.TryGetProperty("malicious", out var vtMalicious))
                    {
                        vtMaliciousCount = vtMalicious.GetInt32();
                    }
                }

                // 3. Shodan'da açık servis/port bilgisi var mı?
                if (report.Shodan is JsonElement shoEl && shoEl.ValueKind == JsonValueKind.Object)
                {
                    // Shodan veri dönmüşse genellikle "data" veya "ports" dizisi dolu olur
                    if (shoEl.TryGetProperty("ports", out var portsEl) && portsEl.GetArrayLength() > 0)
                    {
                        hasShodanData = true;
                    }
                }

                // --- Karar Mantığı ---
                // Yüksek Risk: Abuse skoru > 50 VEYA VT'de 3'ten fazla motor zararlı demişse
                if (abuseScore > 50 || vtMaliciousCount >= 3)
                {
                    report.OverallRisk = "High";
                }
                // Orta Risk: Abuse skoru > 10 VEYA VT'de en az 1 motor zararlı demişse VEYA Shodan'da açık port varsa
                else if (abuseScore > 10 || vtMaliciousCount > 0 || hasShodanData)
                {
                    report.OverallRisk = "Medium";
                }
                // Düşük Risk: Yukarıdakilerin hiçbiri karşılanmıyorsa
                else
                {
                    report.OverallRisk = "Low";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Risk Score Calculation Error: " + ex.Message);
                report.OverallRisk = "Unknown";
            }

            report.Timestamp = DateTime.UtcNow;
            /*await _mongo.SaveReport(report);*/
            return Ok(new
            {
                id = report.Id,
                query = report.Query,
                resolvedIP = report.ResolvedIP,
                overallRisk = report.OverallRisk,
                virusTotal = report.VirusTotal,
                abuseIPDB = report.AbuseIPDB,
                shodan = report.Shodan,
                timestamp = report.Timestamp
            });
             
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
            try
            {
                var reports = await _mongo.GetReports();
                return Ok(reports);
            }
            catch (Exception ex)
            {
                // Loglama yapıp boş liste dönerek frontend'in çökmesini engelliyoruz
                Console.WriteLine($"Liste yükleme hatası: {ex.Message}");
                return Ok(new List<ThreatReport>());
            }
        }
        

        // Orijinal /reports endpoint DO NOT REMOVE
        [HttpGet("reports")]
        public async Task<IActionResult> GetReports()
        {
            var reports = await _mongo.GetReports();
            return Ok(reports);
        }

        //Delete 
        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> Delete(string id)
        {
            try
            {
                await _mongo.DeleteReport(id);
                return Ok(new { message = "Rapor silindi" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Silme hatası", error = ex.Message });
            }
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
                {
                    var content = await resp.Content.ReadAsStringAsync();
                    using (JsonDocument doc = JsonDocument.Parse(content))
                    {
                        // .Clone() kullanmak, JsonDocument dispose edilse bile verinin hafızada kalmasını sağlar
                        report.VirusTotal = doc.RootElement.Clone();
                    }
                }
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
                {
                    var content = await resp.Content.ReadAsStringAsync();
                    using (JsonDocument doc = JsonDocument.Parse(content))
                    {
                        report.AbuseIPDB = doc.RootElement.Clone();
                    }
                }
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
                {
                    var content = await resp.Content.ReadAsStringAsync();
                    using (JsonDocument doc = JsonDocument.Parse(content))
                    {
                        report.Shodan = doc.RootElement.Clone();
                    }
                }
            }
            catch { }
        }
    }
}
