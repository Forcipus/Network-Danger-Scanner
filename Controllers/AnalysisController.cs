using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Linq;
using System.Net.Sockets;
using System.Collections.Generic;

namespace CyberAnalyzer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AnalysisController : ControllerBase
    {
        // HttpClient instance
        private static readonly HttpClient client = new HttpClient();
        private static readonly ConcurrentBag<object> SavedReports = new ConcurrentBag<object>();

        //api key
        private const string VirusTotalApiKey = "0c4126b1020f9e5f3f7346fa3983a650f254c20d7901b7c8a79673b3611f26a6";
        private const string AbuseIpdbApiKey = "d63fb5a8a4779b3c9481ee09f8c1a2d7301658a0bfa59399288c3aa7cc5e3fb63076849d046da752";
        private const string ShodanApiKey = "lOH0g1Yqm6hT7g5CuyZqEOM469jF4lFs";

        [HttpGet("analyze")]
        public async Task<IActionResult> Analyze([FromQuery] string query)
        {
            if (string.IsNullOrWhiteSpace(query))
            {
                return BadRequest(new { error = "query param is required" });
            }

            // Normalize input so URLs without scheme still work (ör: "www.example.com" veya "example.com/path")
            string normalizedQuery = query;
            Uri? normalizedUri = null;
            string? host = null;

            if (Uri.TryCreate(query, UriKind.Absolute, out var uri))
            {
                normalizedUri = uri;
                normalizedQuery = uri.AbsoluteUri;
                host = uri.Host;
            }
            else
            {
                // Eğer kullanıcı scheme belirtmediyse ama muhtemel bir URL ise http:// ekleyip tekrar dene
                if (query.StartsWith("www.", System.StringComparison.OrdinalIgnoreCase) || query.Contains("/"))
                {
                    if (Uri.TryCreate("http://" + query, UriKind.Absolute, out var uri2))
                    {
                        normalizedUri = uri2;
                        normalizedQuery = uri2.AbsoluteUri;
                        host = uri2.Host;
                    }
                }

                if (normalizedUri == null) //ip mo bak
                {
                    if (IPAddress.TryParse(query, out _))
                    {
                        // ip olarak bırak
                        normalizedQuery = query;
                        host = null;
                    }
                    else
                    {
                        // Muhtemel domain (örn: example.com)
                        normalizedQuery = query;
                        host = query;
                    }
                }
            }

            var report = new //construct report
            {
                query = normalizedQuery,
                virusTotal = await GetVirusTotalSummary(normalizedQuery, host),
                abuseIPDB = await GetAbuseIPDBSummary(normalizedQuery, host),
                shodan = await GetShodanSummary(normalizedQuery, host),
            };

            string overallRisk = EvaluateRisk(report);
            return Ok(new { report.query, report.virusTotal, report.abuseIPDB, report.shodan, overallRisk });

            //Console.WriteLine(report.query, report.virusTotal, report.abuseIPDB, report.shodan, overallRisk);
        }

        [HttpPost("save")]
        public IActionResult SaveReport([FromBody] object report)
        {
            SavedReports.Add(report);
            return Ok(new { message = "Report" });
        }

        [HttpGet("saved")]
        public IActionResult GetSavedReports() => Ok(SavedReports);

        //risk degerlendirme
        private static string EvaluateRisk(dynamic r)
        {
            int num1 = 0;
            if (r.virusTotal != null && r.virusTotal.Contains("malicious")) num1++;
            if (r.abuseIPDB != null && r.abuseIPDB.Contains("high confidence")) num1++;
            if (r.shodan != null && r.shodan.Contains("vulnerable")) num1++;

            return num1 switch
            {
                0 => "Low",
                1 => "Medium",
                _ => "High"
            };
        }

        //virustotal
        private async Task<string> GetVirusTotalSummary(string query, string? host)
        {
            try
            {
                string url;
                if (Uri.TryCreate(query, UriKind.Absolute, out var uri))
                {
                    var id = Base64UrlEncode(query);
                    url = $"https://www.virustotal.com/api/v3/urls/{id}";
                }
                else if (IPAddress.TryParse(query, out _))
                {
                    url = $"https://www.virustotal.com/api/v3/ip_addresses/{WebUtility.UrlEncode(query)}";
                }
                else
                {
                    url = $"https://www.virustotal.com/api/v3/domains/{WebUtility.UrlEncode(query)}";
                }

                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.Add("x-apikey", VirusTotalApiKey);
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var res = await client.SendAsync(req);
                if (!res.IsSuccessStatusCode)
                {
                    // Eğer URL sorgusu için 404 döndüyse, domain bilgisi varsa domain endpoint'ine bak
                    if (res.StatusCode == HttpStatusCode.NotFound && !string.IsNullOrEmpty(host))
                    {
                        using var req2 = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/domains/{WebUtility.UrlEncode(host)}");
                        req2.Headers.Add("x-apikey", VirusTotalApiKey);
                        req2.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        var r2 = await client.SendAsync(req2);
                        if (!r2.IsSuccessStatusCode) return $"No data from VirusTotal (HTTP {(int)r2.StatusCode}): {r2.ReasonPhrase}";
                        var j2 = await r2.Content.ReadAsStringAsync();
                        return j2.Contains("malicious", StringComparison.OrdinalIgnoreCase) ? "Malicious activity detected (domain)" : "Domain info from VirusTotal";
                    }

                    return $"No data from VirusTotal (HTTP {(int)res.StatusCode}): {res.ReasonPhrase}";
                }

                var json = await res.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.ToString().Contains("malicious", System.StringComparison.OrdinalIgnoreCase)) return "Malicious activity detected";
                if (root.ToString().Contains("harmless", System.StringComparison.OrdinalIgnoreCase) || root.ToString().Contains("clean", System.StringComparison.OrdinalIgnoreCase)) return "Clean";
                return "VirusTotal no verdict";
            }
            catch
            {
                return "VirusTotal unavailable";
            }
        }

        //abuseipdb

        private async Task<string> GetAbuseIPDBSummary(string query, string? host)
        {
            try
            {
                // Direkt IP ise sorgula
                if (IPAddress.TryParse(query, out _))
                {
                    return await QueryAbuseIpdbForIp(query);
                }

                // Eğer domain/URL ise host varsa DNS çözümlemesi yap
                if (string.IsNullOrEmpty(host) && Uri.TryCreate(query, UriKind.Absolute, out var tmp)) host = tmp.Host;
                if (!string.IsNullOrEmpty(host))
                {
                    var ips = await TryResolveHostToIps(host);
                    if (ips.Count == 0) return "AbuseIPDB: host could not be resolved to IP";
                    var results = new List<string>();
                    foreach (var ip in ips)
                    {
                        results.Add(await QueryAbuseIpdbForIp(ip));
                    }
                    return string.Join(" | ", results);
                }

                return "AbuseIPDB expects an IP or resolvable domain";
            }
            catch
            {
                return "AbuseIPDB unavailable";
            }
        }

        //abuseipdb ip ise

        private async Task<string> QueryAbuseIpdbForIp(string ip)
        {
            var url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={WebUtility.UrlEncode(ip)}&maxAgeInDays=90";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Add("Key", AbuseIpdbApiKey);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var res = await client.SendAsync(req);
            if (!res.IsSuccessStatusCode) return $"No data from AbuseIPDB (HTTP {(int)res.StatusCode}): {res.ReasonPhrase}";
            var json = await res.Content.ReadAsStringAsync();
            return json.Contains("abuseConfidenceScore") ? $"High confidence of abuse for {ip}" : $"Low confidence for {ip}";
        }

        //shodan
        private async Task<string> GetShodanSummary(string query, string? host)
        {
            try
            {
                // Shodan host endpoint expects IP; çözümle
                if (IPAddress.TryParse(query, out _)) return await QueryShodanForIp(query);

                if (string.IsNullOrEmpty(host) && Uri.TryCreate(query, UriKind.Absolute, out var tmp)) host = tmp.Host;
                if (!string.IsNullOrEmpty(host))
                {
                    var ips = await TryResolveHostToIps(host);
                    if (ips.Count == 0) return "Shodan: host could not be resolved to IP";
                    var results = new List<string>();
                    foreach (var ip in ips)
                    {
                        results.Add(await QueryShodanForIp(ip));
                    }
                    return string.Join(" | ", results);
                }

                return "Shodan host endpoint expects an IP address or resolvable domain";
            }
            catch
            {
                return "Shodan unavailable";
            }
        }

        //shodan ip ise
        private async Task<string> QueryShodanForIp(string ip)
        {
            var url = $"https://api.shodan.io/shodan/host/{WebUtility.UrlEncode(ip)}?key={WebUtility.UrlEncode(ShodanApiKey)}";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var res = await client.SendAsync(req);
            if (!res.IsSuccessStatusCode) return $"No data from Shodan (HTTP {(int)res.StatusCode}): {res.ReasonPhrase}";
            var json = await res.Content.ReadAsStringAsync();
            return json.Contains("vulns") ? $"Vulnerabilities found for {ip}" : $"No vulnerabilities for {ip}";
        }

        private static async Task<List<string>> TryResolveHostToIps(string host)
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(host);
                return addrs
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork || a.AddressFamily == AddressFamily.InterNetworkV6)
                    .Select(a => a.ToString())
                    .ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        // Yardımcı: URL'leri VirusTotal'un beklediği base64url formatına çevirir
        private static string Base64UrlEncode(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            var base64 = Convert.ToBase64String(bytes);
            return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }
    }
}
