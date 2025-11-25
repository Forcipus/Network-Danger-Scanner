using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using ThreatIntelAPI.Models;

namespace ThreatIntelAPI.Services
{
    public class MongoService
    {
        private readonly IMongoCollection<ThreatReport> _reports;

        public MongoService(IConfiguration config)
        {
            var client = new MongoClient(config["MongoDB:ConnectionString"]);
            var database = client.GetDatabase(config["MongoDB:DatabaseName"]);
            _reports = database.GetCollection<ThreatReport>(config["MongoDB:ReportCollection"]);
        }

        public async Task SaveReport(ThreatReport report) =>
            await _reports.InsertOneAsync(report);

        public async Task<List<ThreatReport>> GetReports() =>
            await _reports.Find(_ => true).SortByDescending(r => r.Timestamp).ToListAsync();
    }
}
