using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Sentinel.Core;

public sealed partial class Journal
{
    private readonly SentinelPaths _paths;
    private readonly object _gate = new();
    private readonly JsonSerializerOptions _json = new() { WriteIndented = false };
    private string _lastHash = "";

    public Journal(SentinelPaths paths)
    {
        _paths = paths;
        Init();
    }

    private SqliteConnection Open()
    {
        var cn = new SqliteConnection($"Data Source={_paths.DbPath};Cache=Shared");
        cn.Open();
        using var cmd = cn.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;";
        cmd.ExecuteNonQuery();
        return cn;
    }

    private void Init()
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS files(
                    sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, path TEXT,
                    verdict INTEGER NOT NULL, score INTEGER NOT NULL, engines TEXT,
                    sig_version TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, type TEXT,
                    severity TEXT, path TEXT, sha256 TEXT, pid INTEGER,
                    message TEXT, json TEXT);
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
                CREATE TABLE IF NOT EXISTS quarantine(
                    id TEXT PRIMARY KEY, orig_path TEXT NOT NULL, sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL, detected_by TEXT, verdict INTEGER NOT NULL,
                    created_at TEXT NOT NULL, restored_at TEXT);
                CREATE TABLE IF NOT EXISTS allowlist(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                    value TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL,
                    expires_at TEXT);
                CREATE TABLE IF NOT EXISTS usage(
                    hour_key TEXT PRIMARY KEY, active_seconds INTEGER NOT NULL,
                    sample_count INTEGER NOT NULL);
                """;
            cmd.ExecuteNonQuery();

            using var read = cn.CreateCommand();
            read.CommandText = "SELECT value FROM meta WHERE key='last_log_hash'";
            _lastHash = read.ExecuteScalar() as string ?? "";
        }
    }

    public string GetMeta(string key)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT value FROM meta WHERE key=$k";
            cmd.Parameters.AddWithValue("$k", key);
            return cmd.ExecuteScalar() as string ?? "";
        }
    }

    public void SetMeta(string key, string value)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "INSERT INTO meta(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=$v";
            cmd.Parameters.AddWithValue("$k", key);
            cmd.Parameters.AddWithValue("$v", value);
            cmd.ExecuteNonQuery();
        }
    }

    public void Log(string type, string message, string severity = "info", string? path = null,
        string? sha256 = null, int? pid = null, object? data = null)
    {
        var ev = new LogEvent
        {
            Type = type,
            Severity = severity,
            Message = message,
            Path = path,
            Sha256 = sha256,
            Pid = pid,
            Json = data is null ? null : JsonSerializer.Serialize(data, _json)
        };

        lock (_gate)
        {
            try
            {
                using var cn = Open();
                using var cmd = cn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO events(ts,type,severity,path,sha256,pid,message,json)
                    VALUES($ts,$t,$s,$p,$h,$pid,$m,$j)
                    """;
                cmd.Parameters.AddWithValue("$ts", ev.Ts.ToString("O"));
                cmd.Parameters.AddWithValue("$t", ev.Type);
                cmd.Parameters.AddWithValue("$s", ev.Severity);
                cmd.Parameters.AddWithValue("$p", (object?)ev.Path ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$h", (object?)ev.Sha256 ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$pid", (object?)ev.Pid ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$m", ev.Message);
                cmd.Parameters.AddWithValue("$j", (object?)ev.Json ?? DBNull.Value);
                cmd.ExecuteNonQuery();
            }
            catch
            {
                // Journal must never take the pipeline down.
            }

            AppendJsonLine(ev);
        }
    }

    private void AppendJsonLine(LogEvent ev)
    {
        try
        {
            var payload = JsonSerializer.Serialize(ev, _json);
            var prev = _lastHash;
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(prev + payload))).ToLowerInvariant();
            var line = $"{{\"prev\":\"{prev}\",\"hash\":\"{hash}\",\"event\":{payload}}}";
            var file = Path.Combine(_paths.Logs, $"sentinel-{DateTime.Now:yyyyMMdd}.jsonl");
            File.AppendAllText(file, line + Environment.NewLine, Encoding.UTF8);
            _lastHash = hash;
            SetMetaUnsafe("last_log_hash", hash);
        }
        catch
        {
            // ignore
        }
    }

    private void SetMetaUnsafe(string key, string value)
    {
        using var cn = Open();
        using var cmd = cn.CreateCommand();
        cmd.CommandText = "INSERT INTO meta(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=$v";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    public bool TryGetCached(string sha256, string sigVersion, out ScanResult result)
    {
        result = new ScanResult();
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT size,path,verdict,score,engines,sig_version,last_seen FROM files WHERE sha256=$h";
            cmd.Parameters.AddWithValue("$h", sha256);
            using var r = cmd.ExecuteReader();
            if (!r.Read()) return false;
            if (!string.Equals(r.GetString(5), sigVersion, StringComparison.Ordinal)) return false;

            var verdict = (Verdict)r.GetInt32(2);
            if (verdict == Verdict.Unknown) return false;

            result = new ScanResult
            {
                Path = r.IsDBNull(1) ? "" : r.GetString(1),
                Sha256 = sha256,
                Size = r.GetInt64(0),
                Verdict = verdict,
                Score = r.GetInt32(3),
                ScannedAt = DateTimeOffset.Parse(r.GetString(6), CultureInfo.InvariantCulture),
                FromCache = true,
                Findings = new List<ScanFinding>()
            };
            if (!r.IsDBNull(4))
            {
                foreach (var name in r.GetString(4).Split(';', StringSplitOptions.RemoveEmptyEntries))
                    result.Findings.Add(new ScanFinding { Engine = "cache", Name = name });
            }
            return true;
        }
    }

    public void PutCached(ScanResult res, string sigVersion)
    {
        if (string.IsNullOrEmpty(res.Sha256)) return;
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO files(sha256,size,path,verdict,score,engines,sig_version,first_seen,last_seen)
                VALUES($h,$s,$p,$v,$sc,$e,$sig,$now,$now)
                ON CONFLICT(sha256) DO UPDATE SET
                  size=$s, path=$p, verdict=$v, score=$sc, engines=$e, sig_version=$sig, last_seen=$now
                """;
            cmd.Parameters.AddWithValue("$h", res.Sha256);
            cmd.Parameters.AddWithValue("$s", res.Size);
            cmd.Parameters.AddWithValue("$p", res.Path);
            cmd.Parameters.AddWithValue("$v", (int)res.Verdict);
            cmd.Parameters.AddWithValue("$sc", res.Score);
            cmd.Parameters.AddWithValue("$e", string.Join(';', res.Findings.Select(f => f.Name).Distinct()));
            cmd.Parameters.AddWithValue("$sig", sigVersion);
            cmd.Parameters.AddWithValue("$now", res.ScannedAt.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public bool IsAllowed(string? sha256, string path)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                SELECT COUNT(*) FROM allowlist
                WHERE (expires_at IS NULL OR expires_at > $now)
                  AND ((kind='sha256' AND value=$h) OR (kind='path' AND $p LIKE value || '%'))
                """;
            cmd.Parameters.AddWithValue("$h", (object?)sha256 ?? "");
            cmd.Parameters.AddWithValue("$p", path);
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.Now.ToString("O"));
            return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
        }
    }

    public void AddAllow(string kind, string value, string? reason, DateTimeOffset? expires)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "INSERT INTO allowlist(kind,value,reason,created_at,expires_at) VALUES($k,$v,$r,$c,$e)";
            cmd.Parameters.AddWithValue("$k", kind);
            cmd.Parameters.AddWithValue("$v", value);
            cmd.Parameters.AddWithValue("$r", (object?)reason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$c", DateTimeOffset.Now.ToString("O"));
            cmd.Parameters.AddWithValue("$e", expires is null ? DBNull.Value : expires.Value.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public List<AllowEntry> ListAllow()
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT id,kind,value,reason,created_at,expires_at FROM allowlist ORDER BY id DESC";
            using var r = cmd.ExecuteReader();
            var list = new List<AllowEntry>();
            while (r.Read())
            {
                list.Add(new AllowEntry
                {
                    Id = r.GetInt64(0),
                    Kind = r.GetString(1),
                    Value = r.GetString(2),
                    Reason = r.IsDBNull(3) ? null : r.GetString(3),
                    CreatedAt = DateTimeOffset.Parse(r.GetString(4), CultureInfo.InvariantCulture),
                    ExpiresAt = r.IsDBNull(5) ? null : DateTimeOffset.Parse(r.GetString(5), CultureInfo.InvariantCulture)
                });
            }
            return list;
        }
    }

    public bool RemoveAllow(long id)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "DELETE FROM allowlist WHERE id=$id";
            cmd.Parameters.AddWithValue("$id", id);
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    public void RecordUsage(string hourKey, int activeSeconds)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO usage(hour_key,active_seconds,sample_count) VALUES($k,$a,1)
                ON CONFLICT(hour_key) DO UPDATE SET
                  active_seconds=active_seconds+$a, sample_count=sample_count+1
                """;
            cmd.Parameters.AddWithValue("$k", hourKey);
            cmd.Parameters.AddWithValue("$a", activeSeconds);
            cmd.ExecuteNonQuery();
        }
    }

    public Dictionary<int, double> HourActivity()
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT hour_key,active_seconds,sample_count FROM usage";
            using var r = cmd.ExecuteReader();
            var sums = new double[24];
            var counts = new double[24];
            while (r.Read())
            {
                var key = r.GetString(0);
                if (!DateTime.TryParse(key, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt)) continue;
                sums[dt.Hour] += r.GetInt64(1);
                counts[dt.Hour] += r.GetInt64(2);
            }
            var result = new Dictionary<int, double>();
            for (var h = 0; h < 24; h++)
                result[h] = counts[h] <= 0 ? 0 : sums[h] / counts[h];
            return result;
        }
    }

    public List<LogEvent> RecentEvents(int limit = 50, string? type = null)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = type is null
                ? "SELECT ts,type,severity,path,sha256,pid,message,json FROM events ORDER BY id DESC LIMIT $n"
                : "SELECT ts,type,severity,path,sha256,pid,message,json FROM events WHERE type=$t ORDER BY id DESC LIMIT $n";
            cmd.Parameters.AddWithValue("$n", limit);
            if (type is not null) cmd.Parameters.AddWithValue("$t", type);
            using var r = cmd.ExecuteReader();
            var list = new List<LogEvent>();
            while (r.Read())
            {
                list.Add(new LogEvent
                {
                    Ts = DateTimeOffset.Parse(r.GetString(0), CultureInfo.InvariantCulture),
                    Type = r.GetString(1),
                    Severity = r.GetString(2),
                    Path = r.IsDBNull(3) ? null : r.GetString(3),
                    Sha256 = r.IsDBNull(4) ? null : r.GetString(4),
                    Pid = r.IsDBNull(5) ? null : r.GetInt32(5),
                    Message = r.GetString(6),
                    Json = r.IsDBNull(7) ? null : r.GetString(7)
                });
            }
            return list;
        }
    }

    public (long Total, long Malicious, long Suspicious, long Clean) Counters()
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*), SUM(verdict=3), SUM(verdict=2), SUM(verdict=1) FROM files";
            using var r = cmd.ExecuteReader();
            r.Read();
            return (r.GetInt64(0),
                r.IsDBNull(1) ? 0 : r.GetInt64(1),
                r.IsDBNull(2) ? 0 : r.GetInt64(2),
                r.IsDBNull(3) ? 0 : r.GetInt64(3));
        }
    }

    public void Purge(int retentionDays)
    {
        var cutoff = DateTimeOffset.Now.AddDays(-retentionDays).ToString("O");
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "DELETE FROM events WHERE ts < $c";
            cmd.Parameters.AddWithValue("$c", cutoff);
            cmd.ExecuteNonQuery();
        }

        try
        {
            foreach (var f in Directory.EnumerateFiles(_paths.Logs, "sentinel-*.jsonl"))
            {
                var name = Path.GetFileNameWithoutExtension(f).Replace("sentinel-", "");
                if (DateTime.TryParseExact(name, "yyyyMMdd", CultureInfo.InvariantCulture,
                        DateTimeStyles.None, out var dt) && dt < DateTime.Now.AddDays(-retentionDays))
                    File.Delete(f);
            }
        }
        catch
        {
            // ignore
        }
    }
}
