using System.Security.Cryptography;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Engines;

public sealed class ScanPipeline
{
    private readonly SentinelPaths _paths;
    private readonly SentinelConfig _config;
    private readonly Journal _journal;
    private readonly QuarantineService _quarantine;
    private readonly List<IScanEngine> _engines = new();
    private readonly string _sigVersion;

    public ScanPipeline(SentinelPaths paths, SentinelConfig config, Journal journal, QuarantineService quarantine)
    {
        _paths = paths;
        _config = config;
        _journal = journal;
        _quarantine = quarantine;

        if (config.Engines.Builtin) _engines.Add(new BuiltinEngine());
        if (config.Engines.Defender) _engines.Add(new DefenderEngine());
        if (config.Engines.YaraX.Enabled) _engines.Add(new YaraXEngine(config.Engines.YaraX, paths));
        if (config.Engines.ClamAv.Enabled) _engines.Add(new ClamAvEngine(config.Engines.ClamAv));

        _sigVersion = ComputeSigVersion();
    }

    public string SignatureVersion => _sigVersion;

    public async Task<ScanResult> ScanAsync(string path, bool deep = false, bool force = false,
        CancellationToken ct = default)
    {
        var full = Path.GetFullPath(path);
        var result = new ScanResult { Path = full };

        if (!File.Exists(full))
        {
            result.Verdict = Verdict.Unknown;
            result.Error = "file not found";
            return result;
        }

        var info = new FileInfo(full);
        result.Size = info.Length;

        if (info.Length > _config.Scan.MaxFileSizeMb * 1024L * 1024L)
        {
            result.Verdict = Verdict.Unknown;
            result.Error = $"larger than {_config.Scan.MaxFileSizeMb} MB (skipped)";
            _journal.Log("scan", $"Skipped large file {full}", "info", full);
            return result;
        }

        if (info.Length <= _config.Scan.MaxHashSizeMb * 1024L * 1024L)
        {
            try { result.Sha256 = HashUtil.Sha256File(full, _config.Scan.MaxHashSizeMb * 1024L * 1024L); }
            catch (Exception ex)
            {
                result.Verdict = Verdict.Unknown;
                result.Error = "hash failed: " + ex.Message;
                return result;
            }
        }

        if (!force && result.Sha256 is not null &&
            _journal.TryGetCached(result.Sha256, _sigVersion, out var cached))
        {
            cached.Path = full;
            return cached;
        }

        if (_journal.IsAllowed(result.Sha256, full))
        {
            result.Verdict = Verdict.Clean;
            result.Findings.Add(new ScanFinding { Engine = "policy", Name = "allowlisted" });
            return result;
        }

        result.Findings.AddRange(Heuristics.Inspect(full, deep, out _));
        var score = Score(result.Findings);
        var anyEngineRan = false;

        foreach (var engine in _engines)
        {
            ct.ThrowIfCancellationRequested();
            EngineResult er;
            try
            {
                er = await engine.ScanFileAsync(full, deep, ct);
            }
            catch (Exception ex)
            {
                er = new EngineResult { Engine = engine.Name, Available = false, Error = ex.Message };
            }

            if (er.Available) anyEngineRan = true;
            if (er.Infected)
            {
                result.Findings.Add(new ScanFinding
                {
                    Engine = er.Engine, Name = er.Signature ?? "malware", Severity = "critical",
                    Detail = er.Duration.TotalMilliseconds.ToString("F0") + " ms"
                });
            }
            else if (er.Available && er.Error is not null)
            {
                result.Findings.Add(new ScanFinding
                {
                    Engine = er.Engine, Name = "engine-error", Severity = "info", Detail = er.Error
                });
            }
        }

        var engineHit = result.Findings.Any(f => f.Severity == "critical");
        if (engineHit)
        {
            result.Verdict = Verdict.Malicious;
            result.Score = 100;
        }
        else if (score >= _config.Response.MaliciousThreshold)
        {
            result.Verdict = Verdict.Malicious;
            result.Score = score;
        }
        else if (score >= _config.Response.SuspiciousThreshold)
        {
            result.Verdict = Verdict.Suspicious;
            result.Score = score;
        }
        else
        {
            result.Verdict = anyEngineRan ? Verdict.Clean : Verdict.Unknown;
            result.Score = score;
        }

        result.ScannedAt = DateTimeOffset.Now;
        _journal.PutCached(result, _sigVersion);
        _journal.Log("scan", $"{full} => {result.Verdict} ({result.Score})",
            result.Verdict switch
            {
                Verdict.Malicious => "critical",
                Verdict.Suspicious => "warning",
                _ => "info"
            },
            full, result.Sha256,
            data: new { result.Verdict, result.Score, Findings = result.Findings.Select(f => f.ToString()) });

        return result;
    }

    /// <summary>Quarantine or notify according to the configured response mode.</summary>
    public QuarantineEntry? ApplyResponse(ScanResult result)
    {
        if (result.Sha256 is null || !File.Exists(result.Path)) return null;
        var mode = _config.Response.Mode;
        var detectedBy = string.Join(",", result.Findings.Select(f => f.Engine).Distinct());

        var shouldQuarantine =
            (result.Verdict == Verdict.Malicious && _config.Response.QuarantineMalicious) ||
            (result.Verdict == Verdict.Suspicious && _config.Response.QuarantineSuspicious);

        if (!shouldQuarantine) return null;

        if (mode == ResponseMode.DryRun)
        {
            _journal.Log("response", $"[dry-run] would quarantine {result.Path}", "info", result.Path, result.Sha256);
            return null;
        }

        try
        {
            return _quarantine.Add(result.Path, result.Sha256, result.Verdict, detectedBy);
        }
        catch (Exception ex)
        {
            _journal.Log("response", $"Quarantine failed for {result.Path}: {ex.Message}", "error", result.Path);
            return null;
        }
    }

    public async Task<(int Scanned, int Malicious, int Suspicious)> ScanTreeAsync(
        IEnumerable<string> roots, bool deep, DateTimeOffset? since, Action<ScanResult>? onResult = null,
        CancellationToken ct = default)
    {
        int scanned = 0, malicious = 0, suspicious = 0;
        foreach (var root in roots.Select(SentinelPaths.Expand).Where(Directory.Exists))
        {
            foreach (var file in EnumerateFiles(root))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (since is not null && File.GetLastWriteTimeUtc(file) < since.Value.UtcDateTime) continue;
                    var res = await ScanAsync(file, deep, ct: ct);
                    if (res.FromCache) continue;
                    scanned++;
                    if (res.Verdict == Verdict.Malicious) malicious++;
                    if (res.Verdict == Verdict.Suspicious) suspicious++;
                    onResult?.Invoke(res);
                }
                catch (OperationCanceledException) { throw; }
                catch { /* unreadable file */ }
            }
        }
        return (scanned, malicious, suspicious);
    }

    private IEnumerable<string> EnumerateFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> files;
            IEnumerable<string> dirs;
            try
            {
                files = Directory.EnumerateFiles(dir);
                dirs = Directory.EnumerateDirectories(dir);
            }
            catch
            {
                continue;
            }

            foreach (var f in files)
            {
                if (f.StartsWith(_paths.Data, StringComparison.OrdinalIgnoreCase)) continue;
                yield return f;
            }

            foreach (var d in dirs)
            {
                try
                {
                    var attrs = File.GetAttributes(d);
                    if (attrs.HasFlag(FileAttributes.ReparsePoint)) continue;
                }
                catch { continue; }
                stack.Push(d);
            }
        }
    }

    private static int Score(IEnumerable<ScanFinding> findings) => Math.Min(95,
        findings.Sum(f => f.Severity switch
        {
            "critical" => 60,
            "high" => 30,
            "warning" => 15,
            "info" => 5,
            _ => 0
        }));

    private string ComputeSigVersion()
    {
        var sb = new StringBuilder();
        sb.Append(_config.Scan.MaxFileSizeMb).Append('|');
        foreach (var e in _engines) sb.Append(e.Name).Append('|');

        try
        {
            var dir = string.IsNullOrWhiteSpace(_config.Engines.YaraX.RulesDir)
                ? _paths.YaraRulesDir
                : SentinelPaths.Expand(_config.Engines.YaraX.RulesDir);
            if (Directory.Exists(dir))
            {
                foreach (var f in Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
                             .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                {
                    var fi = new FileInfo(f);
                    sb.Append(fi.Name).Append(':').Append(fi.Length).Append(':').Append(fi.LastWriteTimeUtc.Ticks).Append('|');
                }
            }
        }
        catch
        {
            // rules dir unreadable, keep whatever we have
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}
