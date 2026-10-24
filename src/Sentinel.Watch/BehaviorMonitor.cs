using System.Diagnostics;
using Sentinel.Core;
using Sentinel.Engines;

namespace Sentinel.Watch;

/// <summary>
/// Watches process creation (by polling, deliberately cheap) and verifies anything that starts
/// from a download/temp location. This is detection + response, not pre-execution blocking:
/// user mode cannot stop CreateProcess before it happens.
/// </summary>
public sealed class BehaviorMonitor : IDisposable
{
    private readonly SentinelConfig _config;
    private readonly ScanPipeline _pipeline;
    private readonly Journal _journal;
    private readonly HashSet<int> _known = new();
    private readonly SemaphoreSlim _scanSlots = new(2, 2);
    private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);
    private readonly string[] _interestRoots;

    public BehaviorMonitor(SentinelConfig config, ScanPipeline pipeline, Journal journal)
    {
        _config = config;
        _pipeline = pipeline;
        _journal = journal;

        var roots = config.WatchPaths
            .Concat(new[] { "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop", "%TEMP%" })
            .Select(SentinelPaths.Expand)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        _interestRoots = roots;
    }

    public void Prime()
    {
        foreach (var p in Process.GetProcesses())
        {
            _known.Add(p.Id);
            p.Dispose();
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        Prime();
        var interval = TimeSpan.FromSeconds(Math.Clamp(_config.Behavior.PollSeconds, 2, 30));
        _journal.Log("behavior", $"Behavior monitor started ({interval.TotalSeconds:0}s poll, {_known.Count} processes primed)", "info");
        using var timer = new PeriodicTimer(interval);

        while (await timer.WaitForNextTickAsync(ct))
        {
            try
            {
                Tick();
            }
            catch (Exception ex)
            {
                _journal.Log("behavior", "Process poll failed: " + ex.Message, "warning");
            }
        }
    }

    private void Tick()
    {
        var seen = new HashSet<int>();
        foreach (var proc in Process.GetProcesses())
        {
            using (proc)
            {
                var pid = proc.Id;
                seen.Add(pid);
                if (!_known.Add(pid)) continue;
                if (pid <= 4) continue;

                string? path = null;
                try
                {
                    if (proc.HasExited) continue;
                    path = proc.MainModule?.FileName;
                }
                catch
                {
                    // protected / cross-bitness / already gone
                }

                if (string.IsNullOrEmpty(path)) continue;
                if (!_interestRoots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase))) continue;

                var key = $"{pid}:{path}";
                lock (_reported)
                {
                    if (!_reported.Add(key)) continue;
                }

                var zone = Heuristics.MotwZone(path);
                _journal.Log("exec", $"Started from watched location: {path}",
                    zone is "3" or "4" ? "warning" : "info", path, pid: pid,
                    data: new { zone, proc.ProcessName });

                _ = Task.Run(() => VerifyAsync(path, pid));
            }
        }

        // Forget exited processes so the set does not grow forever.
        _known.IntersectWith(seen);
    }

    private async Task VerifyAsync(string path, int pid)
    {
        if (!await _scanSlots.WaitAsync(TimeSpan.FromSeconds(30))) return;
        try
        {
            if (!File.Exists(path)) return;
            var result = await _pipeline.ScanAsync(path);
            if (result.Verdict == Verdict.Clean) return;

            _journal.Log("exec", $"Executed file is {result.Verdict}: {path}",
                result.Verdict == Verdict.Malicious ? "critical" : "warning",
                path, result.Sha256, pid,
                new { result.Score, Findings = result.Findings.Select(f => f.ToString()) });

            if (result.Verdict != Verdict.Malicious) return;
            if (_config.Response.Mode != ResponseMode.Auto || !_config.Behavior.KillMalicious) return;

            try
            {
                using var proc = Process.GetProcessById(pid);
                if (!proc.HasExited && string.Equals(proc.MainModule?.FileName, path,
                        StringComparison.OrdinalIgnoreCase))
                {
                    proc.Kill(true);
                    _journal.Log("response", $"Killed process {pid} ({path})", "warning", path, result.Sha256, pid);
                }
            }
            catch (Exception ex)
            {
                _journal.Log("response", $"Could not kill {pid}: {ex.Message}", "error", path, pid: pid);
            }

            _pipeline.ApplyResponse(result);
        }
        catch (Exception ex)
        {
            _journal.Log("behavior", $"Verification failed for {path}: {ex.Message}", "error", path);
        }
        finally
        {
            _scanSlots.Release();
        }
    }

    public void Dispose()
    {
        _scanSlots.Dispose();
    }
}
