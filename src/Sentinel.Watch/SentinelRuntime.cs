using System.Globalization;
using Sentinel.Core;
using Sentinel.Engines;

namespace Sentinel.Watch;

/// <summary>The always-on, deliberately cheap part: watch drops, sample usage, run the weekly deep scan.</summary>
public sealed class SentinelRuntime : IAsyncDisposable
{
    private readonly SentinelPaths _paths;
    private readonly SentinelConfig _config;
    private readonly Journal _journal;
    private readonly ScanPipeline _pipeline;
    private readonly UsageStats _usage;
    private readonly DropWatcher _watcher;
    private readonly BehaviorMonitor _behavior;

    public SentinelRuntime(SentinelPaths paths, SentinelConfig config, Journal journal,
        ScanPipeline pipeline, UsageStats usage)
    {
        _paths = paths;
        _config = config;
        _journal = journal;
        _pipeline = pipeline;
        _usage = usage;
        _watcher = new DropWatcher(config, pipeline, journal, paths);
        _behavior = new BehaviorMonitor(config, pipeline, journal);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _journal.Log("runtime", $"Sentinel started (home={_paths.Root}, engine set={_pipeline.SignatureVersion})", "info");
        _watcher.Start();

        var tasks = new List<Task>
        {
            _watcher.RunAsync(ct),
            SampleLoopAsync(ct),
            ScheduleLoopAsync(ct),
            MaintenanceLoopAsync(ct)
        };
        if (_config.Behavior.Enabled) tasks.Add(_behavior.RunAsync(ct));
        else _journal.Log("runtime", "Behavior monitor disabled in config", "info");

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        finally
        {
            _watcher.Dispose();
            _behavior.Dispose();
            _journal.Log("runtime", "Sentinel stopped", "info");
        }
    }

    private async Task SampleLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (await timer.WaitForNextTickAsync(ct))
        {
            try { _usage.Sample(); }
            catch { /* sampling must never stop the runtime */ }
        }
    }

    private async Task ScheduleLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5));
        while (await timer.WaitForNextTickAsync(ct))
        {
            try
            {
                if (await MaybeRunWeeklyAsync(ct)) continue;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _journal.Log("schedule", $"Weekly scan check failed: {ex.Message}", "error");
            }
        }
    }

    private async Task<bool> MaybeRunWeeklyAsync(CancellationToken ct)
    {
        if (!_config.Schedule.WeeklyEnabled) return false;

        var lastText = _journal.GetMeta("last_weekly_scan");
        DateTimeOffset last = DateTimeOffset.MinValue;
        if (!string.IsNullOrEmpty(lastText))
            DateTimeOffset.TryParse(lastText, CultureInfo.InvariantCulture, DateTimeStyles.None, out last);

        if (DateTimeOffset.Now - last < TimeSpan.FromDays(_config.Schedule.IntervalDays)) return false;

        var window = _usage.IsColdStart()
            ? (3, (3 + _config.Schedule.QuietWindowHours) % 24)
            : _usage.QuietWindow(_config.Schedule.QuietWindowHours);

        if (!InWindow(DateTime.Now.Hour, window.Item1, window.Item2)) return false;
        if (Win32.IdleTime() < TimeSpan.FromMinutes(_config.Schedule.MinIdleMinutes)) return false;
        if (Win32.IsOnBattery()) return false;

        _journal.Log("schedule", $"Weekly deep scan starting (quiet window {window.Item1:00}:00-{window.Item2:00}:00)", "info");
        Win32.LowPriority(true);
        try
        {
            var since = last == DateTimeOffset.MinValue ? (DateTimeOffset?)null : last.AddHours(-1);
            var (scanned, malicious, suspicious) = await _pipeline.ScanTreeAsync(
                _config.WeeklyRoots, deep: _config.Scan.DeepWeekly, since, ct: ct);

            _journal.SetMeta("last_weekly_scan", DateTimeOffset.Now.ToString("O"));
            _journal.Log("schedule",
                $"Weekly deep scan finished: {scanned} scanned, {malicious} malicious, {suspicious} suspicious",
                malicious > 0 ? "critical" : "info");
            Reporter.Write(_paths, _journal);
        }
        finally
        {
            Win32.LowPriority(false);
        }
        return true;
    }

    private static bool InWindow(int hour, int start, int end)
    {
        if (start == end) return true;
        return start < end
            ? hour >= start && hour < end
            : hour >= start || hour < end;
    }

    private async Task MaintenanceLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(6));
        while (await timer.WaitForNextTickAsync(ct))
        {
            try { _journal.Purge(_config.Journal.RetentionDays); }
            catch { /* ignore */ }
            await Task.Yield();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _watcher.Dispose();
        await Task.CompletedTask;
    }
}
