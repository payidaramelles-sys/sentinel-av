using System.Threading.Channels;
using Sentinel.Core;
using Sentinel.Engines;

namespace Sentinel.Watch;

/// <summary>Watches download/temp folders and scans files as they finish writing.</summary>
public sealed class DropWatcher : IDisposable
{
    private static readonly string[] PartialSuffixes =
    {
        ".crdownload", ".part", ".partial", ".tmp", ".download", ".!ut", ".opdownload", ".aria2"
    };

    private readonly SentinelConfig _config;
    private readonly ScanPipeline _pipeline;
    private readonly Journal _journal;
    private readonly string _ownDataDir;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly Channel<string> _queue = Channel.CreateUnbounded<string>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
    private readonly HashSet<string> _pending = new(StringComparer.OrdinalIgnoreCase);

    public DropWatcher(SentinelConfig config, ScanPipeline pipeline, Journal journal, SentinelPaths paths)
    {
        _config = config;
        _pipeline = pipeline;
        _journal = journal;
        _ownDataDir = paths.Data;
    }

    public void Start()
    {
        foreach (var raw in _config.WatchPaths)
        {
            var path = SentinelPaths.Expand(raw);
            if (!Directory.Exists(path))
            {
                _journal.Log("watch", $"Watch path missing, skipped: {path}", "info");
                continue;
            }

            try
            {
                var fsw = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024,
                    EnableRaisingEvents = true
                };
                fsw.Created += (_, e) => Enqueue(e.FullPath);
                fsw.Renamed += (_, e) => Enqueue(e.FullPath);
                fsw.Error += (_, e) => _journal.Log("watch", $"Watcher error: {e.GetException().Message}", "warning");
                _watchers.Add(fsw);
                _journal.Log("watch", $"Watching {path}", "info");
            }
            catch (Exception ex)
            {
                _journal.Log("watch", $"Cannot watch {path}: {ex.Message}", "warning");
            }
        }
    }

    private void Enqueue(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            if (path.StartsWith(_ownDataDir, StringComparison.OrdinalIgnoreCase)) return;
            if (Directory.Exists(path)) return;
            if (PartialSuffixes.Any(s => path.EndsWith(s, StringComparison.OrdinalIgnoreCase))) return;

            lock (_pending)
            {
                if (!_pending.Add(path)) return;
            }
            _queue.Writer.TryWrite(path);
        }
        catch
        {
            // watcher callbacks must not throw
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        await foreach (var path in _queue.Reader.ReadAllAsync(ct))
        {
            try
            {
                if (!await WaitUntilReadableAsync(path, ct)) continue;
                if (!File.Exists(path)) continue;

                var result = await _pipeline.ScanAsync(path, deep: _config.Scan.ScanArchives, ct: ct);
                var entry = _pipeline.ApplyResponse(result);

                _journal.Log("drop", $"New file {result.Verdict}: {path}",
                    result.Verdict == Verdict.Malicious ? "critical"
                    : result.Verdict == Verdict.Suspicious ? "warning" : "info",
                    path, result.Sha256,
                    data: new
                    {
                        result.Score,
                        result.FromCache,
                        Quarantined = entry?.Id,
                        Findings = result.Findings.Select(f => f.ToString())
                    });
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _journal.Log("drop", $"Scan failed for {path}: {ex.Message}", "error", path);
            }
            finally
            {
                lock (_pending) _pending.Remove(path);
            }
        }
    }

    private static async Task<bool> WaitUntilReadableAsync(string path, CancellationToken ct)
    {
        for (var i = 0; i < 40; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.None, 1, FileOptions.None);
                return true;
            }
            catch (FileNotFoundException)
            {
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                return false;
            }
            catch
            {
                await Task.Delay(250, ct);
            }
        }
        return false;
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch { }
        }
        _queue.Writer.TryComplete();
    }
}
