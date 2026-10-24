using System.Diagnostics;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Watch;

namespace Sentinel.Tray;

/// <summary>WebView2 arayüzü ile .NET arasındaki komut köprüsü.</summary>
internal sealed class UiBridge
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly SentinelPaths _paths;
    private readonly SentinelConfig _config;
    private readonly Journal _journal;
    private readonly QuarantineService _quarantine;
    private readonly ScanPipeline _pipeline;
    private readonly AppLockerTrust _trust;
    private readonly Action<object> _push;
    private int _scanning;

    public UiBridge(SentinelPaths paths, SentinelConfig config, Journal journal,
        QuarantineService quarantine, ScanPipeline pipeline, Action<object> push)
    {
        _paths = paths;
        _config = config;
        _journal = journal;
        _quarantine = quarantine;
        _pipeline = pipeline;
        _push = push;
        _trust = new AppLockerTrust(paths.Root);
    }

    public async Task<object> HandleAsync(string command, JsonElement args)
    {
        switch (command)
        {
            case "status":
                return Status();

            case "events":
                return Events(args);

            case "quarantine.list":
                return QuarantineList();

            case "quarantine.restore":
                return RestoreQuarantine(args);

            case "quarantine.delete":
                return DeleteQuarantine(args);

            case "scan.start":
                return await StartScanAsync(args);

            case "mode.set":
                return SetMode(args);

            case "trust.status":
                return await TrustStatusAsync();

            case "trust.list":
                return await TrustListAsync();

            case "trust.add":
                return await TrustAddAsync(args);

            case "trust.remove":
                return await TrustRemoveAsync(args);

            case "trust.mode":
                return await TrustModeAsync(args);

            case "trust.applyElevated":
                return TrustApplyElevated();

            case "trust.browse":
                return TrustBrowse(args);

            case "report.open":
                Open(Reporter.Write(_paths, _journal));
                return new { opened = true };

            case "config.open":
                Open(_paths.ConfigPath);
                return new { opened = true };

            case "folder.open":
                return OpenFolder(args);

            case "app.quit":
                Application.Exit();
                return new { quitting = true };

            default:
                throw new InvalidOperationException($"Bilinmeyen komut: {command}");
        }
    }

    public static string Serialize(object value) => JsonSerializer.Serialize(value, Json);

    private object Status()
    {
        var (total, malicious, suspicious, clean) = _journal.Counters();
        var quarantineCount = _journal.ListQuarantine().Count(q => q.RestoredAt is null);
        var (quietStart, quietEnd) = new UsageStats(_journal, _paths)
            .QuietWindow(_config.Schedule.QuietWindowHours);

        return new
        {
            root = _paths.Root,
            configPath = _paths.ConfigPath,
            quarantineDir = _paths.QuarantineDir,
            reportsDir = _paths.Reports,
            admin = SentinelPaths.IsAdmin(),
            mode = _config.Response.Mode.ToString(),
            signatureVersion = _pipeline.SignatureVersion,
            counters = new { total, malicious, suspicious, clean },
            quarantine = quarantineCount,
            quiet = new { start = quietStart, end = quietEnd },
            behavior = _config.Behavior.Enabled,
            sac = SacState(),
            engines = new
            {
                builtin = _config.Engines.Builtin,
                defender = _config.Engines.Defender,
                yaraX = _config.Engines.YaraX.Enabled,
                clamAv = _config.Engines.ClamAv.Enabled
            },
            watchPaths = _config.WatchPaths.Select(SentinelPaths.Expand).ToArray(),
            weeklyRoots = _config.WeeklyRoots.Select(SentinelPaths.Expand).ToArray(),
            schedule = new
            {
                weeklyEnabled = _config.Schedule.WeeklyEnabled,
                intervalDays = _config.Schedule.IntervalDays,
                quietWindowHours = _config.Schedule.QuietWindowHours
            }
        };
    }

    private object Events(JsonElement args)
    {
        var limit = 200;
        if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty("limit", out var l) && l.TryGetInt32(out var n))
            limit = Math.Clamp(n, 1, 1000);

        string? type = null;
        if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty("type", out var t) &&
            t.ValueKind == JsonValueKind.String)
            type = t.GetString();

        return _journal.RecentEvents(limit, string.IsNullOrWhiteSpace(type) ? null : type)
            .Select(e => new
            {
                ts = e.Ts,
                type = e.Type,
                severity = e.Severity,
                message = e.Message,
                path = e.Path,
                sha256 = e.Sha256,
                pid = e.Pid
            })
            .ToArray();
    }

    private object QuarantineList() => _journal.ListQuarantine()
        .Where(q => q.RestoredAt is null)
        .OrderByDescending(q => q.CreatedAt)
        .Select(q => new
        {
            id = q.Id,
            createdAt = q.CreatedAt,
            originalPath = q.OriginalPath,
            verdict = q.Verdict.ToString(),
            size = q.Size,
            detectedBy = q.DetectedBy,
            sha256 = q.Sha256
        })
        .ToArray();

    private object RestoreQuarantine(JsonElement args)
    {
        var id = RequireString(args, "id");
        var destination = _quarantine.Restore(id);
        _push(new { @event = "toast", data = new { kind = "success", text = $"Geri yüklendi: {destination}" } });
        return new { destination };
    }

    private object DeleteQuarantine(JsonElement args)
    {
        var id = RequireString(args, "id");
        _quarantine.Delete(id);
        _push(new { @event = "toast", data = new { kind = "success", text = "Karantina kaydı silindi" } });
        return new { deleted = true };
    }

    private async Task<object> StartScanAsync(JsonElement args)
    {
        var deep = args.ValueKind == JsonValueKind.Object &&
                   args.TryGetProperty("deep", out var d) &&
                   d.ValueKind == JsonValueKind.True;

        if (Interlocked.Exchange(ref _scanning, 1) == 1)
            throw new InvalidOperationException("Zaten bir tarama sürüyor.");

        try
        {
            var watch = Stopwatch.StartNew();
            var scanned = 0;
            var bad = 0;
            var suspicious = 0;

            Action<ScanResult> onResult = result =>
            {
                var count = Interlocked.Increment(ref scanned);
                if (result.Verdict == Verdict.Malicious) Interlocked.Increment(ref bad);
                if (result.Verdict == Verdict.Suspicious) Interlocked.Increment(ref suspicious);
                if (count % 3 != 0) return;
                _push(new
                {
                    @event = "scan.progress",
                    data = new
                    {
                        scanned = count,
                        bad = Volatile.Read(ref bad),
                        suspicious = Volatile.Read(ref suspicious),
                        file = Path.GetFileName(result.Path)
                    }
                });
            };

            _push(new { @event = "scan.started", data = new { deep } });

            var summary = await _pipeline.ScanTreeAsync(_config.WeeklyRoots, deep, null, onResult);
            var payload = new
            {
                scanned = summary.Scanned,
                bad = summary.Malicious,
                suspicious = summary.Suspicious,
                seconds = Math.Round(watch.Elapsed.TotalSeconds, 1),
                deep
            };

            _push(new { @event = "scan.done", data = payload });

            if (summary.Malicious > 0)
                _push(new
                {
                    @event = "toast",
                    data = new { kind = "warn", text = $"{summary.Malicious} kötü dosya bulundu" }
                });

            return payload;
        }
        finally
        {
            Interlocked.Exchange(ref _scanning, 0);
        }
    }

    private object SetMode(JsonElement args)
    {
        var raw = RequireString(args, "mode");
        var mode = raw.ToLowerInvariant() switch
        {
            "dryrun" => ResponseMode.DryRun,
            "notify" => ResponseMode.Notify,
            "auto" => ResponseMode.Auto,
            _ => throw new ArgumentException($"Geçersiz mod: {raw}")
        };

        _config.Response.Mode = mode;
        _config.Save(_paths.ConfigPath);
        _journal.Log("config", $"Response mode set to {mode}", "info");

        return new { mode = mode.ToString() };
    }

    /* ---------- güven listesi (AppLocker) ---------- */

    /// <summary>Smart App Control durumu: 0 kapalı, 1 zorunlu, 2 değerlendirme, -1 bilinmiyor.</summary>
    private static int SacState()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Policy");
            return key?.GetValue("VerifiedAndReputablePolicyState") is int value ? value : -1;
        }
        catch
        {
            return -1;
        }
    }

    private static object RulePayload(TrustRule rule) => new
    {
        id = rule.Id,
        kind = rule.Kind,
        target = rule.Target,
        display = rule.Display,
        reason = rule.Reason,
        collection = rule.Collection
    };

    private async Task<object> TrustStatusAsync()
    {
        var status = await _trust.StatusAsync();
        var rules = await _trust.ListAsync();
        return new
        {
            sac = status?.Sac ?? -1,
            appIdService = status?.AppIdService,
            admin = status?.Admin ?? SentinelPaths.IsAdmin(),
            enforcement = status?.Enforcement ?? "off",
            ruleCount = rules.Count,
            statePath = status?.StatePath,
            policyPath = status?.PolicyPath,
            cmdlets = status?.AppLockerCmdl ?? false,
            rules = rules.Select(RulePayload).ToArray()
        };
    }

    private async Task<object> TrustListAsync() =>
        (await _trust.ListAsync()).Select(RulePayload).ToArray();

    private async Task<object> TrustAddAsync(JsonElement args)
    {
        var path = RequireString(args, "path");
        var kind = OptionalString(args, "kind") ?? "auto";
        var reason = OptionalString(args, "reason") ?? string.Empty;

        var rule = await _trust.AddAsync(path, kind, reason);
        var status = await _trust.StatusAsync();
        return new
        {
            rule = rule is null ? null : RulePayload(rule),
            enforcement = status?.Enforcement ?? "off",
            ruleCount = status?.RuleCount ?? 0
        };
    }

    private async Task<object> TrustRemoveAsync(JsonElement args)
    {
        var id = RequireString(args, "id");
        var removed = await _trust.RemoveAsync(id);
        return new { removed };
    }

    private async Task<object> TrustModeAsync(JsonElement args)
    {
        var raw = RequireString(args, "mode").ToLowerInvariant();
        if (raw is not ("off" or "audit" or "enforce"))
            throw new ArgumentException($"Geçersiz mod: {raw}");

        try
        {
            await _trust.ApplyModeAsync(raw);
            return new { mode = raw, applied = true, needsAdmin = false };
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("yonetici", StringComparison.OrdinalIgnoreCase))
        {
            return new { mode = raw, applied = false, needsAdmin = true };
        }
    }

    private object TrustApplyElevated() => new { applied = _trust.ApplyElevated() };

    private static object TrustBrowse(JsonElement args)
    {
        var kind = OptionalString(args, "kind") ?? "folder";
        return new { path = BrowsePath(kind == "file") };
    }

    /// <summary>Klasör/dosya seçiciyi arayüz iş parçacığında açar.</summary>
    private static string? BrowsePath(bool file)
    {
        var form = Application.OpenForms.Cast<Form>().FirstOrDefault();
        if (form is null) return null;

        string? result = null;
        void Show()
        {
            if (file)
            {
                using var dialog = new OpenFileDialog
                {
                    Title = "Güvenilir dosyayı seç",
                    Filter = "Programlar|*.exe;*.dll;*.com;*.msi|Betikler|*.ps1;*.bat;*.cmd;*.vbs;*.js|Tüm dosyalar|*.*"
                };
                if (dialog.ShowDialog(form) == DialogResult.OK) result = dialog.FileName;
            }
            else
            {
                using var dialog = new FolderBrowserDialog
                {
                    Description = "Güvenilir klasörü seç",
                    UseDescriptionForTitle = true,
                    ShowNewFolderButton = false
                };
                if (dialog.ShowDialog(form) == DialogResult.OK) result = dialog.SelectedPath;
            }
        }

        if (form.InvokeRequired) form.Invoke((Action)Show);
        else Show();
        return result;
    }

    private object OpenFolder(JsonElement args)
    {
        var which = RequireString(args, "which");
        var path = which switch
        {
            "quarantine" => _paths.QuarantineDir,
            "reports" => _paths.Reports,
            "data" => _paths.Data,
            _ => throw new ArgumentException($"Bilinmeyen klasör: {which}")
        };
        Open(path);
        return new { opened = path };
    }

    private static void Open(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch { /* arayüz çökmemeli */ }
    }

    private static string RequireString(JsonElement args, string name)
    {
        var value = OptionalString(args, name);
        if (!string.IsNullOrWhiteSpace(value)) return value!;
        throw new ArgumentException($"'{name}' alanı gerekli.");
    }

    private static string? OptionalString(JsonElement args, string name)
    {
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty(name, out var value) &&
            value.ValueKind == JsonValueKind.String)
            return value.GetString();
        return null;
    }
}
