using System.Reflection;
using System.Text;
using System.Text.Json;

namespace Sentinel.Engines;

public sealed record TrustStatus(
    int Sac,
    string AppIdService,
    bool Admin,
    string Enforcement,
    int RuleCount,
    string StatePath,
    string PolicyPath,
    bool AppLockerCmdl);

public sealed record TrustRule(
    string Id,
    string Kind,
    string Target,
    string Display,
    string? Reason,
    string? Created,
    string? Collection);

/// <summary>
/// AppLocker tabanlı güven listesi. Smart App Control'ün aksine kural yazılabilir:
/// yayıncı (sertifika), hash veya klasör yolu bazında izin.
/// Ağır iş PowerShell betiğinde; burası yalnızca köprü.
/// </summary>
public sealed class AppLockerTrust
{
    private readonly string _root;
    private readonly string _scriptPath;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public AppLockerTrust(string root)
    {
        _root = root;
        _scriptPath = Path.Combine(root, "applocker", "trust.ps1");
    }

    public string ScriptPath => _scriptPath;

    private string EnsureScript()
    {
        var dir = Path.GetDirectoryName(_scriptPath)!;
        Directory.CreateDirectory(dir);
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("applocker-trust.ps1", StringComparison.OrdinalIgnoreCase));
        if (name is null) throw new InvalidOperationException("applocker-trust.ps1 gömülü kaynağı bulunamadı.");
        using var stream = asm.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var text = reader.ReadToEnd();
        // Her çalıştırmada yazmak yerine içerik değiştiyse yaz.
        if (!File.Exists(_scriptPath) || File.ReadAllText(_scriptPath) != text)
            File.WriteAllText(_scriptPath, text, new UTF8Encoding(true));
        return _scriptPath;
    }

    private async Task<string> RunAsync(string command, IEnumerable<string> extra, TimeSpan timeout,
        CancellationToken ct)
    {
        var script = EnsureScript();
        var powershell = ProcessRunner.Which("powershell.exe") ?? "powershell.exe";
        var args = new List<string>
        {
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", script, command, "-Root", _root, "-Json"
        };
        args.AddRange(extra);

        var output = await ProcessRunner.RunAsync(powershell, args, timeout, ct);
        if (output.TimedOut)
            throw new TimeoutException("AppLocker komutu zaman aşımına uğradı.");

        var stdout = output.StdOut.Trim();
        if (output.ExitCode != 0)
        {
            var message = string.IsNullOrWhiteSpace(output.StdErr) ? stdout : output.StdErr.Trim();
            throw new InvalidOperationException(message.Length > 600 ? message[..600] : message);
        }
        return stdout;
    }

    public async Task<TrustStatus?> StatusAsync(CancellationToken ct = default)
    {
        var json = await RunAsync("status", Array.Empty<string>(), TimeSpan.FromSeconds(40), ct);
        return string.IsNullOrWhiteSpace(json) ? null : JsonSerializer.Deserialize<TrustStatus>(json, JsonOptions);
    }

    public async Task<IReadOnlyList<TrustRule>> ListAsync(CancellationToken ct = default)
    {
        var json = await RunAsync("list", Array.Empty<string>(), TimeSpan.FromSeconds(40), ct);
        return ParseList(json);
    }

    public static IReadOnlyList<TrustRule> ParseList(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<TrustRule>();
        using var doc = JsonDocument.Parse(json);
        var list = new List<TrustRule>();
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in doc.RootElement.EnumerateArray())
            {
                var rule = item.Deserialize<TrustRule>(JsonOptions);
                if (rule is not null) list.Add(rule);
            }
        }
        else if (doc.RootElement.ValueKind == JsonValueKind.Object)
        {
            var rule = doc.RootElement.Deserialize<TrustRule>(JsonOptions);
            if (rule is not null) list.Add(rule);
        }
        return list;
    }

    public async Task<TrustRule?> AddAsync(string path, string kind = "auto", string reason = "",
        CancellationToken ct = default)
    {
        var json = await RunAsync("add",
            new[] { "-Path", path, "-Kind", kind, "-Reason", reason },
            TimeSpan.FromSeconds(120), ct);
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("rule", out var ruleElement)) return null;
        return ruleElement.Deserialize<TrustRule>(JsonOptions);
    }

    public async Task<bool> RemoveAsync(string id, CancellationToken ct = default)
    {
        var json = await RunAsync("remove", new[] { "-Id", id }, TimeSpan.FromSeconds(60), ct);
        return json.Contains("\"removed\":true", StringComparison.OrdinalIgnoreCase);
    }

    public async Task ApplyModeAsync(string mode, CancellationToken ct = default)
    {
        await RunAsync("mode", new[] { "-Value", mode }, TimeSpan.FromSeconds(90), ct);
    }

    public async Task ApplyAsync(CancellationToken ct = default)
    {
        await RunAsync("apply", Array.Empty<string>(), TimeSpan.FromSeconds(120), ct);
    }

    public async Task ResetAsync(CancellationToken ct = default)
    {
        await RunAsync("reset", Array.Empty<string>(), TimeSpan.FromSeconds(90), ct);
    }

    public async Task<string> DescribeAsync(string path, string kind = "auto", CancellationToken ct = default)
    {
        var json = await RunAsync("describe", new[] { "-Path", path, "-Kind", kind },
            TimeSpan.FromSeconds(60), ct);
        return json;
    }

    /// <summary>
    /// Politikayı yönetici onayıyla uygular (UAC istemi). Kullanıcı reddederse false döner.
    /// </summary>
    public bool ApplyElevated()
    {
        var script = EnsureScript();
        var powershell = ProcessRunner.Which("powershell.exe") ?? "powershell.exe";
        var info = new System.Diagnostics.ProcessStartInfo
        {
            FileName = powershell,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
        };
        foreach (var arg in new[]
                 {
                     "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
                     "apply", "-Root", _root
                 })
            info.ArgumentList.Add(arg);

        try
        {
            using var process = System.Diagnostics.Process.Start(info);
            process?.WaitForExit(120_000);
            return process is null || process.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false; // UAC reddedildi
        }
    }
}
