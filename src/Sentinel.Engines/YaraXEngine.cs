using System.Diagnostics;
using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Engines;

public sealed class YaraXEngine : IScanEngine
{
    public string Name => "yara";
    private readonly YaraOptions _options;
    private readonly SentinelPaths _paths;
    private readonly string? _binary;

    public YaraXEngine(YaraOptions options, SentinelPaths paths)
    {
        _options = options;
        _paths = paths;
        _binary = ResolveBinary();
    }

    private string? ResolveBinary()
    {
        if (!string.IsNullOrWhiteSpace(_options.Binary))
        {
            if (File.Exists(_options.Binary)) return _options.Binary;
            var found = ProcessRunner.Which(_options.Binary);
            if (found is not null) return found;
        }
        return ProcessRunner.Which("yr.exe") ?? ProcessRunner.Which("yr");
    }

    private string RulesDir => string.IsNullOrWhiteSpace(_options.RulesDir)
        ? _paths.YaraRulesDir
        : SentinelPaths.Expand(_options.RulesDir);

    public async Task<EngineResult> ScanFileAsync(string path, bool deep, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        if (!_options.Enabled || _binary is null)
            return new EngineResult { Engine = Name, Available = false, Error = "YARA-X (yr) not installed", Duration = sw.Elapsed };
        if (!Directory.Exists(RulesDir) || !Directory.EnumerateFiles(RulesDir, "*.yar", SearchOption.AllDirectories).Any()
            && !Directory.EnumerateFiles(RulesDir, "*.yara", SearchOption.AllDirectories).Any())
            return new EngineResult { Engine = Name, Available = false, Error = "no YARA rules", Duration = sw.Elapsed };

        var output = await ProcessRunner.RunAsync(_binary,
            new[] { "scan", "--output-format=ndjson", RulesDir, path },
            TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 5, 300)), ct);

        sw.Stop();
        if (output.TimedOut)
            return new EngineResult { Engine = Name, Available = false, Error = "timeout", Duration = sw.Elapsed };

        var matches = ParseMatches(output.StdOut);
        var infected = matches.Count > 0;

        return new EngineResult
        {
            Engine = Name,
            Infected = infected,
            Signature = infected ? string.Join(", ", matches.Distinct()) : null,
            Available = true,
            Error = output.ExitCode != 0 ? FirstLine(output.StdErr) : null,
            Duration = sw.Elapsed
        };
    }

    private static List<string> ParseMatches(string stdout)
    {
        var list = new List<string>();
        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith('{')) continue;
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                Walk(doc.RootElement, list);
            }
            catch
            {
                // ignore non-JSON lines
            }
        }
        return list;
    }

    private static void Walk(JsonElement el, List<string> list)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                {
                    if (p.Name.Equals("identifier", StringComparison.OrdinalIgnoreCase) &&
                        p.Value.ValueKind == JsonValueKind.String)
                        list.Add(p.Value.GetString()!);
                    else if (p.Name.Equals("rule", StringComparison.OrdinalIgnoreCase) &&
                             p.Value.ValueKind == JsonValueKind.String)
                        list.Add(p.Value.GetString()!);
                    else
                        Walk(p.Value, list);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray()) Walk(item, list);
                break;
        }
    }

    private static string FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "";
}
