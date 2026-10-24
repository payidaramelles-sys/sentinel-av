using System.Diagnostics;
using System.Text.RegularExpressions;
using Sentinel.Core;

namespace Sentinel.Engines;

public sealed class DefenderEngine : IScanEngine
{
    public string Name => "defender";
    private readonly string? _mpCmdRun;

    public DefenderEngine()
    {
        _mpCmdRun = Locate();
    }

    public static string? Locate()
    {
        var direct = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(direct)) return direct;

        var platform = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        if (!Directory.Exists(platform)) return null;

        return Directory.EnumerateDirectories(platform)
            .Select(d => new { Dir = d, Exe = Path.Combine(d, "MpCmdRun.exe") })
            .Where(x => File.Exists(x.Exe))
            .OrderByDescending(x => x.Dir, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.Exe)
            .FirstOrDefault();
    }

    public async Task<EngineResult> ScanFileAsync(string path, bool deep, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        if (_mpCmdRun is null)
            return new EngineResult { Engine = Name, Available = false, Error = "MpCmdRun.exe not found", Duration = sw.Elapsed };

        var args = new List<string>
        {
            "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation", "-Timeout", "120"
        };

        var output = await ProcessRunner.RunAsync(_mpCmdRun, args, TimeSpan.FromSeconds(150), ct);
        sw.Stop();

        if (output.TimedOut)
            return new EngineResult { Engine = Name, Available = false, Error = "timeout", Duration = sw.Elapsed };

        var text = output.Combined;
        var infected = output.ExitCode == 2 ||
                       Regex.IsMatch(text, @"\bThreat detected\b|\bfound\s+(?!no\b)\S*\s*threat", RegexOptions.IgnoreCase);

        string? signature = null;
        if (infected)
        {
            var m = Regex.Match(text, @"(?:Threat information|Threat)\s*:?\s*(.+)", RegexOptions.IgnoreCase);
            signature = m.Success ? m.Groups[1].Value.Trim().Split('\n')[0].Trim() : "Defender detection";
        }

        return new EngineResult
        {
            Engine = Name,
            Infected = infected,
            Signature = signature,
            Available = output.ExitCode is 0 or 2,
            Error = output.ExitCode is 0 or 2 ? null : text.Split('\n')[0].Trim(),
            Duration = sw.Elapsed
        };
    }
}
