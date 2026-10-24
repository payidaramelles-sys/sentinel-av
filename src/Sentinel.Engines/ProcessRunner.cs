using System.Diagnostics;
using System.Text;

namespace Sentinel.Engines;

public sealed record ProcessOutput(int ExitCode, string StdOut, string StdErr, bool TimedOut)
{
    public string Combined => (StdOut + "\n" + StdErr).Trim();
}

public static class ProcessRunner
{
    public static async Task<ProcessOutput> RunAsync(string fileName, IEnumerable<string> args,
        TimeSpan timeout, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        try
        {
            await proc.WaitForExitAsync(linked.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(true); } catch { }
            return new ProcessOutput(-1, stdout.ToString(), stderr.ToString(), true);
        }

        return new ProcessOutput(proc.ExitCode, stdout.ToString(), stderr.ToString(), false);
    }

    public static string? Which(string exe)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), exe);
                if (File.Exists(candidate)) return candidate;
            }
            catch
            {
                // ignore malformed PATH entries
            }
        }
        return null;
    }
}
