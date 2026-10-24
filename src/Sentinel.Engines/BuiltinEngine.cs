using Sentinel.Core;

namespace Sentinel.Engines;

public interface IScanEngine
{
    string Name { get; }
    Task<EngineResult> ScanFileAsync(string path, bool deep, CancellationToken ct);
}

public sealed class BuiltinEngine : IScanEngine
{
    public string Name => "builtin";

    // EICAR anti-malware test string, split so this source file is not itself flagged.
    private static readonly byte[] Eicar = BuildEicar();

    private static byte[] BuildEicar() =>
        System.Text.Encoding.ASCII.GetBytes(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    public Task<EngineResult> ScanFileAsync(string path, bool deep, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[64 * 1024];
            var read = fs.Read(buffer, 0, buffer.Length);
            return Task.FromResult(Scan(buffer.AsSpan(0, read), sw));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new EngineResult
            {
                Engine = Name, Available = false, Error = ex.Message, Duration = sw.Elapsed
            });
        }
    }

    public EngineResult ScanBytes(ReadOnlySpan<byte> data)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = Scan(data, sw);
        result.Engine = Name;
        return result;
    }

    private static EngineResult Scan(ReadOnlySpan<byte> data, System.Diagnostics.Stopwatch sw)
    {
        var infected = data.IndexOf(Eicar) >= 0;
        return new EngineResult
        {
            Engine = "builtin",
            Infected = infected,
            Signature = infected ? "Eicar-Test-Signature" : null,
            Duration = sw.Elapsed
        };
    }
}
