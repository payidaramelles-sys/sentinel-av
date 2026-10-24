using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Engines;

/// <summary>Talks to clamd over TCP (INSTREAM). The daemon stays off unless deep scanning runs.</summary>
public sealed class ClamAvEngine : IScanEngine
{
    public string Name => "clamav";
    private readonly ClamAvOptions _options;

    public ClamAvEngine(ClamAvOptions options) => _options = options;

    public async Task<EngineResult> ScanFileAsync(string path, bool deep, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        if (!_options.Enabled || (_options.DeepOnly && !deep))
            return new EngineResult { Engine = Name, Available = false, Error = "disabled", Duration = sw.Elapsed };

        try
        {
            using var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await client.ConnectAsync(_options.Host, _options.Port, timeout.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync("zINSTREAM\0"u8.ToArray(), ct);
            await using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                             FileShare.ReadWrite | FileShare.Delete, 1 << 16, true))
            {
                var buffer = new byte[1 << 16];
                int read;
                while ((read = await fs.ReadAsync(buffer, ct)) > 0)
                {
                    var len = new byte[4];
                    BinaryPrimitives.WriteInt32BigEndian(len, read);
                    await stream.WriteAsync(len, ct);
                    await stream.WriteAsync(buffer.AsMemory(0, read), ct);
                }
            }
            await stream.WriteAsync(new byte[4], ct);

            var response = await ReadUntilNull(stream, ct);
            sw.Stop();
            var infected = response.Contains("FOUND", StringComparison.OrdinalIgnoreCase);
            return new EngineResult
            {
                Engine = Name,
                Infected = infected,
                Signature = infected ? response.Split(':').Last().Replace("FOUND", "").Trim() : null,
                Available = true,
                Duration = sw.Elapsed
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new EngineResult
            {
                Engine = Name, Available = false,
                Error = "clamd unreachable: " + ex.Message, Duration = sw.Elapsed
            };
        }
    }

    private static async Task<string> ReadUntilNull(NetworkStream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buf = new byte[512];
        while (true)
        {
            var read = await stream.ReadAsync(buf, ct);
            if (read <= 0) break;
            var chunk = Encoding.UTF8.GetString(buf, 0, read);
            var end = chunk.IndexOf('\0');
            if (end >= 0)
            {
                sb.Append(chunk[..end]);
                break;
            }
            sb.Append(chunk);
        }
        return sb.ToString();
    }
}
