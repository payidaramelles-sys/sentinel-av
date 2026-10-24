using System.Security.Cryptography;

namespace Sentinel.Core;

public static class HashUtil
{
    public static string Sha256File(string path, long maxBytes = long.MaxValue)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        var buffer = new byte[1 << 16];
        long total = 0;
        int read;
        while (total < maxBytes && (read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            var take = (int)Math.Min(read, maxBytes - total);
            sha.TransformBlock(buffer, 0, take, null, 0);
            total += take;
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
    }

    public static string Sha256Bytes(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
