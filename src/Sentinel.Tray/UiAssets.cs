using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Tray;

/// <summary>
/// UI dosyaları assembly içine gömülüdür; çalışma anında sürüm damgalı bir klasöre açılır.
/// Böylece tek dosya (single-file) yayında da arayüz yanında taşınmak zorunda kalmaz.
/// </summary>
internal static class UiAssets
{
    private const string Prefix = "Sentinel.Tray.ui.";

    public static string EnsureExtracted()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var names = assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(Prefix, StringComparison.Ordinal))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        // Damga içerikten üretilir: dosya değişince yeni klasöre açılır, eski sürüm kullanılmaz.
        using var fingerprint = SHA256.Create();
        foreach (var name in names)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name);
            fingerprint.TransformBlock(nameBytes, 0, nameBytes.Length, null, 0);
            using var resource = assembly.GetManifestResourceStream(name)!;
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = resource.Read(buffer, 0, buffer.Length)) > 0)
                fingerprint.TransformBlock(buffer, 0, read, null, 0);
        }
        fingerprint.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        var stamp = Convert.ToHexString(fingerprint.Hash!).ToLowerInvariant()[..12];

        var dir = Path.Combine(Path.GetTempPath(), "sentinel-ui", stamp);
        Directory.CreateDirectory(dir);

        foreach (var name in names)
        {
            var fixedTarget = FixExtension(dir, name);
            Directory.CreateDirectory(Path.GetDirectoryName(fixedTarget)!);
            if (File.Exists(fixedTarget)) continue;

            using var source = assembly.GetManifestResourceStream(name)!;
            using var file = File.Create(fixedTarget);
            source.CopyTo(file);
        }

        return dir;
    }

    private static string FixExtension(string root, string resourceName)
    {
        var relative = resourceName[Prefix.Length..];
        var parts = relative.Split('.');
        var file = parts[^2] + "." + parts[^1];
        var folders = parts[..^2];
        return Path.Combine(new[] { root }.Concat(folders).Append(file).ToArray());
    }
}
