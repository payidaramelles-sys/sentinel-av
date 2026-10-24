using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Sentinel.Core;

namespace Sentinel.Engines;

public static class Heuristics
{
    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi", ".com", ".msi", ".mui"
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".bat", ".cmd", ".hta", ".jar"
    };

    private static readonly HashSet<string> MacroExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xltm"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".vsix", ".nupkg"
    };

    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".doc", ".xls", ".ppt", ".mp3", ".mp4", ".rtf"
    };

    private static readonly Regex DoubleExtension = new(
        @"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|mp[34]|avi|zip|rar|7z)\.[a-z0-9]{2,4}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<ScanFinding> Inspect(string path, bool deep, out string? motwZone)
    {
        var findings = new List<ScanFinding>();
        motwZone = MotwZone(path);
        var name = Path.GetFileName(path);
        var ext = Path.GetExtension(path);

        if (DoubleExtension.IsMatch(name))
            findings.Add(F("double-extension", "warning", name));

        byte[] head;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var len = (int)Math.Min(fs.Length, 2 * 1024 * 1024);
            head = new byte[len];
            var total = 0;
            while (total < len)
            {
                var read = fs.Read(head, total, len - total);
                if (read <= 0) break;
                total += read;
            }
            if (total < len) Array.Resize(ref head, total);
        }
        catch
        {
            return findings;
        }

        var isPe = head.Length >= 2 && head[0] == 'M' && head[1] == 'Z';
        var hasPeHeader = IndexOf(head, "PE\0\0"u8) > 0;
        var looksScript = head.Length > 2 && (head[0] == '#' && head[1] == '!' ||
            Encoding.ASCII.GetString(head, 0, Math.Min(head.Length, 64)).Contains("<script", StringComparison.OrdinalIgnoreCase));

        if (isPe && !PeExtensions.Contains(ext))
            findings.Add(F("magic-mismatch", "warning", $"PE inside {ext}"));
        else if (!isPe && PeExtensions.Contains(ext) && ext is not ".msi" and not ".mui")
            findings.Add(F("extension-mismatch", "warning", $"{ext} without MZ header"));

        if (!isPe && !hasPeHeader && IndexOf(head, "PE\0\0"u8) > 0)
            findings.Add(F("embedded-pe", "high", "PE header at non-zero offset"));

        if (hasPeHeader && ImageExtensions.Contains(ext))
            findings.Add(F("polyglot", "high", $"{ext} carries a PE payload"));

        if (ScriptExtensions.Contains(ext))
        {
            var text = Encoding.ASCII.GetString(head);
            if (text.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase))
                findings.Add(F("encoded-script", "high", "base64/encoded payload"));
            if (text.Contains("DownloadString", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("Invoke-WebRequest", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("WinHttp.WinHttpRequest", StringComparison.OrdinalIgnoreCase))
                findings.Add(F("remote-fetch", "warning", "downloads and runs remote content"));
        }

        if (MacroExtensions.Contains(ext))
            findings.Add(F("macro-document", "warning", "macro-enabled document"));

        if (isPe && PeExtensions.Contains(ext) && !IsSigned(path))
            findings.Add(F("unsigned-pe", "info", "no Authenticode signature"));

        var inTemp = path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                     path.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase);
        if (isPe && inTemp)
            findings.Add(F("temp-executable", "warning", "executable stored in Temp"));

        if (motwZone is "3" or "4")
            findings.Add(F("downloaded", "info", $"mark-of-the-web zone {motwZone}"));

        if (deep && ArchiveExtensions.Contains(ext) && ZipArchiveSafe(path) is { } zip)
            findings.AddRange(zip);

        return findings;

        static ScanFinding F(string n, string sev, string? detail) =>
            new() { Engine = "heuristics", Name = n, Severity = sev, Detail = detail };
    }

    private static List<ScanFinding>? ZipArchiveSafe(string path)
    {
        var findings = new List<ScanFinding>();
        try
        {
            using var zip = ZipFile.OpenRead(path);
            var exeEntries = 0;
            var encrypted = 0;
            foreach (var entry in zip.Entries.Take(2000))
            {
                var e = Path.GetExtension(entry.FullName);
                if (PeExtensions.Contains(e) || ScriptExtensions.Contains(e)) exeEntries++;
                if (entry.Length > 0 && entry.CompressedLength > 0)
                {
                    try
                    {
                        using var probe = entry.Open();
                        probe.ReadByte();
                    }
                    catch (InvalidDataException)
                    {
                        encrypted++;
                    }
                    catch
                    {
                        // unreadable entry, ignore
                    }
                }
            }
            if (exeEntries > 0)
                findings.Add(new ScanFinding
                {
                    Engine = "heuristics", Name = "archive-with-executables", Severity = "warning",
                    Detail = $"{exeEntries} executable/script entries"
                });
            if (encrypted > 0)
                findings.Add(new ScanFinding
                {
                    Engine = "heuristics", Name = "encrypted-archive", Severity = "high",
                    Detail = $"{encrypted} encrypted entries (cannot be scanned)"
                });
        }
        catch
        {
            return null;
        }
        return findings;
    }

    public static string? MotwZone(string path)
    {
        try
        {
            var ads = path + ":Zone.Identifier";
            string text;
            try
            {
                using var fs = new FileStream(ads, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(fs);
                text = reader.ReadToEnd();
            }
            catch
            {
                return null;
            }
            var idx = text.IndexOf("ZoneId=", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;
            var zone = text[(idx + 7)..].Trim().Split('\n', '\r')[0].Trim();
            return zone;
        }
        catch
        {
            return null;
        }
    }

    public static bool IsSigned(string path)
    {
        try
        {
            _ = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (haystack.Length <= 1) return -1;
        var idx = haystack[1..].IndexOf(needle);
        return idx < 0 ? -1 : idx + 1;
    }
}
