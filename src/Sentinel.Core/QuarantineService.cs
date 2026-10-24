using System.Security.Cryptography;

namespace Sentinel.Core;

public sealed class QuarantineService
{
    private readonly SentinelPaths _paths;
    private readonly Journal _journal;
    private readonly object _gate = new();

    public QuarantineService(SentinelPaths paths, Journal journal)
    {
        _paths = paths;
        _journal = journal;
    }

    private byte[] Key()
    {
        if (!File.Exists(_paths.QuarantineKeyPath))
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var wrapped = ProtectedData.Protect(key, null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(_paths.QuarantineKeyPath, wrapped);
            return key;
        }

        var stored = File.ReadAllBytes(_paths.QuarantineKeyPath);
        return ProtectedData.Unprotect(stored, null, DataProtectionScope.LocalMachine);
    }

    public QuarantineEntry Add(string sourcePath, string sha256, Verdict verdict, string detectedBy)
    {
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("Quarantine source not found", sourcePath);

        var size = new FileInfo(sourcePath).Length;
        var id = $"{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..8]}";
        var stored = Path.Combine(_paths.QuarantineDir, id + ".qtn");

        lock (_gate)
        {
            var plain = File.ReadAllBytes(sourcePath);
            var key = Key();
            var nonce = RandomNumberGenerator.GetBytes(12);
            var cipher = new byte[plain.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(key, 16))
                aes.Encrypt(nonce, plain, cipher, tag);

            using (var fs = new FileStream(stored, FileMode.CreateNew, FileAccess.Write))
            {
                fs.Write(nonce);
                fs.Write(tag);
                fs.Write(cipher);
            }

            File.Delete(sourcePath);
        }

        var entry = new QuarantineEntry
        {
            Id = id,
            OriginalPath = sourcePath,
            Sha256 = sha256,
            Size = size,
            DetectedBy = detectedBy,
            Verdict = verdict,
            CreatedAt = DateTimeOffset.Now
        };
        _journal.SaveQuarantine(entry);
        _journal.Log("quarantine", $"Quarantined {sourcePath} ({detectedBy})", "warning",
            sourcePath, sha256, data: new { entry.Id, entry.DetectedBy });
        return entry;
    }

    public string Restore(string id, string? destination = null)
    {
        var entry = _journal.GetQuarantine(id)
                    ?? throw new InvalidOperationException($"Quarantine entry not found: {id}");
        var stored = Path.Combine(_paths.QuarantineDir, id + ".qtn");
        if (!File.Exists(stored)) throw new FileNotFoundException("Quarantine blob missing", stored);

        var target = destination ?? entry.OriginalPath;
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);

        lock (_gate)
        {
            var blob = File.ReadAllBytes(stored);
            var nonce = blob.AsSpan(0, 12);
            var tag = blob.AsSpan(12, 16);
            var cipher = blob.AsSpan(28);
            var plain = new byte[cipher.Length];
            using (var aes = new AesGcm(Key(), 16))
                aes.Decrypt(nonce, cipher, tag, plain);
            File.WriteAllBytes(target, plain);
            File.Delete(stored);
        }

        _journal.MarkQuarantineRestored(id);
        _journal.Log("quarantine", $"Restored {target}", "info", target, entry.Sha256, data: new { id });
        return target;
    }

    public void Delete(string id)
    {
        var stored = Path.Combine(_paths.QuarantineDir, id + ".qtn");
        if (File.Exists(stored)) File.Delete(stored);
        _journal.DeleteQuarantine(id);
        _journal.Log("quarantine", $"Deleted quarantine entry {id}", "info");
    }
}
