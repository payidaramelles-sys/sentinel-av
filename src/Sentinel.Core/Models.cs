namespace Sentinel.Core;

public enum Verdict
{
    Unknown = 0,
    Clean = 1,
    Suspicious = 2,
    Malicious = 3
}

public enum ResponseMode
{
    DryRun = 0,
    Notify = 1,
    Auto = 2
}

public sealed class ScanFinding
{
    public string Engine { get; set; } = "";
    public string Name { get; set; } = "";
    public string Severity { get; set; } = "info";
    public string? Detail { get; set; }

    public override string ToString() => $"{Engine}:{Name}";
}

public sealed class ScanResult
{
    public string Path { get; set; } = "";
    public string? Sha256 { get; set; }
    public long Size { get; set; }
    public Verdict Verdict { get; set; } = Verdict.Unknown;
    public int Score { get; set; }
    public List<ScanFinding> Findings { get; set; } = new();
    public DateTimeOffset ScannedAt { get; set; } = DateTimeOffset.Now;
    public bool FromCache { get; set; }
    public string? Error { get; set; }

    public bool IsInfected => Verdict == Verdict.Malicious;

    public string Summary
    {
        get
        {
            if (Verdict == Verdict.Unknown) return Error ?? "unknown";
            if (Findings.Count == 0) return Verdict.ToString().ToLowerInvariant();
            return $"{Verdict.ToString().ToLowerInvariant()} ({string.Join(", ", Findings.Select(f => f.Name).Distinct())})";
        }
    }
}

public sealed class EngineResult
{
    public string Engine { get; set; } = "";
    public bool Infected { get; set; }
    public bool Available { get; set; } = true;
    public string? Signature { get; set; }
    public string? Error { get; set; }
    public TimeSpan Duration { get; set; }
}

public sealed class LogEvent
{
    public DateTimeOffset Ts { get; set; } = DateTimeOffset.Now;
    public string Type { get; set; } = "info";
    public string Severity { get; set; } = "info";
    public string Message { get; set; } = "";
    public string? Path { get; set; }
    public string? Sha256 { get; set; }
    public int? Pid { get; set; }
    public string? Json { get; set; }
}

public sealed class QuarantineEntry
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public string DetectedBy { get; set; } = "";
    public Verdict Verdict { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RestoredAt { get; set; }
}

public sealed class AllowEntry
{
    public long Id { get; set; }
    public string Kind { get; set; } = "path"; // path | sha256
    public string Value { get; set; } = "";
    public string? Reason { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
}
