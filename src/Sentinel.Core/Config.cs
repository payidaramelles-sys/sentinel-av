using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core;

public sealed class SentinelConfig
{
    public List<string> WatchPaths { get; set; } = new()
    {
        "%USERPROFILE%\\Downloads",
        "%TEMP%"
    };

    public List<string> WeeklyRoots { get; set; } = new()
    {
        "%USERPROFILE%\\Downloads",
        "%USERPROFILE%\\Desktop",
        "%USERPROFILE%\\Documents",
        "%TEMP%"
    };

    public ScanOptions Scan { get; set; } = new();
    public EngineOptions Engines { get; set; } = new();
    public ResponseOptions Response { get; set; } = new();
    public ScheduleOptions Schedule { get; set; } = new();
    public JournalOptions Journal { get; set; } = new();
    public BehaviorOptions Behavior { get; set; } = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static SentinelConfig Load(string path)
    {
        if (!File.Exists(path)) return new SentinelConfig();
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<SentinelConfig>(json, JsonOptions) ?? new SentinelConfig();
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOptions));
    }
}

public sealed class ScanOptions
{
    public int MaxFileSizeMb { get; set; } = 256;
    public int MaxHashSizeMb { get; set; } = 1024;
    public bool DeepWeekly { get; set; } = true;
    public bool ScanArchives { get; set; } = true;
    public bool CopyOnWrite { get; set; } = true;
}

public sealed class EngineOptions
{
    public bool Builtin { get; set; } = true;
    public bool Defender { get; set; } = true;
    public YaraOptions YaraX { get; set; } = new();
    public ClamAvOptions ClamAv { get; set; } = new();
}

public sealed class YaraOptions
{
    public bool Enabled { get; set; } = true;
    public string? Binary { get; set; }          // null => search PATH
    public string? RulesDir { get; set; }        // null => <root>/rules/yara
    public int TimeoutSeconds { get; set; } = 30;
}

public sealed class ClamAvOptions
{
    public bool Enabled { get; set; } = false;
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 3310;
    public string? ClamScanPath { get; set; }
    public bool DeepOnly { get; set; } = true;
}

public sealed class ResponseOptions
{
    public ResponseMode Mode { get; set; } = ResponseMode.DryRun;
    public bool QuarantineMalicious { get; set; } = true;
    public bool QuarantineSuspicious { get; set; } = false;
    public int SuspiciousThreshold { get; set; } = 40;
    public int MaliciousThreshold { get; set; } = 80;
}

public sealed class ScheduleOptions
{
    public bool WeeklyEnabled { get; set; } = true;
    public int QuietWindowHours { get; set; } = 2;
    public int MinIdleMinutes { get; set; } = 5;
    public int IntervalDays { get; set; } = 7;
}

public sealed class JournalOptions
{
    public int RetentionDays { get; set; } = 30;
}

public sealed class BehaviorOptions
{
    public bool Enabled { get; set; } = true;
    public int PollSeconds { get; set; } = 3;
    public bool KillMalicious { get; set; } = true;
}
