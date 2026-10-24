using System.Globalization;

namespace Sentinel.Core;

public sealed class UsageStats
{
    private readonly Journal _journal;
    private readonly SentinelPaths _paths;
    private DateTime _lastSample = DateTime.Now;

    public UsageStats(Journal journal, SentinelPaths paths)
    {
        _journal = journal;
        _paths = paths;
    }

    public void Sample()
    {
        var now = DateTime.Now;
        var elapsed = (int)Math.Clamp((now - _lastSample).TotalSeconds, 0, 300);
        _lastSample = now;
        if (elapsed <= 0) return;

        var idle = Win32.IdleTime();
        var active = idle.TotalSeconds < 60 ? elapsed : 0;
        if (active == 0) return;
        var key = now.ToString("yyyy-MM-ddTHH", CultureInfo.InvariantCulture);
        _journal.RecordUsage(key, active);
    }

    /// <summary>Least busy contiguous window of the day, learned from usage samples.</summary>
    public (int StartHour, int EndHour) QuietWindow(int hours)
    {
        hours = Math.Clamp(hours, 1, 12);
        var activity = _journal.HourActivity();
        var hasData = activity.Values.Any(v => v > 0);
        if (!hasData) return (3, 3 + hours);

        var bestStart = 0;
        var bestScore = double.MaxValue;
        for (var start = 0; start < 24; start++)
        {
            double score = 0;
            for (var i = 0; i < hours; i++) score += activity[(start + i) % 24];
            if (score < bestScore)
            {
                bestScore = score;
                bestStart = start;
            }
        }

        return (bestStart, (bestStart + hours) % 24);
    }

    /// <summary>True when the sample set is too thin to be trusted.</summary>
    public bool IsColdStart()
    {
        var activity = _journal.HourActivity();
        return activity.Values.All(v => v <= 0);
    }
}
