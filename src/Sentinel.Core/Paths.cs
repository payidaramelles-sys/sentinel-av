using System.Security.Principal;

namespace Sentinel.Core;

public sealed class SentinelPaths
{
    public string Root { get; }
    public string Data => Path.Combine(Root, "data");
    public string Logs => Path.Combine(Data, "logs");
    public string Reports => Path.Combine(Data, "reports");
    public string QuarantineDir => Path.Combine(Data, "quarantine");
    public string DbPath => Path.Combine(Data, "sentinel.db");
    public string ConfigPath => Path.Combine(Root, "sentinel.json");
    public string RulesDir => Path.Combine(Root, "rules");
    public string YaraRulesDir => Path.Combine(RulesDir, "yara");
    public string StatePath => Path.Combine(Data, "state.json");
    public string QuarantineKeyPath => Path.Combine(Data, "quarantine.key");

    private SentinelPaths(string root) => Root = root;

    public static SentinelPaths Resolve(string? home = null)
    {
        var machine = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
        var user = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel");

        string root;
        if (!string.IsNullOrWhiteSpace(home))
            root = home;
        else if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SENTINEL_HOME")))
            root = Environment.GetEnvironmentVariable("SENTINEL_HOME")!;
        else if (Directory.Exists(machine) && CanWrite(machine))
            root = machine;      // service-installed layout, shared with the tray and CLI
        else
            root = IsAdmin() ? machine : user;

        root = Expand(root);
        var p = new SentinelPaths(root);
        p.Ensure();
        return p;
    }

    private static bool CanWrite(string dir)
    {
        try
        {
            var probe = Path.Combine(dir, ".write-probe-" + Guid.NewGuid().ToString("N")[..6]);
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Ensure()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Data);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(Reports);
        Directory.CreateDirectory(QuarantineDir);
        Directory.CreateDirectory(YaraRulesDir);
    }

    public static bool IsAdmin()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static string Expand(string value) =>
        Environment.ExpandEnvironmentVariables(value)
            .Replace('/', Path.DirectorySeparatorChar);
}
