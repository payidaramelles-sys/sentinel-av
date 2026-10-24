using System.Diagnostics;
using Sentinel.Core;
using Sentinel.Engines;

namespace Sentinel.Tray;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        var context = new TrayContext();
        var startInTray = args.Any(a => a.Equals("--tray", StringComparison.OrdinalIgnoreCase));
        if (!startInTray) context.OpenMainWindow();
        Application.Run(context);
    }
}

internal sealed class TrayContext : ApplicationContext
{
    private readonly NotifyIcon _icon;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly SentinelPaths _paths;
    private readonly SentinelConfig _config;
    private readonly Journal _journal;
    private readonly ScanPipeline _pipeline;
    private readonly QuarantineService _quarantine;
    private MainForm? _window;
    private bool _busy;

    public TrayContext()
    {
        _paths = SentinelPaths.Resolve();
        _config = SentinelConfig.Load(_paths.ConfigPath);
        _journal = new Journal(_paths);
        _quarantine = new QuarantineService(_paths, _journal);
        _pipeline = new ScanPipeline(_paths, _config, _journal, _quarantine);

        var menu = new ContextMenuStrip();
        menu.Items.Add("Pencereyi aç", null, (_, _) => OpenMainWindow());
        menu.Items.Add("Durum", null, (_, _) => ShowStatus());
        menu.Items.Add("Şimdi tara (Downloads)", null, async (_, _) => await ScanDownloadsAsync());
        menu.Items.Add("Rapor aç", null, (_, _) => OpenReport());
        menu.Items.Add("Karantina klasörü", null, (_, _) => OpenFolder(_paths.QuarantineDir));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Çıkış", null, (_, _) => ExitThread());

        _icon = new NotifyIcon
        {
            Icon = LoadAppIcon(),
            Visible = true,
            Text = "Sentinel",
            ContextMenuStrip = menu
        };
        _icon.DoubleClick += (_, _) => OpenMainWindow();
        _icon.BalloonTipClicked += (_, _) => OpenReport();

        _timer = new System.Windows.Forms.Timer { Interval = 60_000 };
        _timer.Tick += (_, _) => UpdateTooltip();
        _timer.Start();

        UpdateTooltip();
        _icon.ShowBalloonTip(4000, "Sentinel çalışıyor",
            $"İzleme: {string.Join(", ", _config.WatchPaths.Select(SentinelPaths.Expand))}", ToolTipIcon.Info);
    }

    internal void OpenMainWindow()
    {
        if (_window is { IsDisposed: false })
        {
            if (_window.WindowState == FormWindowState.Minimized)
                _window.WindowState = FormWindowState.Normal;
            _window.Show();
            _window.BringToFront();
            _window.Activate();
            return;
        }

        _window = new MainForm(_paths, _config, _journal, _quarantine, _pipeline);
        _window.FormClosed += (_, _) => _window = null;
        _window.Show();
    }

    private void UpdateTooltip()
    {
        try
        {
            var c = _journal.Counters();
            var text = $"Sentinel · {c.Malicious} kötü · {c.Suspicious} şüpheli";
            _icon.Text = text.Length > 63 ? text[..63] : text;
        }
        catch
        {
            // tray must never crash
        }
    }

    private void ShowStatus()
    {
        var c = _journal.Counters();
        var q = _journal.ListQuarantine().Count(x => x.RestoredAt is null);
        var (start, end) = new UsageStats(_journal, _paths).QuietWindow(_config.Schedule.QuietWindowHours);
        var msg = $"Taranan: {c.Total}\nKötü: {c.Malicious}\nŞüpheli: {c.Suspicious}\nKarantina: {q}\n" +
                  $"Sakin pencere: {start:00}:00–{end:00}:00\nYanıt modu: {_config.Response.Mode}";
        MessageBox.Show(msg, "Sentinel durumu", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private async Task ScanDownloadsAsync()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            _icon.ShowBalloonTip(2000, "Sentinel", "Tarama başladı…", ToolTipIcon.Info);
            var roots = _config.WeeklyRoots;
            var (scanned, bad, sus) = await _pipeline.ScanTreeAsync(roots, deep: false, since: null);
            _icon.ShowBalloonTip(5000, "Tarama bitti",
                $"{scanned} dosya · {bad} kötü · {sus} şüpheli", bad > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info);
            UpdateTooltip();
        }
        catch (Exception ex)
        {
            _icon.ShowBalloonTip(5000, "Tarama hatası", ex.Message, ToolTipIcon.Error);
        }
        finally
        {
            _busy = false;
        }
    }

    private void OpenReport()
    {
        try
        {
            var file = Sentinel.Watch.Reporter.Write(_paths, _journal);
            Process.Start(new ProcessStartInfo(file) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Rapor açılamadı", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static void OpenFolder(string path)
    {
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true }); }
        catch { }
    }

    private static Icon LoadAppIcon()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe) && File.Exists(exe))
            {
                var icon = Icon.ExtractAssociatedIcon(exe);
                if (icon is not null) return icon;
            }
        }
        catch
        {
            // simge okunamazsa varsayılana düş
        }
        return SystemIcons.Shield;
    }

    protected override void ExitThreadCore()
    {
        _timer.Stop();
        _window?.Close();
        _icon.Visible = false;
        _icon.Dispose();
        base.ExitThreadCore();
    }
}

