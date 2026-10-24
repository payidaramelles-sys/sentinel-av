using System.Diagnostics;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Sentinel.Core;
using Sentinel.Engines;

namespace Sentinel.Tray;

/// <summary>
/// Modern WebView2 kabuğu: arayüz HTML/CSS/JS, arka uç mevcut .NET motorları.
/// </summary>
internal sealed class MainForm : Form
{
    private readonly WebView2 _web = new() { Dock = DockStyle.Fill };
    private readonly UiBridge _bridge;
    private readonly string? _screenshotPath;

    public MainForm(SentinelPaths paths, SentinelConfig config, Journal journal,
        QuarantineService quarantine, ScanPipeline pipeline)
    {
        _bridge = new UiBridge(paths, config, journal, quarantine, pipeline, Push);
        _screenshotPath = ReadScreenshotPath();

        Text = "Sentinel";
        AutoScaleMode = AutoScaleMode.None;
        ClientSize = new Size(1280, 820);
        MinimumSize = new Size(1000, 640);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(10, 12, 15);
        Font = new Font("Segoe UI", 9f);

        _web.DefaultBackgroundColor = Color.FromArgb(10, 12, 15);
        Controls.Add(_web);

        Load += async (_, _) => await InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        try
        {
            var environment = await CreateEnvironmentAsync();
            await _web.EnsureCoreWebView2Async(environment);

            var core = _web.CoreWebView2;
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.AreDevToolsEnabled = true;
            core.Settings.IsZoomControlEnabled = false;
            if (core.Settings.IsSwipeNavigationEnabled) core.Settings.IsSwipeNavigationEnabled = false;

            core.SetVirtualHostNameToFolderMapping(
                "sentinel.ui", UiAssets.EnsureExtracted(), CoreWebView2HostResourceAccessKind.Allow);

            core.WebMessageReceived += OnWebMessage;
            core.NavigationCompleted += OnNavigationCompleted;

            var startPage = ReadArg("--page") ?? "overview";
            core.Navigate($"https://sentinel.ui/index.html#{startPage}");
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Arayüz başlatılamadı.\n\n" + ex.Message +
                "\n\nWebView2 Runtime kurulu mu? (Edge ile birlikte gelir)",
                "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Close();
        }
    }

    /// <summary>
    /// WebView2 varsayılan olarak user data klasörünü exe'nin yanında açar. Program Files
    /// yazılamadığı için kurulu sürümde E_ACCESSDENIED veriyordu; bu yüzden kullanıcıya
    /// yazılabilir bir klasör veriyoruz.
    /// </summary>
    private static async Task<CoreWebView2Environment> CreateEnvironmentAsync()
    {
        string[] candidates =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Sentinel", "WebView2"),
            Path.Combine(Path.GetTempPath(), "sentinel-webview")
        ];

        Exception? last = null;
        foreach (var folder in candidates)
        {
            try
            {
                Directory.CreateDirectory(folder);
                return await CoreWebView2Environment.CreateAsync(null, folder);
            }
            catch (Exception ex)
            {
                last = ex;
            }
        }

        throw last ?? new InvalidOperationException("WebView2 ortamı oluşturulamadı.");
    }

    private async void OnNavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (_screenshotPath is null) return;

        var smokeScan = Environment.GetCommandLineArgs()
            .Any(a => a.Equals("--smoke-scan", StringComparison.OrdinalIgnoreCase));

        await Task.Delay(smokeScan ? 1200 : 5000);

        if (smokeScan)
        {
            await _web.CoreWebView2.ExecuteScriptAsync("window.sentinel && window.sentinel.startScan(false)");
            await Task.Delay(14000);
        }

        try
        {
            await using var stream = File.Create(_screenshotPath);
            await _web.CoreWebView2.CapturePreviewAsync(
                CoreWebView2CapturePreviewImageFormat.Png, stream);
        }
        catch
        {
            // ekran görüntüsü yalnızca doğrulama içindir
        }
        finally
        {
            Application.Exit();
        }
    }

    private void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        var raw = e.WebMessageAsJson;

        _ = Task.Run(async () =>
        {
            long id = 0;
            try
            {
                using var document = JsonDocument.Parse(raw);
                var root = document.RootElement;
                if (root.TryGetProperty("id", out var idElement)) id = idElement.GetInt64();

                var command = root.TryGetProperty("cmd", out var cmdElement)
                    ? cmdElement.GetString() ?? string.Empty
                    : string.Empty;

                var args = root.TryGetProperty("args", out var argsElement)
                    ? argsElement
                    : default;

                var data = await _bridge.HandleAsync(command, args);
                Push(new { id, ok = true, data });
            }
            catch (Exception ex)
            {
                Push(new { id, ok = false, error = ex.Message });
            }
        });
    }

    private void Push(object message)
    {
        var json = UiBridge.Serialize(message);
        if (IsDisposed) return;

        if (InvokeRequired)
        {
            BeginInvoke(new Action(() => Send(json)));
            return;
        }

        Send(json);
    }

    private void Send(string json)
    {
        try
        {
            if (_web.CoreWebView2 is not null)
                _web.CoreWebView2.PostWebMessageAsJson(json);
        }
        catch
        {
            // pencere kapanırken yarış durumu
        }
    }

    private static string? ReadScreenshotPath() => ReadArg("--screenshot");

    private static string? ReadArg(string name)
    {
        var args = Environment.GetCommandLineArgs();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                return args[i + 1];
            if (args[i].StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
                return args[i][(name.Length + 1)..];
        }
        return null;
    }
}
