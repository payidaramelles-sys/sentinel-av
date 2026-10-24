using System.Globalization;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Watch;

public static class Reporter
{
    public static string Write(SentinelPaths paths, Journal journal, int days = 7)
    {
        var events = journal.RecentEvents(1000);
        var counters = journal.Counters();
        var quarantine = journal.ListQuarantine();
        var (start, end) = new UsageStats(journal, paths).QuietWindow(2);

        var sb = new StringBuilder();
        sb.Append("""
            <!doctype html><html lang="tr"><head><meta charset="utf-8">
            <title>Sentinel raporu</title>
            <style>
              :root { color-scheme: dark; }
              body { background:#0f1115; color:#e6e8ee; font:15px/1.55 ui-sans-serif,system-ui,sans-serif; margin:0; padding:32px; }
              h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:16px; margin:28px 0 8px; }
              .muted { color:#98a0b3; font-size:13px; }
              .cards { display:flex; gap:12px; flex-wrap:wrap; margin-top:18px; }
              .card { background:#171a21; border:1px solid #252a35; border-radius:10px; padding:14px 18px; min-width:130px; }
              .num { font-size:26px; font-variant-numeric:tabular-nums; }
              table { width:100%; border-collapse:collapse; font-size:13px; }
              th,td { text-align:left; padding:7px 10px; border-bottom:1px solid #252a35; vertical-align:top; }
              th { color:#98a0b3; font-weight:500; }
              code { font-family:ui-monospace,monospace; font-size:12px; color:#c8d0e0; word-break:break-all; }
              .critical { color:#ff6b6b; } .warning { color:#ffc46b; } .info { color:#7ec8a9; } .error { color:#ff6b6b; }
            </style></head><body>
            """);
        sb.Append($"<h1>Sentinel raporu</h1><div class=\"muted\">Oluşturuldu: {DateTime.Now:yyyy-MM-dd HH:mm} · son {days} gün · öğrenilen sakin pencere {start:00}:00–{end:00}:00</div>");
        sb.Append($"""
            <div class="cards">
              <div class="card"><div class="num">{counters.Total}</div><div class="muted">taranan dosya</div></div>
              <div class="card"><div class="num critical">{counters.Malicious}</div><div class="muted">kötü</div></div>
              <div class="card"><div class="num warning">{counters.Suspicious}</div><div class="muted">şüpheli</div></div>
              <div class="card"><div class="num">{quarantine.Count(q => q.RestoredAt is null)}</div><div class="muted">karantinada</div></div>
            </div>
            """);
        sb.Append("<h2>Olaylar</h2><table><tr><th>Zaman</th><th>Tip</th><th>Önem</th><th>Mesaj</th><th>Yol</th></tr>");
        foreach (var e in events)
        {
            sb.Append("<tr>")
              .Append($"<td>{e.Ts.LocalDateTime.ToString("MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}</td>")
              .Append($"<td>{Esc(e.Type)}</td>")
              .Append($"<td class=\"{Esc(e.Severity)}\">{Esc(e.Severity)}</td>")
              .Append($"<td>{Esc(e.Message)}</td>")
              .Append($"<td><code>{Esc(e.Path ?? "")}</code></td>")
              .Append("</tr>");
        }
        sb.Append("</table>");

        sb.Append("<h2>Karantina</h2><table><tr><th>ID</th><th>Özgün yol</th><th>SHA-256</th><th>Tespit</th><th>Tarih</th></tr>");
        foreach (var q in quarantine)
        {
            sb.Append("<tr>")
              .Append($"<td><code>{Esc(q.Id)}</code></td>")
              .Append($"<td><code>{Esc(q.OriginalPath)}</code></td>")
              .Append($"<td><code>{Esc(q.Sha256[..16])}…</code></td>")
              .Append($"<td>{Esc(q.DetectedBy)}</td>")
              .Append($"<td>{q.CreatedAt.LocalDateTime:yyyy-MM-dd HH:mm}</td>")
              .Append("</tr>");
        }
        sb.Append("</table></body></html>");

        Directory.CreateDirectory(paths.Reports);
        var file = Path.Combine(paths.Reports, $"report-{DateTime.Now:yyyyMMdd-HHmmss}.html");
        File.WriteAllText(file, sb.ToString(), Encoding.UTF8);
        return file;
    }

    private static string Esc(string value) => value
        .Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
