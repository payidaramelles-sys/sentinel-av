using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Watch;

namespace Sentinel.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        try
        {
            return Run(args).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"hata: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            Help();
            return 0;
        }

        var opts = Parse(args);
        var paths = SentinelPaths.Resolve(opts.Home);
        var config = SentinelConfig.Load(paths.ConfigPath);
        var journal = new Journal(paths);
        var quarantine = new QuarantineService(paths, journal);
        var pipeline = new ScanPipeline(paths, config, journal, quarantine);
        var command = opts.Positional.FirstOrDefault() ?? "help";

        switch (command)
        {
            case "init":
                return Init(paths);

            case "status":
                return Status(paths, config, journal, pipeline);

            case "scan":
            {
                var target = opts.Positional.Skip(1).FirstOrDefault()
                             ?? throw new ArgumentException("kullanım: sentinel scan <yol> [--deep] [--force] [--json]");
                var deep = opts.Has("deep");
                var force = opts.Has("force");

                if (Directory.Exists(target))
                {
                    var (scanned, bad, sus) = await pipeline.ScanTreeAsync(new[] { target }, deep, null, r =>
                        PrintResult(r, opts.Has("json")));
                    Console.WriteLine($"\n{scanned} dosya tarandı · {bad} kötü · {sus} şüpheli");
                    return bad > 0 ? 2 : 0;
                }

                var result = await pipeline.ScanAsync(target, deep, force);
                PrintResult(result, opts.Has("json"));
                pipeline.ApplyResponse(result);
                return result.Verdict == Verdict.Malicious ? 2 : 0;
            }

            case "watch":
            {
                var usage = new UsageStats(journal, paths);
                var runtime = new SentinelRuntime(paths, config, journal, pipeline, usage);
                using var cts = new CancellationTokenSource();
                Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
                Console.WriteLine($"izleniyor… (durdurmak için Ctrl+C) · {paths.Root}");
                await runtime.RunAsync(cts.Token);
                return 0;
            }

            case "report":
            {
                var file = Reporter.Write(paths, journal);
                Console.WriteLine(file);
                return 0;
            }

            case "quarantine":
                return QuarantineCommand(opts, journal, quarantine);

            case "allow":
                return AllowCommand(opts, journal, pipeline);

            case "config":
                Console.WriteLine(paths.ConfigPath);
                Console.WriteLine(JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
                return 0;

            case "quiet":
            {
                var usage = new UsageStats(journal, paths);
                var (start, end) = usage.QuietWindow(config.Schedule.QuietWindowHours);
                Console.WriteLine(usage.IsColdStart()
                    ? $"henüz veri yok, varsayılan pencere {start:00}:00-{end:00}:00"
                    : $"öğrenilen sakin pencere: {start:00}:00-{end:00}:00");
                return 0;
            }

            case "selftest":
                return SelfTest(paths, journal, quarantine);

            case "service":
                return ServiceCommand(opts);

            case "trust":
                return await TrustCommand(opts, paths);

            default:
                Console.Error.WriteLine($"bilinmeyen komut: {command}");
                Help();
                return 1;
        }
    }

    private static int Init(SentinelPaths paths)
    {
        if (!File.Exists(paths.ConfigPath))
        {
            var cfg = new SentinelConfig();
            cfg.Save(paths.ConfigPath);
            Console.WriteLine($"config oluşturuldu: {paths.ConfigPath}");
        }
        else
        {
            Console.WriteLine($"config zaten var: {paths.ConfigPath}");
        }

        if (!Directory.EnumerateFiles(paths.YaraRulesDir, "*.yar", SearchOption.AllDirectories).Any())
        {
            File.WriteAllText(Path.Combine(paths.YaraRulesDir, "sentinel.yar"), StarterRules);
            Console.WriteLine($"başlangıç YARA kuralları yazıldı: {paths.YaraRulesDir}");
        }

        Console.WriteLine($"veri klasörü: {paths.Data}");
        Console.WriteLine("sıradaki: sentinel selftest && sentinel watch");
        return 0;
    }

    private static int Status(SentinelPaths paths, SentinelConfig config, Journal journal, ScanPipeline pipeline)
    {
        var counters = journal.Counters();
        var usage = new UsageStats(journal, paths);
        var (start, end) = usage.QuietWindow(config.Schedule.QuietWindowHours);
        var lastWeekly = journal.GetMeta("last_weekly_scan");
        var defender = DefenderEngine.Locate();
        var yara = ProcessRunner.Which("yr.exe") ?? ProcessRunner.Which("yr");
        var clamd = config.Engines.ClamAv.Enabled ? "açık (yalnız derin tarama)" : "kapalı";

        Console.WriteLine($"""
            Sentinel
              kök             : {paths.Root}
              yönetici        : {(SentinelPaths.IsAdmin() ? "evet" : "hayır")}
              smart app ctrl  : {SacName()}
              imza sürümü     : {pipeline.SignatureVersion}
              motorlar        : builtin{(config.Engines.Defender ? ", defender" : "")}{(config.Engines.YaraX.Enabled ? ", yara" : "")}{(config.Engines.ClamAv.Enabled ? ", clamav" : "")}
              defender        : {(defender is null ? "bulunamadı" : defender)}
              yara-x          : {(yara is null ? "kurulu değil (opsiyonel)" : yara)}
              clamav          : {clamd}
              yanıt modu      : {config.Response.Mode}
              izlenen yollar  : {string.Join(" · ", config.WatchPaths.Select(SentinelPaths.Expand))}
              sakin pencere   : {start:00}:00-{end:00}:00{(usage.IsColdStart() ? " (veri yok, varsayılan)" : " (öğrenildi)")}
              son haftalık    : {(string.IsNullOrEmpty(lastWeekly) ? "hiç" : DateTimeOffset.Parse(lastWeekly).LocalDateTime.ToString("yyyy-MM-dd HH:mm"))}
              taranan dosya   : {counters.Total} (kötü {counters.Malicious}, şüpheli {counters.Suspicious}, temiz {counters.Clean})
              karantina       : {journal.ListQuarantine().Count(q => q.RestoredAt is null)}
            """);
        return 0;
    }

    private static void PrintResult(ScanResult r, bool json)
    {
        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(r, new JsonSerializerOptions
            {
                WriteIndented = false,
                Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
            }));
            return;
        }

        var tag = r.Verdict switch
        {
            Verdict.Malicious => "KÖTÜ",
            Verdict.Suspicious => "ŞÜPHELİ",
            Verdict.Clean => "temiz",
            _ => "bilinmiyor"
        };
        Console.WriteLine($"[{tag,-9}] {r.Score,3}  {r.Path}{(r.FromCache ? "  (önbellek)" : "")}");
        if (r.Error is not null) Console.WriteLine($"            not: {r.Error}");
        foreach (var f in r.Findings.Where(f => f.Severity is "warning" or "high" or "critical"))
            Console.WriteLine($"            - {f.Engine}/{f.Name}{(f.Detail is null ? "" : ": " + f.Detail)}");
    }

    private static int QuarantineCommand(Options opts, Journal journal, QuarantineService quarantine)
    {
        var sub = opts.Positional.Skip(1).FirstOrDefault() ?? "list";
        switch (sub)
        {
            case "list":
                var rows = journal.ListQuarantine();
                if (rows.Count == 0)
                {
                    Console.WriteLine("karantina boş");
                    return 0;
                }
                foreach (var q in rows)
                    Console.WriteLine($"{q.Id}  {q.Size,10}  {q.DetectedBy,-20}  {q.OriginalPath}");
                return 0;

            case "restore":
            {
                var id = opts.Positional.Skip(2).FirstOrDefault()
                         ?? throw new ArgumentException("kullanım: sentinel quarantine restore <id> [--to <yol>]");
                var target = quarantine.Restore(id, opts.Get("to"));
                Console.WriteLine($"geri yüklendi: {target}");
                return 0;
            }

            case "delete":
            {
                var id = opts.Positional.Skip(2).FirstOrDefault()
                         ?? throw new ArgumentException("kullanım: sentinel quarantine delete <id>");
                quarantine.Delete(id);
                Console.WriteLine($"silindi: {id}");
                return 0;
            }

            default:
                Console.Error.WriteLine("kullanım: sentinel quarantine list|restore|delete");
                return 1;
        }
    }

    private static int AllowCommand(Options opts, Journal journal, ScanPipeline pipeline)
    {
        var sub = opts.Positional.Skip(1).FirstOrDefault() ?? "list";
        switch (sub)
        {
            case "list":
                var rows = journal.ListAllow();
                if (rows.Count == 0) Console.WriteLine("allowlist boş");
                foreach (var a in rows) Console.WriteLine($"{a.Id}  {a.Kind,-6}  {a.Value}  {a.Reason}");
                return 0;

            case "add":
            {
                var value = opts.Positional.Skip(2).FirstOrDefault()
                            ?? throw new ArgumentException("kullanım: sentinel allow add <yol|sha256> [--reason ...] [--days N]");
                var isHash = value.Length == 64 && value.All(Uri.IsHexDigit);
                DateTimeOffset? expires = opts.Get("days") is { } d
                    ? DateTimeOffset.Now.AddDays(int.Parse(d, CultureInfo.InvariantCulture))
                    : null;
                journal.AddAllow(isHash ? "sha256" : "path", value, opts.Get("reason") ?? "manual", expires);
                journal.Log("allow", $"Allowlisted {value}", "info");
                Console.WriteLine($"eklendi: {value}");
                return 0;
            }

            case "remove":
            {
                var id = long.Parse(opts.Positional.Skip(2).FirstOrDefault()
                                    ?? throw new ArgumentException("kullanım: sentinel allow remove <id>"),
                    CultureInfo.InvariantCulture);
                Console.WriteLine(journal.RemoveAllow(id) ? "silindi" : "bulunamadı");
                return 0;
            }

            default:
                Console.Error.WriteLine("kullanım: sentinel allow list|add|remove");
                return 1;
        }
    }

    private static int SelfTest(SentinelPaths paths, Journal journal, QuarantineService quarantine)
    {
        var failures = 0;
        void Check(string name, bool ok)
        {
            Console.WriteLine($"  [{(ok ? "GEÇTİ" : "KALDI")}] {name}");
            if (!ok) failures++;
        }

        Console.WriteLine("Sentinel selftest");

        var builtin = new BuiltinEngine();
        var eicar = Encoding.ASCII.GetBytes(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        Check("EICAR imzası yakalanıyor", builtin.ScanBytes(eicar).Infected);
        Check("temiz içerik temiz kalıyor", !builtin.ScanBytes(Encoding.ASCII.GetBytes("hello sentinel")).Infected);

        var cfg = SentinelConfig.Load(paths.ConfigPath);
        var pipeline = new ScanPipeline(paths, cfg, journal, quarantine);
        Check("pipeline kuruldu", !string.IsNullOrEmpty(pipeline.SignatureVersion));

        var temp = Path.Combine(Path.GetTempPath(), "sentinel-selftest-" + Guid.NewGuid().ToString("N")[..8] + ".txt");
        File.WriteAllText(temp, "sentinel benign test " + DateTime.Now.Ticks);

        try
        {
            var benign = pipeline.ScanAsync(temp, force: true).GetAwaiter().GetResult();
            Check($"temiz dosya temiz sonuç verdi ({benign.Verdict})", benign.Verdict is Verdict.Clean or Verdict.Unknown);

            var q = quarantine.Add(temp, benign.Sha256 ?? "0", Verdict.Clean, "selftest");
            Check("karantinaya alma", !File.Exists(temp) && File.Exists(Path.Combine(paths.QuarantineDir, q.Id + ".qtn")));
            var restored = quarantine.Restore(q.Id);
            Check("karantinadan geri yükleme", File.Exists(restored) && File.ReadAllText(restored).Contains("benign"));
            quarantine.Delete(q.Id);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }

        Console.WriteLine(failures == 0 ? "sonuç: tüm testler geçti" : $"sonuç: {failures} test kaldı");
        return failures == 0 ? 0 : 1;
    }

    private static async Task<int> TrustCommand(Options opts, SentinelPaths paths)
    {
        var trust = new AppLockerTrust(paths.Root);
        var sub = opts.Positional.Skip(1).FirstOrDefault() ?? "status";

        switch (sub)
        {
            case "status":
            {
                var status = await trust.StatusAsync();
                if (status is null)
                {
                    Console.Error.WriteLine("AppLocker durumu okunamadı");
                    return 1;
                }

                if (opts.Has("json"))
                {
                    Console.WriteLine(JsonSerializer.Serialize(status, new JsonSerializerOptions { WriteIndented = false }));
                    return 0;
                }

                Console.WriteLine($"""
                    Sentinel güven listesi (AppLocker)
                      smart app control : {SacName()}
                      uygulama kimliği  : {status.AppIdService}
                      applocker cmdlet  : {(status.AppLockerCmdl ? "var" : "yok")}
                      mod               : {ModeName(status.Enforcement)}
                      kural             : {status.RuleCount}
                      durum dosyası     : {status.StatePath}
                      ilke dosyası      : {status.PolicyPath}
                      yönetici          : {(status.Admin ? "evet" : "hayır")}
                    """);
                if (status.Enforcement != "off" && !status.Admin)
                    Console.WriteLine("  not: etkin modu değiştirmek için yönetici gerekir");
                return 0;
            }

            case "list":
            {
                var rules = await trust.ListAsync();
                if (rules.Count == 0)
                {
                    Console.WriteLine("güven listesi boş");
                    return 0;
                }
                foreach (var r in rules)
                    Console.WriteLine($"{r.Id}  {r.Kind,-9}  {r.Collection,-6}  {r.Display}  {r.Reason}");
                return 0;
            }

            case "add":
            {
                var target = opts.Positional.Skip(2).FirstOrDefault()
                             ?? opts.Get("path")
                             ?? throw new ArgumentException("kullanım: sentinel trust add <yol> [--kind auto|publisher|hash|path]");
                var rule = await trust.AddAsync(target, opts.Get("kind") ?? "auto", opts.Get("reason") ?? "manual");
                if (rule is null)
                {
                    Console.Error.WriteLine("kural üretilemedi");
                    return 1;
                }
                Console.WriteLine($"eklendi: {rule.Id}  {rule.Kind}  {rule.Display}");
                var status = await trust.StatusAsync();
                if (status is { Enforcement: not "off" })
                    Console.WriteLine($"not: ilke yeniden uygulandı (mod {ModeName(status.Enforcement)})");
                else
                    Console.WriteLine("not: güven listesi henüz etkin değil (sentinel trust mode audit)");
                return 0;
            }

            case "remove":
            {
                var id = opts.Positional.Skip(2).FirstOrDefault() ?? opts.Get("id")
                         ?? throw new ArgumentException("kullanım: sentinel trust remove <id>");
                Console.WriteLine(await trust.RemoveAsync(id) ? "silindi" : "bulunamadı");
                return 0;
            }

            case "mode":
            {
                var value = (opts.Positional.Skip(2).FirstOrDefault() ?? opts.Get("mode") ?? "").ToLowerInvariant();
                if (value is not ("off" or "audit" or "enforce"))
                    throw new ArgumentException("kullanım: sentinel trust mode off|audit|enforce");
                await trust.ApplyModeAsync(value);
                Console.WriteLine($"mod: {ModeName(value)}");
                if (value != "off")
                    Console.WriteLine("değişikliğin etkin olması için: sentinel trust apply (yönetici)");
                return 0;
            }

            case "apply":
                await trust.ApplyAsync();
                Console.WriteLine("ilke uygulandı");
                return 0;

            case "reset":
                await trust.ResetAsync();
                Console.WriteLine("kurallar ve ilke sıfırlandı (mod kapalı)");
                return 0;

            case "describe":
            {
                var target = opts.Positional.Skip(2).FirstOrDefault()
                             ?? throw new ArgumentException("kullanım: sentinel trust describe <yol>");
                Console.WriteLine(await trust.DescribeAsync(target, opts.Get("kind") ?? "auto"));
                return 0;
            }

            default:
                Console.Error.WriteLine("kullanım: sentinel trust status|list|add|remove|mode|apply|reset|describe");
                return 1;
        }
    }

    private static string ModeName(string mode) => mode switch
    {
        "off" => "kapalı",
        "audit" => "denetim (yalnız günlüğe yazar)",
        "enforce" => "zorunlu (engeller)",
        _ => mode
    };

    private static string SacName()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Policy");
            var raw = key?.GetValue("VerifiedAndReputablePolicyState");
            if (raw is not int value) return "bilinmiyor";
            return value switch
            {
                0 => "kapalı",
                1 => "zorunlu (engelliyor)",
                2 => "değerlendirme",
                _ => "bilinmiyor"
            };
        }
        catch
        {
            return "bilinmiyor";
        }
    }

    private static int ServiceCommand(Options opts)
    {
        var sub = opts.Positional.Skip(1).FirstOrDefault() ?? "status";
        if (!SentinelPaths.IsAdmin())
            Console.Error.WriteLine("uyarı: servis komutları yönetici gerektirir");

        var exe = opts.Get("exe");
        if (exe is null)
        {
            var candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "Sentinel.Service.exe"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Sentinel.Service", "bin", "Debug", "net8.0", "Sentinel.Service.exe"))
            };
            exe = candidates.FirstOrDefault(File.Exists);
        }

        static int Sc(params string[] args)
        {
            var o = ProcessRunner.RunAsync("sc.exe", args, TimeSpan.FromSeconds(30)).GetAwaiter().GetResult();
            Console.Write(o.Combined);
            return o.ExitCode;
        }

        return sub switch
        {
            "install" when exe is null => MissingExe(),
            "install" => Sc("create", "Sentinel", "binPath=", $"\"{exe}\"",
                "start=", "auto", "DisplayName=", "Sentinel Antivirus"),
            "uninstall" => Sc("delete", "Sentinel"),
            "start" => Sc("start", "Sentinel"),
            "stop" => Sc("stop", "Sentinel"),
            "status" => Sc("query", "Sentinel"),
            _ => MissingExe()
        };

        static int MissingExe()
        {
            Console.Error.WriteLine("Sentinel.Service.exe bulunamadı; --exe <yol> ver veya scripts/install-service.ps1 kullan");
            return 1;
        }
    }

    private sealed class Options
    {
        public string? Home { get; set; }
        public List<string> Positional { get; } = new();
        public Dictionary<string, string?> Flags { get; } = new(StringComparer.OrdinalIgnoreCase);

        public bool Has(string key) => Flags.ContainsKey(key);
        public string? Get(string key) => Flags.TryGetValue(key, out var v) ? v : null;
    }

    private static Options Parse(string[] args)
    {
        var opts = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                var key = a[2..];
                string? value = null;
                var eq = key.IndexOf('=');
                if (eq >= 0)
                {
                    value = key[(eq + 1)..];
                    key = key[..eq];
                }
                else if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)
                         && key is "home" or "to" or "reason" or "days" or "exe" or "path" or "kind" or "id" or "mode")
                {
                    value = args[++i];
                }

                if (key.Equals("home", StringComparison.OrdinalIgnoreCase)) opts.Home = value;
                opts.Flags[key] = value;
            }
            else
            {
                opts.Positional.Add(a);
            }
        }
        return opts;
    }

    private static void Help()
    {
        Console.WriteLine("""
            Sentinel — hafif Windows bekçisi (ClamAV + YARA + Defender)

            kullanım: sentinel <komut> [seçenekler]

            komutlar:
              init                    config ve başlangıç kurallarını oluştur
              status                  durum, motorlar, sayaçlar
              scan <yol> [--deep]     dosya/klasör tara (--force önbelleği atlar, --json çıktı)
              watch                   indirme/temp izleyicisini çalıştır (Ctrl+C ile durur)
              report                  HTML rapor üret ve yolunu yazdır
              quarantine list|restore <id> [--to <yol>]|delete <id>
              allow list|add <yol|sha256> [--reason ...] [--days N]|remove <id>
              quiet                   öğrenilen sakin tarama penceresi
              config                  config yolunu ve içeriğini göster
              selftest                EICAR + karantina testleri
              service install|uninstall|start|stop|status [--exe <yol>]
              trust status|list|add <yol> [--kind auto|publisher|hash|path] [--reason ...]|remove <id>|mode off|audit|enforce|apply|reset|describe <yol>

            genel:
              --home <klasör>         veri kökünü değiştir (varsayılan: yönetici ise %ProgramData%\Sentinel, değilse %LOCALAPPDATA%\Sentinel)
            """);
    }

    private const string StarterRules = """
        /*
          Sentinel başlangıç kuralları.
          Kendi kurallarını bu klasöre ekle; imza sürümü otomatik yenilenir.
        */

        rule Suspicious_PowerShell_Encoded
        {
            meta:
                description = "Encoded PowerShell command line in a script"
                severity = "high"
            strings:
                $a = "-EncodedCommand" nocase
                $b = "-enc " nocase
                $c = "FromBase64String" nocase
            condition:
                any of them
        }

        rule Suspicious_Download_And_Execute
        {
            meta:
                description = "Script downloads and runs remote content"
                severity = "high"
            strings:
                $a = "DownloadString" nocase
                $b = "Invoke-WebRequest" nocase
                $c = "WinHttp.WinHttpRequest" nocase
                $d = "Start-Process" nocase
            condition:
                any of ($a, $b, $c) and $d
        }

        rule Suspicious_Lnk_Shell_Command
        {
            meta:
                description = "LNK shortcut spawning a shell"
                severity = "high"
            strings:
                $lnk = { 4C 00 00 00 01 14 02 00 }
                $a = "powershell" nocase
                $b = "cmd.exe" nocase
                $c = "wscript" nocase
            condition:
                $lnk at 0 and any of ($a, $b, $c)
        }
        """;
}
