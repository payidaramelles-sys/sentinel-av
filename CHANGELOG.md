# Sürüm Notları

Bu proje [Semantic Versioning](https://semver.org/lang/tr/) kullanır.

## [Yayınlanmamış]

### Eklenen
- ETW tabanlı davranış katmanı (süreç ağacı, komut satırı zinciri) — yol haritasında
- USN Journal ile artımlı tarama — yol haritasında
- Fidye yazılımı erken uyarısı için canary dosyaları — yol haritasında
- Tray için otomatik başlatma ve named-pipe üzerinden canlı durum — yol haritasında

---

## [1.0.0] — 2026-10-24

İlk açık kaynak sürüm.

### Eklenen
- **İzleme:** indirilenler ve `%TEMP%` gerçek zamanlı izleme, dosya açılana kadar bekleme,
  Mark-of-the-Web (ZoneId=3/4) tespiti, hash önbelleği
- **Heuristikler:** çift uzantı, MZ/uzantı uyuşmazlığı, gömülü PE, polyglot, imzasız PE,
  `%TEMP%` içinde EXE, makro, arşiv içinde çalıştırılabilir
- **Arşiv incelemesi:** zip/docx/xlsx/jar içi tarama, şifreli arşiv uyarısı
- **Motorlar:** yerleşik EICAR imzası, Windows Defender (`MpCmdRun -DisableRemediation`),
  YARA-X (opsiyonel), ClamAV (opsiyonel, `clamd` TCP/INSTREAM)
- **Karantina:** AES-256-GCM + DPAPI ile şifreli saklama, geri yükleme, silme
- **Günlük:** SQLite olay kaydı + hash zincirli JSONL
- **Zamanlama:** kullanım öğrenimi ile en sakin 2 saatte haftalık derin tarama
- **Davranış izleyici:** izlenen klasörlerden başlayan süreçleri yakalama (varsayılan
  `dryRun` modunda yalnızca kaydeder)
- **Arayüz:** WebView2 tabanlı masaüstü uygulaması — Genel Bakış, Tarama, Karantina, Güven,
  Olaylar, Ayarlar; koyu/açık tema; tepsi simgesi
- **Güven listesi:** AppLocker ile yayıncı / SHA-256 / klasör bazlı izin; kapalı, denetim
  ve zorunlu modları
- **CLI:** `init`, `status`, `scan`, `watch`, `quiet`, `report`, `quarantine`,
  `allow`, `trust`, `selftest`, `service`
- **Paketleme:** tek dosya `Sentinel.exe` (self-contained), Windows servisi, Inno Setup
  kurulum paketi
- **Belgeler:** Türkçe README, güvenlik politikası, katkı rehberi, davranış kuralları,
  GitHub Actions CI

### Bilinçli olarak kapsam dışı
- Ön-yürütme engelleme (kernel minifilter) — imzalı sürücü ve EV sertifikası gerektirir
- Windows Güvenlik Merkezi'ne AV olarak kaydolma — WSC + ELAM sürücüsü gerektirir

### Bilinen sınırlar
- Dosyanın çalışmasını engelleyemez; tespit → karantina → bildirim yapar
- Davranış katmanı 3 saniyelik süreç yoklaması kullanır (ETW değil)
- ClamAV'ın Windows tespit oranı ticari AV'lerin gerisindedir

[Yayınlanmamış]: https://github.com/payidaramelles-sys/sentinel-av/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/payidaramelles-sys/sentinel-av/releases/tag/v1.0.0
