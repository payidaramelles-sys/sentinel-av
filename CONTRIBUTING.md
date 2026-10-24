# Katkı Rehberi

Sentinel tek kişiyle başladı; katkılar memnuniyetle karşılanır. Bu rehber, katkının
hızlıca değerlendirilebilmesi için gereken en az bilgiyi tanımlar.

## Hata bildirimi

Issue açmadan önce arama yapın. Issue'da şunlar bulunsun:

- **Ne yaptım?** (adım adım)
- **Ne bekliyordum?**
- **Ne oldu?** (hata mesajı, ekran görüntüsü, `sentinel report` çıktısı)
- Windows sürümü (`winver`), Sentinel sürümü, ilgili motor (Defender / YARA-X / ClamAV / heuristik)
- `response.mode` (dryRun / notify / auto)

## Geliştirme ortamı

- Windows 10 1809+ veya Windows 11
- [.NET SDK 8](https://dotnet.microsoft.com/download) (`dotnet --list-sdks`)
- WebView2 Runtime (Windows 11'de kurulu gelir)
- Opsiyonel: Inno Setup 6 (kurulum paketi için), YARA-X, ClamAV

```powershell
dotnet build Sentinel.sln -c Release
dotnet run --project src\Sentinel.Cli -- selftest
dotnet run --project src\Sentinel.Tray\Sentinel.Tray.csproj
```

`Sentinel.Tray` yalnızca Windows'ta derlenir (`net8.0-windows` + WinForms + WebView2).
`Core`, `Engines`, `Watch`, `Cli` ve `Service` `net8.0` hedefler; ancak çalışma zamanında
Windows API'leri (kayıt defteri, DPAPI, WMI) kullandıkları için üretimde Windows gerekir.

## Kod katkısı

1. Depoyu fork'layın, `main` dışında bir dal açın: `git checkout -b ozellik/kisa-aciklama`
2. Değişikliği yapın; davranış değişiyorsa `selftest`'e veya yeni bir teste yansıtın
3. `dotnet build Sentinel.sln -c Release` uyarısız geçmeli
4. Commit mesajı kısa ve emir kipi olsun: `düzeltme: karantina klasörü oluşturma yarışı`
5. Pull request açıklamasında **ne değişti**, **neden** ve **nasıl doğruladığınız** yazsın

## Kod kuralları

- Mevcut stile uyun; biçimlendirici/toplu yeniden adlandırma PR'ları ayrı gönderin
- Yeni NuGet bağımlılığı ekliyorsanız gerekçesini ve lisansını PR'da belirtin
- **Yanlış pozitif felsefesini koruyun:** varsayılan mod `dryRun` kalmalı. Varsayılanı
  daha agresif yapan değişiklikler, gerekçesi çok güçlü değilse kabul edilmez.
- Ayrıcalık, süreç çağrısı, dosya silme veya kayıt defteri yazımı ekleyen her değişiklik
  `SECURITY.md`'deki inceleme kapsamındadır — PR'da bunu belirtin.
- Sırlar, kişisel yollar (`C:\Users\<ad>\...`), makineye özel klasörler commit edilmez.

## Lisans

Katkılar MIT lisansı altında kabul edilir. ClamAV (GPLv2) ve YARA-X (BSD-3) ayrı süreç
olarak çağrılır; bunların kodunu projeye dahil etmeyin, bağlantılamayın (bkz. README'deki
"Lisans notu").

## Davranış

Teknik eleştiri memnuniyetle, kişisel eleştiri değil.
