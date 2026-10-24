# Güvenlik Politikası

## Desteklenen sürümler

| Sürüm | Destek |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ |

## Güvenlik açığı bildirimi

**Lütfen güvenlik açıklarını herkese açık issue olarak açmayın.**

Bunun yerine deponun **Security** sekmesindeki
[Report a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
bağlantısını kullanın.

Bildirimde şunlar bulunsun:

- Açığın türü (yetki yükseltme, DLL ele geçirme, karantina anahtarına erişim, ayrıcalıklı dosya yazımı, ...)
- Yeniden üretme adımları
- Etkilenen sürüm ve Windows sürümü
- Varsa kanıt (log, ekran görüntüsü, PoC)

İlk yanıt hedefi: 7 gün.

## Özellikle ilgilendiğimiz alanlar

Sentinel yerel makinede yüksek ayrıcalıkla çalışabildiği için şu sınıflar önceliklidir:

- **Karantina bütünlüğü:** AES-256-GCM blob'unun veya DPAPI anahtarının yetkisiz okunması/değiştirilmesi
- **Ayrıcalık yükseltme:** servis (LocalSystem) ile kullanıcı arayüzü arasındaki köprü (`UiBridge`)
- **Yol/komut enjeksiyonu:** taranan dosya adı veya yolu üzerinden dış süreç çağrılarına (`MpCmdRun`, `yr`, `clamd`) sızan girdi
- **AppLocker politikası:** `trust mode enforce` altında beklenmedik şekilde izin üretilmesi
- **Yükseltilmiş yazma:** `%ProgramData%\Sentinel` altındaki dosyalara yetkisiz yazım

## Kapsam dışı

- Zararlı yazılımın **kaçırılması** (false negative) — bu bir tespit kalitesi sorunudur, hata raporu olarak açılabilir
- İmzasız kurulum dosyası nedeniyle çıkan SmartScreen / Smart App Control uyarısı (bilinen durum, README'de açıklandı)
- Windows Defender'ın veya Smart App Control'ün Sentinel'i engellemesi (README'deki `scripts\fix-blocked-apps.ps1` bölümüne bakın)
- Sosyal mühendislik senaryoları

## Sürüm imzalama

Sürümler henüz kod imzalama sertifikasıyla imzalanmamaktadır. Her sürümün SHA-256 özeti
Release notlarında yayınlanır — indirdiğiniz dosyanın özetini doğrulayın.

```powershell
Get-FileHash .\Sentinel-Setup-x.y.z.exe -Algorithm SHA256
```
