#requires -Version 5.1
<#
.SYNOPSIS
  Windows 11 "Smart App Control" (Akıllı Uygulama Denetimi) durumunu gösterir veya kapatır.

.DESCRIPTION
  Smart App Control, imzasız ve itibarı bilinmeyen exe'leri Windows Defender'dan bağımsız olarak
  engeller. Hata iletisi "Uygulama Denetimi ilkesi bu dosyayı engelledi" şeklindedir;
  Defender günlüğünde hiçbir tehdit görünmez.

  Değerler: 0 = kapalı, 1 = zorunlu (engelliyor), 2 = değerlendirme.

  UYARI: Kapatıldıktan sonra Windows'u sıfırlamadan tekrar açılamaz.
  Bu yüzden varsayılan olarak sadece durumu gösterir; kapatmak için -Disable -ConfirmDisable ver.

.EXAMPLE
  .\smart-app-control.ps1
.EXAMPLE
  .\smart-app-control.ps1 -Disable -ConfirmDisable    # yönetici PowerShell
#>
[CmdletBinding()]
param(
    [switch]$Disable,
    [switch]$ConfirmDisable
)

$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
$state = (Get-ItemProperty -Path $key -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState

$names = @{ 0 = 'Kapalı'; 1 = 'Zorunlu (imzasız uygulamaları engelliyor)'; 2 = 'Değerlendirme' }
Write-Host ("Smart App Control: {0} ({1})" -f $state, $names[[int]$state]) -ForegroundColor Cyan

if (-not $Disable) {
    Write-Host ''
    Write-Host 'Kapatmak için (yönetici):  .\smart-app-control.ps1 -Disable -ConfirmDisable'
    Write-Host 'Arayüzden: Ayarlar > Gizlilik ve güvenlik > Windows Güvenliği > Uygulama ve tarayıcı denetimi'
    return
}

if (-not $ConfirmDisable) {
    throw 'Onay gerekli: -ConfirmDisable ekle. Bu işlem geri alınamaz (Windows sıfırlanmadan).'
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Yönetici olarak çalıştır.'
}

if ($state -eq 0) { Write-Host 'Zaten kapalı.'; return }

Set-ItemProperty -Path $key -Name VerifiedAndReputablePolicyState -Value 0 -Type DWord
Write-Host 'Smart App Control kapatıldı. Etkili olması için yeniden başlat.' -ForegroundColor Green
Write-Host 'Geri almak için: Windows Güvenliği > Uygulama ve tarayıcı denetimi > Akıllı Uygulama Denetimi (yalnızca Windows sıfırlanarak).'
