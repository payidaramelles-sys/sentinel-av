#requires -Version 5.1
<#
.SYNOPSIS
  Defender'ı kısmaya yönelik isteğe bağlı ayar scripti.
.DESCRIPTION
  Varsayılan olarak SADECE mevcut durumu gösterir. Hiçbir şeyi değiştirmek için
  ilgili anahtarı açıkça vermen gerekir. Yönetici olarak çalıştır.

  Uyarı: her istisna korumayı zayıflatır. İndirilenler klasörünün tamamını
  istisna yapmak, tam da taramak istediğin yeri kör bırakır.
.EXAMPLE
  .\tame-defender.ps1
  .\tame-defender.ps1 -AddDevExclusions -DisablePua -Apply
#>
param(
    [string[]]$ExtraPaths = @(),
    [switch]$AddDevExclusions,
    [switch]$AddDevProcessExclusions,
    [switch]$DisablePua,
    [switch]$DisableControlledFolderAccess,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Info($text) { Write-Host "    $text" -ForegroundColor Gray }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Yönetici değilsin; salt okunur gösterim yapılacak.'
    $Apply = $false
}

Write-Step 'Mevcut Defender durumu'
$pref = Get-MpPreference
$status = Get-MpComputerStatus
Write-Info "Gerçek zamanlı koruma : $($status.RealTimeProtectionEnabled)"
Write-Info "Bulut (MAPS)          : $($pref.MAPSReporting)"
Write-Info "PUA koruması          : $($pref.PUAProtection)  (2 = açık)"
Write-Info "Controlled folder     : $($pref.EnableControlledFolderAccess)  (1 = açık)"
Write-Info "İstisna yol sayısı    : $($pref.ExclusionPath.Count)"
Write-Info "İstisna süreç sayısı  : $($pref.ExclusionProcess.Count)"

Write-Step 'Planlanan değişiklikler'
$paths = @()
if ($AddDevExclusions) {
    $paths += @(
        "$env:USERPROFILE\.nuget\packages",
        "$env:USERPROFILE\.gradle",
        "$env:USERPROFILE\.m2",
        "$env:USERPROFILE\AppData\Local\Temp\opencode",
        "$env:USERPROFILE\AppData\Local\Temp\chocolatey"
    )
}
$paths += $ExtraPaths
$paths = $paths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

if ($paths.Count -eq 0 -and -not $DisablePua -and -not $AddDevProcessExclusions -and -not $DisableControlledFolderAccess) {
    Write-Info 'Değişiklik yok. Anahtarları incelemek için: Get-Help .\tame-defender.ps1 -Full'
    return
}

foreach ($p in $paths) { Write-Info "yol istisnası      : $p" }
if ($AddDevProcessExclusions) {
    Write-Info 'süreç istisnası    : dotnet.exe, msbuild.exe, node.exe, git.exe, devenv.exe'
}
if ($DisablePua) { Write-Info 'PUA koruması       : kapatılacak' }
if ($DisableControlledFolderAccess) { Write-Info 'Controlled folder  : kapatılacak' }

if (-not $Apply) {
    Write-Host ''
    Write-Host 'Kuru çalışma. Uygulamak için sonuna -Apply ekle.' -ForegroundColor Yellow
    return
}

Write-Step 'Uygulanıyor'
foreach ($p in $paths) {
    Add-MpPreference -ExclusionPath $p
    Write-Info "eklendi: $p"
}
if ($AddDevProcessExclusions) {
    foreach ($proc in 'dotnet.exe', 'msbuild.exe', 'node.exe', 'git.exe', 'devenv.exe') {
        Add-MpPreference -ExclusionProcess $proc
        Write-Info "eklendi: $proc"
    }
}
if ($DisablePua) {
    Set-MpPreference -PUAProtection Disabled
    Write-Info 'PUA koruması kapatıldı'
}
if ($DisableControlledFolderAccess) {
    Set-MpPreference -EnableControlledFolderAccess Disabled
    Write-Info 'Controlled folder access kapatıldı'
}

Write-Step 'Sonuç'
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, PUAProtection, EnableControlledFolderAccess |
    Format-List
Write-Host 'Geri almak için: Remove-MpPreference -ExclusionPath <yol>' -ForegroundColor Yellow
