#requires -Version 5.1
<#
.SYNOPSIS
  "Defender engelliyor" sanılan engelleri gerçek kaynağına ayırır ve gerekli
  istisnaları ekler.

.DESCRIPTION
  Windows'ta bir uygulamayı iki farklı katman durdurabilir:

    1) Microsoft Defender  -> olay günlüğü: Windows Defender/Operational (1116/1117)
       Virüs/imza tespiti. İstisna ile geçilebilir.

    2) Smart App Control (SAC) -> olay günlüğü: CodeIntegrity/Operational (3077/3033)
       İmzasız / itibarı bilinmeyen exe ve DLL'leri engeller.
       Defender'da HİÇBİR tehdit görünmez. İstisna listesi YOKTUR.

  Bu script ikisini ayrı ayrı raporlar; varsayılan olarak hiçbir şeyi değiştirmez.

  -Apply        : bilinen uygulama klasörleri + verilen yollar için Defender
                  istisnası ekler (geri alınabilir).
  -DisablePua   : PUA korumasını kapatır (proxy/patcher gibi araçları engelliyor).
  -DisableSac   : Smart App Control'ü kapatır. GERİ ALINAMAZ (Windows sıfırlanmadan).
                  -ConfirmSac olmadan çalışmaz.

.EXAMPLE
  .\fix-blocked-apps.ps1
.EXAMPLE
  .\fix-blocked-apps.ps1 -Apply -DisablePua -ExtraPaths 'D:\Oyunlar\X'
.EXAMPLE
  .\fix-blocked-apps.ps1 -DisableSac -ConfirmSac    # yönetici, geri alınamaz
#>
[CmdletBinding()]
param(
    [string[]]$ExtraPaths = @(),
    [switch]$Apply,
    [switch]$DisablePua,
    [switch]$DisableSac,
    [switch]$ConfirmSac,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
if ($LogPath) { Start-Transcript -Path $LogPath -Force | Out-Null }

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Info($text) { Write-Host "    $text" -ForegroundColor Gray }
function Write-Warn2($text) { Write-Host "    $text" -ForegroundColor Yellow }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# \Device\HarddiskVolume3\Users\... -> C:\Users\...
function Resolve-DevicePath([string]$devicePath) {
    if (-not $devicePath) { return $null }
    if ($devicePath -notmatch '^\\Device\\HarddiskVolume\d+\\(.*)$') { return $devicePath }
    $tail = $Matches[1]
    foreach ($drive in (Get-PSDrive -PSProvider FileSystem).Name) {
        $candidate = "${drive}:\$tail"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return "C:\$tail"
}

# --- 1. Defender durumu ---------------------------------------------------
Write-Step 'Defender durumu'
$status = Get-MpComputerStatus
$pref = Get-MpPreference
Write-Info "Gerçek zamanlı koruma : $($status.RealTimeProtectionEnabled)"
Write-Info "İmza sürümü           : $($status.AntivirusSignatureVersion)"
Write-Info "PUA koruması          : $($pref.PUAProtection)  (1/2 = açık, 0 = kapalı)"
Write-Info "Controlled folder     : $($pref.EnableControlledFolderAccess)  (1 = açık)"
if ($isAdmin) {
    Write-Info "Tanımlı yol istisnası : $($pref.ExclusionPath.Count)"
    Write-Info "Tanımlı süreç istisna : $($pref.ExclusionProcess.Count)"
} else {
    Write-Info "İstisna listesi       : yönetici olmadan okunamaz"
}

# --- 2. Smart App Control -------------------------------------------------
Write-Step 'Smart App Control (SAC)'
$ciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
$sac = (Get-ItemProperty -Path $ciKey -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
$sacNames = @{ 0 = 'Kapalı'; 1 = 'Zorunlu - imzasız uygulamaları engelliyor'; 2 = 'Değerlendirme' }
Write-Info ("Durum                 : {0} ({1})" -f $sac, $sacNames[[int]$sac])

# --- 3. Son engeller ------------------------------------------------------
Write-Step 'Son engeller (Defender + Code Integrity)'
$rows = @()

$defEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117
} -MaxEvents 40 -ErrorAction SilentlyContinue
foreach ($e in $defEvents) {
    $path = [regex]::Match($e.Message, '(?m)^\s*Path:\s*(.+)$').Groups[1].Value.Trim()
    $name = [regex]::Match($e.Message, '(?m)^\s*Name:\s*(.+)$').Groups[1].Value.Trim()
    if (-not $path) { $path = [regex]::Match($e.Message, '(?m)^\s*Enforcement file:\s*(.+)$').Groups[1].Value.Trim() }
    $rows += [pscustomobject]@{
        Time    = $e.TimeCreated
        Layer   = 'Defender'
        Action  = if ($e.Id -eq 1116) { 'Tespit' } else { 'Aksiyon' }
        Threat  = $name
        File    = $path
    }
}

$ciEvents = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 300 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 3077 -or $_.Id -eq 3033 }
foreach ($e in $ciEvents) {
    $blocked = [regex]::Match($e.Message, 'attempted to load (.+?) that did not meet').Groups[1].Value
    $loader = [regex]::Match($e.Message, 'a process \((.+?)\) attempted').Groups[1].Value
    if (-not $blocked) { continue }
    $rows += [pscustomobject]@{
        Time    = $e.TimeCreated
        Layer   = 'SAC'
        Action  = 'Engel'
        Threat  = if ($loader) { "yükleyen: " + (Split-Path $loader -Leaf) } else { '' }
        File    = Resolve-DevicePath $blocked
    }
}

$rows = $rows | Sort-Object Time -Descending
# 3077 ve 3033 aynı engelin iki kaydı; zaman+dosya ile tekilleştir.
$seen = @{}
$rows = $rows | Where-Object {
    $key = '{0}|{1}' -f $_.Time.ToString('s'), $_.File
    if ($seen.ContainsKey($key)) { $false } else { $seen[$key] = 1; $true }
}
if ($rows.Count -eq 0) {
    Write-Info 'Kayıtlı engel bulunamadı.'
} else {
    $rows | Select-Object -First 15 |
        Select-Object @{n = 'Zaman'; e = { $_.Time.ToString('dd.MM HH:mm') } }, Layer, Action, Threat, File |
        Format-Table -AutoSize | Out-String -Width 300 | Write-Host
    $sacCount = ($rows | Where-Object { $_.Layer -eq 'SAC' }).Count
    $defCount = ($rows | Where-Object { $_.Layer -eq 'Defender' }).Count
    Write-Info "Özet: $defCount Defender tespiti, $sacCount SAC engeli (son 300 CI olayında)."
}

# --- 4. Aday istisnalar ---------------------------------------------------
Write-Step 'Aday istisna yolları'
$candidates = @(
    'C:\WoM2',
    "$env:LOCALAPPDATA\hermes",
    "$env:APPDATA\Hermes",
    "$env:LOCALAPPDATA\com.nousresearch.hermes.setup",
    "$env:USERPROFILE\Downloads\WoM2_Installer_x86.exe",
    "$env:USERPROFILE\Downloads\Hermes-Setup.exe"
) + $ExtraPaths
$candidates = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

if ($candidates.Count -eq 0) {
    Write-Info 'Eşleşen yol yok. -ExtraPaths ile elle ekleyebilirsin.'
} else {
    foreach ($c in $candidates) { Write-Info $c }
}

# --- 5. Uygulama ----------------------------------------------------------
if ($Apply -or $DisablePua -or $DisableSac) {
    if (-not $isAdmin) { throw 'Değişiklik için yönetici PowerShell gerekli.' }
}

if ($Apply) {
    Write-Step 'Defender istisnaları ekleniyor'
    foreach ($c in $candidates) {
        Add-MpPreference -ExclusionPath $c -ErrorAction SilentlyContinue
        Write-Info "eklendi: $c"
    }
}

if ($DisablePua) {
    Write-Step 'PUA koruması kapatılıyor'
    Set-MpPreference -PUAProtection 0
    Write-Info 'tamam (geri al: Set-MpPreference -PUAProtection Enabled)'
}

if ($DisableSac) {
    if (-not $ConfirmSac) { throw 'Geri alınamaz işlem: -ConfirmSac ekle.' }
    Write-Step 'Smart App Control kapatılıyor'
    Set-ItemProperty -Path $ciKey -Name VerifiedAndReputablePolicyState -Value 0 -Type DWord
    Write-Info 'tamam. Etkili olması için yeniden başlat.'
    Write-Warn2 'Geri almak Windows sıfırlaması gerektirir.'
}

if (-not ($Apply -or $DisablePua -or $DisableSac)) {
    Write-Host ''
    Write-Host 'Kuru çalışma. Uygulamak için: -Apply -DisablePua' -ForegroundColor Yellow
    if ($sac -eq 1) {
        Write-Host 'SAC engelliyorsa tek çözüm: -DisableSac -ConfirmSac (geri alınamaz).' -ForegroundColor Yellow
    }
}

if ($LogPath) { Stop-Transcript | Out-Null }
