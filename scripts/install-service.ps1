#requires -Version 5.1
<#
  Sentinel'i yayınlar ve Windows servisi olarak kurar.
  Yönetici PowerShell'de çalıştır.
#>
param(
    [string]$InstallDir = "$env:ProgramData\Sentinel\bin",
    [switch]$SkipService
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = if ($env:SENTINEL_DOTNET) { $env:SENTINEL_DOTNET }
          else { Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe' }
if (-not (Test-Path $dotnet)) { $dotnet = 'dotnet' }

function Step($t) { Write-Host "==> $t" -ForegroundColor Cyan }

Step "Yayınlanıyor: $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

& $dotnet publish (Join-Path $root 'src\Sentinel.Service\Sentinel.Service.csproj') -c Release -o (Join-Path $InstallDir 'service') --nologo
& $dotnet publish (Join-Path $root 'src\Sentinel.Cli\Sentinel.Cli.csproj') -c Release -o (Join-Path $InstallDir 'cli') --nologo
& $dotnet publish (Join-Path $root 'src\Sentinel.Tray\Sentinel.Tray.csproj') -c Release -o (Join-Path $InstallDir 'tray') --nologo

$configRoot = "$env:ProgramData\Sentinel"
New-Item -ItemType Directory -Force -Path $configRoot | Out-Null

Step 'Kurallar kopyalanıyor'
$ruleDest = Join-Path $configRoot 'rules\yara'
New-Item -ItemType Directory -Force -Path $ruleDest | Out-Null
Copy-Item (Join-Path $root 'rules\yara\*') -Destination $ruleDest -Force -ErrorAction SilentlyContinue
Step 'Başlangıç yapılandırması'
& (Join-Path $InstallDir 'cli\Sentinel.Cli.exe') init

# Tray ve CLI (yönetici olmayan kullanıcı) aynı veriyi okuyabilsin.
Step 'Veri klasörü izinleri'
& icacls $configRoot /grant '*S-1-5-32-545:(OI)(CI)M' /T /C | Out-Null

if ($SkipService) {
    Write-Host 'Servis atlandı. CLI: ' + (Join-Path $InstallDir 'cli\Sentinel.Cli.exe')
    return
}

$exe = Join-Path $InstallDir 'service\Sentinel.Service.exe'
Step "Servis kuruluyor: $exe"
& sc.exe stop Sentinel | Out-Null
& sc.exe delete Sentinel | Out-Null
& sc.exe create Sentinel binPath= "`"$exe`"" start= auto DisplayName= "Sentinel Antivirus" | Out-Null
& sc.exe description Sentinel "Hafif dosya izleyici ve zamanlanmis derin tarayici (ClamAV/YARA/Defender)" | Out-Null
& sc.exe failure Sentinel reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
& sc.exe start Sentinel

Write-Host ''
Write-Host "Kurulum tamam. Durum: $InstallDir\cli\Sentinel.Cli.exe status" -ForegroundColor Green
Write-Host "Tray: $InstallDir\tray\Sentinel.exe" -ForegroundColor Green
