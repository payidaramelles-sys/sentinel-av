# Sentinel kurulum paketini üretir: dist\Sentinel.exe + servis + CLI -> installer\output\Sentinel-Setup-1.0.0.exe
# Kullanım: powershell -ExecutionPolicy Bypass -File installer\build.ps1
param(
    [string]$Configuration = 'Release',
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$payload = Join-Path $PSScriptRoot 'payload'

# .NET SDK: makinede global kurulu değilse kullanıcı klasöründeki SDK'ya düş.
$dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnet = if ($dotnetCmd) { $dotnetCmd.Source } else { $null }
if (-not $dotnet -or -not (& $dotnet --list-sdks 2>$null)) {
    $dotnet = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
}
if (-not (Test-Path $dotnet)) { throw ".NET SDK bulunamadı. https://dot.net adresinden kur." }

$iscc = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 bulunamadı. 'winget install JRSoftware.InnoSetup' ile kur." }

$singleFile = @(
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:DebugType=none'
)

function Publish($project, $out) {
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    & $dotnet publish $project -c $Configuration -r win-x64 --self-contained true @singleFile -o $out --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "publish başarısız: $project" }
    Get-ChildItem $out -Filter *.pdb -Recurse | Remove-Item -Force
    Get-ChildItem $out -Filter *.xml -Recurse | Remove-Item -Force
    Get-ChildItem $out -Filter 'appsettings.Development.json' -Recurse | Remove-Item -Force
}

if (-not $SkipPublish) {
    Write-Host '==> Uygulama derleniyor' -ForegroundColor Cyan
    Publish (Join-Path $root 'src\Sentinel.Tray\Sentinel.Tray.csproj') (Join-Path $payload 'app')
    Write-Host '==> CLI derleniyor' -ForegroundColor Cyan
    Publish (Join-Path $root 'src\Sentinel.Cli\Sentinel.Cli.csproj') (Join-Path $payload 'cli')
    Write-Host '==> Servis derleniyor' -ForegroundColor Cyan
    Publish (Join-Path $root 'src\Sentinel.Service\Sentinel.Service.csproj') (Join-Path $payload 'service')

    # dist\ klasörünü de güncel tut
    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    Copy-Item (Join-Path $payload 'app\Sentinel.exe') (Join-Path $dist 'Sentinel.exe') -Force
}

Write-Host '==> Kurulum paketi oluşturuluyor' -ForegroundColor Cyan
& $iscc (Join-Path $PSScriptRoot 'Sentinel.iss') | ForEach-Object { $_ }
if ($LASTEXITCODE -ne 0) { throw "ISCC başarısız (çıkış kodu $LASTEXITCODE)" }

$setup = Get-ChildItem (Join-Path $PSScriptRoot 'output') -Filter 'Sentinel-Setup-*.exe' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host ''
Write-Host ("Hazır: {0}  ({1:N1} MB)" -f $setup.FullName, ($setup.Length / 1MB)) -ForegroundColor Green
