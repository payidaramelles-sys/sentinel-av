#requires -Version 5.1
param([switch]$RemoveData)

$ErrorActionPreference = 'Continue'
Write-Host '==> Servis durduruluyor' -ForegroundColor Cyan
& sc.exe stop Sentinel
& sc.exe delete Sentinel

if ($RemoveData) {
    Write-Host '==> Veri siliniyor (karantina dahil!)' -ForegroundColor Yellow
    Remove-Item "$env:ProgramData\Sentinel" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Sentinel" -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Kaldırıldı.' -ForegroundColor Green
