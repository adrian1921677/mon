<#
.SYNOPSIS
  Starts the Hck backend (and optionally Tauri) for local Windows development.

.PARAMETER Desktop
  Also run `npm run tauri dev` in apps/desktop (requires Rust + WebView2).

.PARAMETER UiOnly
  Only start Vite UI (`npm run dev`); backend must already be running.
#>
[CmdletBinding()]
param(
    [switch]$Desktop,
    [switch]$UiOnly
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$backendDir = Join-Path $repoRoot "backend"
$desktopDir = Join-Path $repoRoot "apps\desktop"
$venvPython = Join-Path $backendDir ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Kein venv — starte setup-backend.ps1…"
    & (Join-Path $PSScriptRoot "setup-backend.ps1")
}

if ($UiOnly) {
    Push-Location $desktopDir
    try {
        if (-not (Test-Path "node_modules")) {
            npm install --legacy-peer-deps
        }
        npm run dev
    } finally {
        Pop-Location
    }
    return
}

$env:HCK_HOST = "127.0.0.1"
$env:HCK_PORT = "8765"
$env:HCK_DATA_DIR = Join-Path $env:USERPROFILE ".hck"
New-Item -ItemType Directory -Force -Path $env:HCK_DATA_DIR | Out-Null

Write-Host "Starte Backend auf http://127.0.0.1:8765 …"
$backend = Start-Process -FilePath $venvPython `
    -ArgumentList @("-m", "app.main") `
    -WorkingDirectory $backendDir `
    -PassThru `
    -WindowStyle Minimized

Start-Sleep -Seconds 2

try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8765/health" -TimeoutSec 5
    Write-Host "Health: $($health.status) v$($health.version)"
} catch {
    Write-Warning "Health-Check noch nicht ok — Backend startet ggf. noch. PID=$($backend.Id)"
}

if ($Desktop) {
    Push-Location $desktopDir
    try {
        if (-not (Test-Path "node_modules")) {
            npm install --legacy-peer-deps
        }
        Write-Host "Starte Tauri (Ctrl+C beendet UI; Backend-PID $($backend.Id) weiterlaufen)…"
        npm run tauri dev
    } finally {
        Pop-Location
    }
} else {
    Write-Host "Backend läuft (PID $($backend.Id)). Stoppen: Stop-Process -Id $($backend.Id)"
    Write-Host "Desktop: .\scripts\windows\dev-start.ps1 -Desktop"
    Wait-Process -Id $backend.Id
}
