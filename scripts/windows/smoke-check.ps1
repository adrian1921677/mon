<#
.SYNOPSIS
  Smoke-Check für Hck auf Windows: Backend-Health, Projects, Tools, OpenAPI.
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:8765",
    [switch]$StartBackend
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$backendDir = Join-Path $repoRoot "backend"
$venvPython = Join-Path $backendDir ".venv\Scripts\python.exe"
$proc = $null
$failed = 0

function Assert-Ok([string]$Name, [scriptblock]$Block) {
    try {
        & $Block
        Write-Host "[OK] $Name"
    } catch {
        Write-Host "[FAIL] $Name — $($_.Exception.Message)"
        $script:failed++
    }
}

if ($StartBackend) {
    if (-not (Test-Path $venvPython)) {
        & (Join-Path $PSScriptRoot "setup-backend.ps1")
    }
    $env:HCK_HOST = "127.0.0.1"
    $env:HCK_PORT = "8765"
    $env:HCK_DATA_DIR = Join-Path $env:USERPROFILE ".hck"
    $proc = Start-Process -FilePath $venvPython `
        -ArgumentList @("-m", "app.main") `
        -WorkingDirectory $backendDir `
        -PassThru `
        -WindowStyle Hidden
    Start-Sleep -Seconds 3
}

Assert-Ok "GET /health" {
    $h = Invoke-RestMethod -Uri "$BaseUrl/health" -TimeoutSec 5
    if ($h.status -ne "ok") { throw "status=$($h.status)" }
}

Assert-Ok "GET /openapi.json" {
    $null = Invoke-RestMethod -Uri "$BaseUrl/openapi.json" -TimeoutSec 5
}

Assert-Ok "GET /api/v1/projects" {
    $null = Invoke-RestMethod -Uri "$BaseUrl/api/v1/projects" -TimeoutSec 5
}

Assert-Ok "GET /api/v1/tools" {
    $tools = Invoke-RestMethod -Uri "$BaseUrl/api/v1/tools" -TimeoutSec 10
    if (-not $tools) { throw "leere Tool-Liste" }
    Write-Host ("       " + $tools.Count + " Scanner in Registry")
}

Assert-Ok "POST project smoke" {
    $body = @{ name = "smoke-win-$(Get-Random)"; description = "phase9" } | ConvertTo-Json
    $created = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/projects" `
        -ContentType "application/json" -Body $body -TimeoutSec 5
    $null = Invoke-RestMethod -Method Delete -Uri "$BaseUrl/api/v1/projects/$($created.id)" -TimeoutSec 5
}

if ($proc) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}

if ($failed -gt 0) {
    Write-Error "$failed Smoke-Check(s) fehlgeschlagen."
    exit 1
}
Write-Host "Alle Smoke-Checks bestanden."
