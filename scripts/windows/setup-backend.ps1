<#
.SYNOPSIS
  Creates a Python venv for the Hck backend (dev checkout or portable AppData layout).

.DESCRIPTION
  Dev mode (default): creates backend\.venv next to the monorepo and installs the package.
  Packaged mode (-Portable): installs into %LOCALAPPDATA%\com.hck.platform\python-venv
  so the Tauri shell can find the interpreter after an MSI/NSIS install.

.PARAMETER Portable
  Use AppData venv instead of backend\.venv (for installed desktop builds).

.PARAMETER BackendDir
  Path to the backend package root (contains pyproject.toml and app\).
#>
[CmdletBinding()]
param(
    [switch]$Portable,
    [string]$BackendDir = ""
)

$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    $here = Split-Path -Parent $PSScriptRoot
    return Split-Path -Parent $here
}

function Invoke-Python {
    param([Parameter(ValueFromRemainingArguments = $true)]$Args)
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 @Args
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python @Args
    } else {
        Write-Error "Python 3.11+ nicht gefunden. Installiere von https://www.python.org/downloads/ (Haken 'Add to PATH')."
    }
}

$repoRoot = Resolve-RepoRoot

if (-not $BackendDir) {
    if ($Portable) {
        $resourceCandidates = @(
            (Join-Path $env:LOCALAPPDATA "com.hck.platform\backend"),
            (Join-Path ${env:ProgramFiles} "Hck\backend"),
            (Join-Path $repoRoot "backend")
        )
        foreach ($c in $resourceCandidates) {
            if (Test-Path (Join-Path $c "app\main.py")) {
                $BackendDir = $c
                break
            }
        }
    } else {
        $BackendDir = Join-Path $repoRoot "backend"
    }
}

if (-not (Test-Path (Join-Path $BackendDir "app\main.py"))) {
    Write-Error "Backend nicht gefunden unter '$BackendDir' (erwartet app\main.py)."
}

Write-Host "Backend: $BackendDir"

if ($Portable) {
    $venvDir = Join-Path $env:LOCALAPPDATA "com.hck.platform\python-venv"
} else {
    $venvDir = Join-Path $BackendDir ".venv"
}

$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Erstelle venv: $venvDir"
    Invoke-Python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) { Write-Error "venv-Erstellung fehlgeschlagen." }
} else {
    Write-Host "Bestehendes venv: $venvDir"
}

Write-Host "Installiere Backend-Dependencies…"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -e "$BackendDir[dev]"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Editable install fehlgeschlagen — versuche normale Installation…"
    & $venvPython -m pip install "$BackendDir"
    if ($LASTEXITCODE -ne 0) { Write-Error "pip install fehlgeschlagen." }
}

Push-Location $BackendDir
try {
    $env:HCK_DATA_DIR = if ($Portable) {
        Join-Path $env:LOCALAPPDATA "com.hck.platform"
    } else {
        Join-Path $env:USERPROFILE ".hck"
    }
    New-Item -ItemType Directory -Force -Path $env:HCK_DATA_DIR | Out-Null
    Write-Host "Alembic upgrade (HCK_DATA_DIR=$($env:HCK_DATA_DIR))…"
    & $venvPython -m alembic upgrade head
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Alembic fehlgeschlagen — Desktop nutzt create_all-Bootstrap beim Start."
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Fertig. Python: $venvPython"
Write-Host "Dev-Start:  .\scripts\windows\dev-start.ps1"
Write-Host "Smoke:      .\scripts\windows\smoke-check.ps1"
