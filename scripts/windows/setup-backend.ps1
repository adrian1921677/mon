<#
.SYNOPSIS
  Creates a Python venv for the Hck backend (dev checkout or portable AppData layout).

.DESCRIPTION
  Dev mode (default): creates backend\.venv next to the monorepo and installs the package.
  Packaged mode (-Portable): installs into %LOCALAPPDATA%\com.hck.platform\python-venv
  so the Tauri shell can find the interpreter after an MSI/NSIS install.

  After an installer build the desktop app can also run the same bootstrap via the
  in-app button „Backend einrichten“ (no separate script needed).

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

function Find-InstalledBackend {
    $candidates = [System.Collections.Generic.List[string]]::new()

    # Tauri resource_dir / NSIS currentUser (productName = Hck)
    foreach ($root in @(
            (Join-Path $env:LOCALAPPDATA "Hck"),
            (Join-Path $env:LOCALAPPDATA "Programs\Hck"),
            (Join-Path ${env:ProgramFiles} "Hck"),
            (Join-Path ${env:ProgramFiles(x86)} "Hck")
        )) {
        if (-not $root) { continue }
        $candidates.Add((Join-Path $root "backend"))
        $candidates.Add((Join-Path $root "resources\backend"))
    }

    # Legacy / mistaken paths still checked for older docs
    $candidates.Add((Join-Path $env:LOCALAPPDATA "com.hck.platform\backend"))

    # Script shipped next to install dir or as Release asset next to a checkout
    if ($PSScriptRoot) {
        $candidates.Add((Join-Path $PSScriptRoot "backend"))
        $candidates.Add((Join-Path (Split-Path -Parent $PSScriptRoot) "backend"))
    }

    # Running from a cloned repo
    $repoBackend = Join-Path (Resolve-RepoRoot) "backend"
    $candidates.Add($repoBackend)

    foreach ($c in $candidates) {
        if ($c -and (Test-Path (Join-Path $c "app\main.py"))) {
            return (Resolve-Path $c).Path
        }
    }

    # Last resort: shallow search under LocalAppData\Hck*
    $searchRoots = @(
        (Join-Path $env:LOCALAPPDATA "Hck"),
        (Join-Path $env:LOCALAPPDATA "Programs")
    ) | Where-Object { $_ -and (Test-Path $_) }
    foreach ($root in $searchRoots) {
        $hit = Get-ChildItem -Path $root -Filter "main.py" -Recurse -ErrorAction SilentlyContinue -Depth 5 |
            Where-Object { $_.FullName -match '[\\/]backend[\\/]app[\\/]main\.py$' } |
            Select-Object -First 1
        if ($hit) {
            return (Resolve-Path (Split-Path -Parent (Split-Path -Parent $hit.FullName))).Path
        }
    }
    return $null
}

$repoRoot = Resolve-RepoRoot

if (-not $BackendDir) {
    if ($Portable) {
        $BackendDir = Find-InstalledBackend
    } else {
        $BackendDir = Join-Path $repoRoot "backend"
    }
}

if (-not $BackendDir -or -not (Test-Path (Join-Path $BackendDir "app\main.py"))) {
    Write-Error @"
Backend nicht gefunden$(if ($BackendDir) { " unter '$BackendDir'" }).
Erwartet app\main.py.

Tipps:
  - App einmal installieren/starten, dann dieses Script mit -Portable erneut ausführen
  - Oder: .\setup-backend.ps1 -Portable -BackendDir 'C:\Pfad\zu\Hck\backend'
  - In der Desktop-App: Button „Backend einrichten“
"@
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
if ($Portable) {
    # Non-editable: AppData venv + read-only install dir (NSIS/MSI resources)
    & $venvPython -m pip install "$BackendDir"
    if ($LASTEXITCODE -ne 0) { Write-Error "pip install fehlgeschlagen." }
} else {
    & $venvPython -m pip install -e "$BackendDir[dev]"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Editable install fehlgeschlagen — versuche normale Installation…"
        & $venvPython -m pip install "$BackendDir"
        if ($LASTEXITCODE -ne 0) { Write-Error "pip install fehlgeschlagen." }
    }
}

# Marker so the Tauri shell knows the venv is ready
$marker = Join-Path $venvDir ".hck-backend-ready"
Set-Content -Path $marker -Value "ready`nbackend=$BackendDir`n" -Encoding utf8

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
Write-Host "Marker:       $marker"
if ($Portable) {
    Write-Host "Jetzt Hck starten. Log: $env:LOCALAPPDATA\com.hck.platform\backend.log"
} else {
    Write-Host "Dev-Start:  .\scripts\windows\dev-start.ps1"
    Write-Host "Smoke:      .\scripts\windows\smoke-check.ps1"
}
