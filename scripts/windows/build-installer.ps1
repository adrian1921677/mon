<#
.SYNOPSIS
  Builds Windows installers (NSIS and/or MSI) via Tauri on a Windows 11 host.

.DESCRIPTION
  MSI requires WiX Toolset v3 and VBSCRIPT (Windows-only).
  NSIS produces Hck_*_x64-setup.exe.
  This script refuses to run on non-Windows hosts — see docs/windows-packaging.md
  for Linux CI limits and optional NSIS cross-compile notes.

.PARAMETER Bundles
  Comma-separated: nsis, msi, or both (default: nsis,msi).
#>
[CmdletBinding()]
param(
    [ValidateSet("nsis", "msi", "nsis,msi", "msi,nsis")]
    [string]$Bundles = "nsis,msi"
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    Write-Error @"
build-installer.ps1 muss auf Windows 11 laufen.
Linux-CI kann MSI nicht erzeugen (WiX). NSIS-Cross-Compile ist möglich, aber
nicht der unterstützte Pfad — siehe docs/windows-packaging.md.
"@
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$desktopDir = Join-Path $repoRoot "apps\desktop"

Write-Host "Prüfe Toolchain…"
foreach ($cmd in @("node", "npm", "cargo", "rustc")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Fehlt: $cmd — siehe README Voraussetzungen."
    }
}

Push-Location $desktopDir
try {
    if (-not (Test-Path "node_modules")) {
        npm install --legacy-peer-deps
    }
    npm run typecheck
    if ($LASTEXITCODE -ne 0) { Write-Error "Typecheck fehlgeschlagen." }

    $bundleArgs = @()
    foreach ($b in ($Bundles -split ",")) {
        $bundleArgs += @("--bundles", $b.Trim())
    }

    Write-Host "tauri build $($bundleArgs -join ' ')…"
    npx tauri build @bundleArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "tauri build fehlgeschlagen." }

    $bundleOut = Join-Path $desktopDir "src-tauri\target\release\bundle"
    Write-Host ""
    Write-Host "Artefakte unter: $bundleOut"
    if (Test-Path $bundleOut) {
        Get-ChildItem -Recurse $bundleOut -Include *.exe,*.msi | ForEach-Object {
            Write-Host ("  " + $_.FullName)
        }
    }
    Write-Host ""
    Write-Host "Nach Installation: .\scripts\windows\setup-backend.ps1 -Portable"
} finally {
    Pop-Location
}
