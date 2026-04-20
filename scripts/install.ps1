# PCAP Hunter — Windows bootstrap
#
# This is a THIN wrapper. All install logic lives in scripts/install.py
# (unified cross-platform installer). This script only handles the one
# Windows-specific concern: bootstrapping Python itself, since install.py
# can't run without it.
#
# Usage:
#   .\scripts\install.ps1                # full install (passes through to install.py)
#   .\scripts\install.ps1 -CheckOnly     # just run the dependency checker
#   .\scripts\install.ps1 -SkipSystem    # pip only
#   .\scripts\install.ps1 -SkipPython    # system binaries only
#   .\scripts\install.ps1 -DryRun        # preview commands

param(
    [switch]$SkipSystem,
    [switch]$SkipPython,
    [switch]$CheckOnly,
    [switch]$DryRun,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"

function Write-Info ($msg) { Write-Host "ℹ  $msg" -ForegroundColor Cyan }
function Write-Ok   ($msg) { Write-Host "✓  $msg" -ForegroundColor Green }
function Write-Fail ($msg) { Write-Host "✗  $msg" -ForegroundColor Red }

function Test-CommandExists ($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# --- Bootstrap Python if missing ------------------------------------------

if (-not (Test-CommandExists python)) {
    Write-Info "Python not found on PATH."
    if (Test-CommandExists winget) {
        Write-Info "Installing Python 3.12 via winget..."
        winget install --id Python.Python.3.12 --silent `
            --accept-package-agreements --accept-source-agreements -e
        # Refresh PATH for this session
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                    [Environment]::GetEnvironmentVariable("Path", "User")
    } else {
        Write-Fail "winget not available — install Python 3.11+ from https://www.python.org/downloads/"
        exit 1
    }
}

if (-not (Test-CommandExists python)) {
    Write-Fail "Python install succeeded but `python` is still not on PATH."
    Write-Fail "Open a new PowerShell and re-run this script."
    exit 1
}

Write-Ok "python found: $(python --version 2>&1)"

# --- Delegate to the unified installer ------------------------------------

$forwarded = @()
if ($SkipSystem)  { $forwarded += "--skip-system" }
if ($SkipPython)  { $forwarded += "--skip-python" }
if ($CheckOnly)   { $forwarded += "--check-only" }
if ($DryRun)      { $forwarded += "--dry-run" }
if ($Yes)         { $forwarded += "--yes" }

$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot "scripts\install.py"

Write-Info "Handing off to: python $installer $($forwarded -join ' ')"
python $installer @forwarded
exit $LASTEXITCODE
