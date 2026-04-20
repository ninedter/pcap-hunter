# PCAP Hunter - Windows installation script
#
# Installs system dependencies (tshark/Wireshark, yara, OpenSSL) and Python
# packages on Windows 10/11. Uses winget when available, otherwise falls
# back to Chocolatey.
#
# Zeek has NO native Windows build — this script prints instructions for
# WSL2 or Docker instead.
#
# Usage (from an elevated or regular PowerShell):
#   .\scripts\install.ps1            # full install + dependency check
#   .\scripts\install.ps1 -SkipSystem # skip system binaries, pip only
#   .\scripts\install.ps1 -CheckOnly  # just run the dependency check

param(
    [switch]$SkipSystem,
    [switch]$CheckOnly,
    [switch]$NoPython
)

$ErrorActionPreference = "Stop"

function Write-Info    ($msg) { Write-Host "ℹ $msg" -ForegroundColor Cyan }
function Write-Ok      ($msg) { Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn    ($msg) { Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Fail    ($msg) { Write-Host "✗ $msg" -ForegroundColor Red }

function Test-CommandExists ($name) {
    $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Install-WithWinget ($id, $label) {
    Write-Info "Installing $label via winget ($id)..."
    winget install --id $id --silent --accept-package-agreements --accept-source-agreements `
        -e --disable-interactivity
}

function Install-WithChoco ($pkg, $label) {
    Write-Info "Installing $label via Chocolatey ($pkg)..."
    choco install $pkg -y --no-progress
}

function Install-SystemDeps {
    $useWinget = Test-CommandExists winget
    $useChoco  = Test-CommandExists choco

    if (-not $useWinget -and -not $useChoco) {
        Write-Fail "Neither winget nor Chocolatey found."
        Write-Host "  Install one of the following and re-run this script:"
        Write-Host "    winget (ships with Windows 10 1809+):  https://aka.ms/getwinget"
        Write-Host "    Chocolatey:                            https://chocolatey.org/install"
        exit 1
    }

    # tshark (via Wireshark) -------------------------------------------------
    if (Test-CommandExists tshark) {
        Write-Ok "tshark already installed: $(Get-Command tshark | Select-Object -ExpandProperty Source)"
    } else {
        if ($useWinget) {
            Install-WithWinget "WiresharkFoundation.Wireshark" "Wireshark (provides tshark)"
        } else {
            Install-WithChoco "wireshark" "Wireshark (provides tshark)"
        }
    }

    # yara (optional) --------------------------------------------------------
    if (Test-CommandExists yara) {
        Write-Ok "yara already installed: $(Get-Command yara | Select-Object -ExpandProperty Source)"
    } else {
        if ($useChoco) {
            Install-WithChoco "yara" "YARA"
        } else {
            Write-Warn "winget has no YARA package — install manually if you need YARA scanning:"
            Write-Host  "  choco install yara   (or)   scoop install yara"
        }
    }

    # Zeek: no native Windows build -----------------------------------------
    Write-Warn "Zeek has NO native Windows build. PCAP Hunter requires Zeek for protocol analysis."
    Write-Host  "  Recommended options:"
    Write-Host  "    A) WSL2 (simplest):  run ``wsl --install -d Ubuntu`` then inside Ubuntu:"
    Write-Host  "                          sudo apt update && sudo apt install -y zeek tshark yara"
    Write-Host  "                          clone and run PCAP Hunter from inside WSL."
    Write-Host  "    B) Docker:           use the bundled Dockerfile  (``docker compose up``)."
    Write-Host  ""
}

function Install-PythonDeps {
    if (-not (Test-CommandExists python)) {
        Write-Fail "python not found on PATH."
        if (Test-CommandExists winget) {
            Write-Info "Installing Python 3.12..."
            Install-WithWinget "Python.Python.3.12" "Python 3.12"
            # Refresh PATH so `python` is discoverable in this session
            $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                        [Environment]::GetEnvironmentVariable("Path", "User")
        } else {
            Write-Host "  Install Python 3.11+ from https://www.python.org/downloads/ and re-run."
            exit 1
        }
    }

    Write-Info "Upgrading pip..."
    python -m pip install --upgrade pip | Out-Null

    Write-Info "Installing Python packages from requirements.txt..."
    python -m pip install -r requirements.txt
}

function Run-DependencyCheck {
    Write-Info "Running dependency verification..."
    python scripts/check_dependencies.py
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Dependency check failed. Fix the items above and re-run."
        exit $LASTEXITCODE
    }
    Write-Ok "All required dependencies are present."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "╔════════════════════════════════════════════════╗"
Write-Host "║   PCAP Hunter — Windows install script        ║"
Write-Host "╚════════════════════════════════════════════════╝"

if ($CheckOnly) {
    Run-DependencyCheck
    exit 0
}

if (-not $SkipSystem) {
    Install-SystemDeps
}

if (-not $NoPython) {
    Install-PythonDeps
}

Run-DependencyCheck

Write-Host ""
Write-Ok "Install complete. Start the app with: streamlit run app/main.py"
