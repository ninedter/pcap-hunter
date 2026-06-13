#!/usr/bin/env python3
"""Verify system and Python dependencies for PCAP Hunter.

Runs a pre-flight check before the app starts (or via ``make doctor``):
  - Required CLI binaries: tshark, capinfos, zeek
  - Optional CLI binaries: yara, openssl
  - Python version and key pip packages

Exits non-zero when any *required* dependency is missing so this can be
wired into CI or a pre-run hook. Missing optional deps print a warning
but do not fail the script.

Supported platforms: macOS, Linux, Windows.

Usage:
    python3 scripts/check_dependencies.py          # full check
    python3 scripts/check_dependencies.py --quiet  # only failures
    python3 scripts/check_dependencies.py --json   # machine-readable
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"


# ---------------------------------------------------------------------------
# Common install locations (matches app/utils/binary_discovery.py)
# ---------------------------------------------------------------------------


def _unix_common_paths() -> list[str]:
    return [
        "/opt/homebrew/bin",
        "/opt/local/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/Applications/Wireshark.app/Contents/MacOS",
        "/Applications/Zeek.app/Contents/MacOS",
        "/opt/zeek/bin",
        "/usr/local/zeek/bin",
    ]


def _windows_common_paths() -> list[str]:
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")
    dirs = [
        rf"{program_files}\Wireshark",
        rf"{program_files_x86}\Wireshark",
        rf"{program_files}\Zeek\bin",
        rf"{program_files}\YARA",
        rf"{program_files}\Git\usr\bin",
        r"C:\ProgramData\chocolatey\bin",
    ]
    if localappdata:
        dirs.append(rf"{localappdata}\Programs\Wireshark")
    if userprofile:
        dirs.append(rf"{userprofile}\scoop\shims")
    return dirs


COMMON_BIN_PATHS = _windows_common_paths() if IS_WINDOWS else _unix_common_paths()


# ---------------------------------------------------------------------------
# Dependency definitions
# ---------------------------------------------------------------------------


@dataclass
class BinaryCheck:
    name: str
    required: bool
    purpose: str
    install_macos: str
    install_linux: str
    install_windows: str
    version_flag: str = "--version"
    found_path: str | None = field(default=None, init=False)
    version: str | None = field(default=None, init=False)


# Note on Zeek for Windows: Zeek has no official native Windows build.
# The recommended options are WSL2 (run inside Ubuntu) or the official Docker image.
# The install hint points users in that direction.
REQUIRED_BINARIES = [
    BinaryCheck(
        name="tshark",
        required=True,
        purpose="Packet parsing (the entire pipeline depends on it)",
        install_macos="brew install wireshark",
        install_linux="sudo apt install -y tshark",
        install_windows="winget install WiresharkFoundation.Wireshark  (or: choco install wireshark)",
    ),
    BinaryCheck(
        name="capinfos",
        required=True,
        purpose="Fast packet counting (ships with tshark)",
        install_macos="brew install wireshark",
        install_linux="sudo apt install -y tshark",
        install_windows="winget install WiresharkFoundation.Wireshark  (or: choco install wireshark)",
    ),
    BinaryCheck(
        name="zeek",
        required=True,
        purpose="Protocol analysis (conn.log, dns.log, http.log, ssl.log)",
        install_macos="brew install zeek",
        install_linux="sudo apt install -y zeek",
        install_windows=(
            "Zeek has no native Windows build — use WSL2 (`wsl --install` then `sudo apt install zeek`) or Docker"
        ),
    ),
    BinaryCheck(
        name="yara",
        required=False,
        purpose="YARA rule scanning of carved files (optional)",
        install_macos="brew install yara",
        install_linux="sudo apt install -y yara",
        install_windows="choco install yara  (or: scoop install yara)",
    ),
    BinaryCheck(
        name="openssl",
        required=False,
        purpose="TLS certificate parsing fallback",
        install_macos="brew install openssl",
        install_linux="sudo apt install -y openssl",
        install_windows="Ships with Git for Windows; or: choco install openssl",
        version_flag="version",
    ),
]

# Python packages checked by name as published on PyPI (importlib.metadata
# normalizes case/dashes). Mirrors the binary pattern above: ``required=False``
# entries degrade gracefully in the app (PDF export, YARA scanning) and print
# a yellow "optional" instead of failing the check.
PYTHON_PACKAGES: list[tuple[str, bool]] = [
    # (distribution name, required)
    ("streamlit", True),
    ("pandas", True),
    ("numpy", True),
    ("pyshark", True),
    ("scapy", True),
    ("openai", True),
    ("anthropic", True),
    ("requests", True),
    ("cryptography", True),
    ("plotly", True),
    ("kaleido", True),
    ("markdown", True),
    ("jinja2", True),
    ("fastapi", True),
    ("uvicorn", True),
    ("weasyprint", False),  # PDF export — needs system pango/cairo libs
    ("yara-python", False),  # YARA scanning — needs system yara library
]


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------


def find_binary(name: str) -> str | None:
    """Return the path to *name* checking $PATH and common install dirs."""
    # shutil.which handles Windows PATHEXT (.exe, .bat, etc.) automatically
    found = shutil.which(name)
    if found:
        return found

    # Fallback: check common dirs for `name` or `name.exe` (Windows)
    candidates = [name, f"{name}.exe"] if IS_WINDOWS else [name]
    for prefix in COMMON_BIN_PATHS:
        for cand in candidates:
            candidate_path = Path(prefix) / cand
            if candidate_path.is_file():
                return str(candidate_path)
    return None


def get_version(path: str, flag: str) -> str | None:
    """Run ``path flag`` and return the first non-empty line of output."""
    try:
        proc = subprocess.run(
            [path, flag],
            capture_output=True,
            text=True,
            timeout=5,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        return out.splitlines()[0] if out else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def check_python_package(name: str) -> tuple[bool, str | None]:
    """Return (installed, version) for a pip package."""
    try:
        import importlib.metadata as md
    except ImportError:  # pragma: no cover - py<3.8
        return False, None
    try:
        return True, md.version(name)
    except md.PackageNotFoundError:
        return False, None


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def colorize(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    codes = {"green": "\033[92m", "yellow": "\033[93m", "red": "\033[91m", "reset": "\033[0m"}
    return f"{codes.get(color, '')}{text}{codes['reset']}"


def print_results_human(results: dict, use_color: bool) -> None:
    print(f"\nPCAP Hunter dependency check — {results['system']} / Python {results['python_version']}\n")

    print("System binaries:")
    for bc in results["binaries"]:
        status_text = "OK" if bc["found"] else ("MISSING" if bc["required"] else "optional")
        status_color = "green" if bc["found"] else ("red" if bc["required"] else "yellow")
        status = colorize(f"[{status_text:>8}]", status_color, use_color)
        req_mark = "*" if bc["required"] else " "
        print(f"  {status} {req_mark} {bc['name']:<10}  {bc['version'] or '-'}")
        if not bc["found"]:
            print(f"               → {bc['purpose']}")
            print(f"               → install: {bc['install_hint']}")

    print("\nPython packages:")
    for pkg in results["python_packages"]:
        required = pkg.get("required", True)
        status_text = "OK" if pkg["installed"] else ("MISSING" if required else "optional")
        status_color = "green" if pkg["installed"] else ("red" if required else "yellow")
        status = colorize(f"[{status_text:>8}]", status_color, use_color)
        req_mark = "*" if required else " "
        print(f"  {status} {req_mark} {pkg['name']:<20} {pkg['version'] or '-'}")

    print()
    if results["missing_required"]:
        count = len(results["missing_required"])
        msg = f"✗ {count} required dependency(ies) missing — PCAP Hunter will not run correctly."
        print(colorize(msg, "red", use_color))
    else:
        print(colorize("✓ All required dependencies present.", "green", use_color))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _os_key() -> str:
    system = platform.system()
    if system == "Darwin":
        return "macos"
    if system == "Windows":
        return "windows"
    return "linux"


def _install_hint(bc: BinaryCheck, os_key: str) -> str:
    return {
        "macos": bc.install_macos,
        "linux": bc.install_linux,
        "windows": bc.install_windows,
    }[os_key]


def run_checks() -> dict:
    os_key = _os_key()

    binary_results = []
    missing_required: list[str] = []

    for bc in REQUIRED_BINARIES:
        bc.found_path = find_binary(bc.name)
        if bc.found_path:
            bc.version = get_version(bc.found_path, bc.version_flag)
        binary_results.append(
            {
                "name": bc.name,
                "required": bc.required,
                "found": bc.found_path is not None,
                "path": bc.found_path,
                "version": bc.version,
                "purpose": bc.purpose,
                "install_hint": _install_hint(bc, os_key),
            }
        )
        if bc.required and not bc.found_path:
            missing_required.append(bc.name)

    pkg_results = []
    for pkg, required in PYTHON_PACKAGES:
        installed, version = check_python_package(pkg)
        pkg_results.append({"name": pkg, "required": required, "installed": installed, "version": version})
        if required and not installed:
            missing_required.append(f"python:{pkg}")

    return {
        "system": platform.system(),
        "python_version": platform.python_version(),
        "binaries": binary_results,
        "python_packages": pkg_results,
        "missing_required": missing_required,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="PCAP Hunter dependency checker")
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument("--quiet", action="store_true", help="print only the failure summary")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args()

    # Windows terminals: enable ANSI colors on Windows 10+ when available
    use_color = sys.stdout.isatty() and not args.no_color and not args.json
    if use_color and IS_WINDOWS:
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            use_color = False

    results = run_checks()

    if args.json:
        print(json.dumps(results, indent=2))
    elif args.quiet:
        if results["missing_required"]:
            print(f"Missing required: {', '.join(results['missing_required'])}", file=sys.stderr)
    else:
        print_results_human(results, use_color)

    return 1 if results["missing_required"] else 0


if __name__ == "__main__":
    sys.exit(main())
