#!/usr/bin/env python3
"""Verify system and Python dependencies for PCAP Hunter.

Runs a pre-flight check before the app starts (or via ``make doctor``):
  - Required CLI binaries: tshark, capinfos, zeek
  - Optional CLI binaries: yara, openssl
  - Python version and key pip packages

Exits non-zero when any *required* dependency is missing so this can be
wired into CI or a pre-run hook. Missing optional deps print a warning
but do not fail the script.

Usage:
    python3 scripts/check_dependencies.py          # full check
    python3 scripts/check_dependencies.py --quiet  # only failures
    python3 scripts/check_dependencies.py --json   # machine-readable
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Dependency definitions
# ---------------------------------------------------------------------------

# Common install locations to check beyond $PATH (matches app/utils/binary_discovery.py)
COMMON_BIN_PATHS = [
    "/opt/homebrew/bin",
    "/opt/local/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/Applications/Wireshark.app/Contents/MacOS",
    "/Applications/Zeek.app/Contents/MacOS",
    "/opt/zeek/bin",
    "/usr/local/zeek/bin",
]


@dataclass
class BinaryCheck:
    name: str
    required: bool
    purpose: str
    install_macos: str
    install_linux: str
    version_flag: str = "--version"
    found_path: str | None = field(default=None, init=False)
    version: str | None = field(default=None, init=False)


REQUIRED_BINARIES = [
    BinaryCheck(
        name="tshark",
        required=True,
        purpose="Packet parsing (the entire pipeline depends on it)",
        install_macos="brew install wireshark",
        install_linux="sudo apt install -y tshark",
    ),
    BinaryCheck(
        name="capinfos",
        required=True,
        purpose="Fast packet counting (ships with tshark)",
        install_macos="brew install wireshark",
        install_linux="sudo apt install -y tshark",
    ),
    BinaryCheck(
        name="zeek",
        required=True,
        purpose="Protocol analysis (conn.log, dns.log, http.log, ssl.log)",
        install_macos="brew install zeek",
        install_linux="sudo apt install -y zeek",
    ),
    BinaryCheck(
        name="yara",
        required=False,
        purpose="YARA rule scanning of carved files (optional)",
        install_macos="brew install yara",
        install_linux="sudo apt install -y yara",
    ),
    BinaryCheck(
        name="openssl",
        required=False,
        purpose="TLS certificate parsing fallback",
        install_macos="brew install openssl",
        install_linux="sudo apt install -y openssl",
        version_flag="version",
    ),
]

REQUIRED_PYTHON_PACKAGES = [
    "streamlit",
    "pandas",
    "pyshark",
    "scapy",
    "openai",
    "requests",
    "cryptography",
]


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------


def find_binary(name: str) -> str | None:
    """Return the path to *name* checking $PATH and common install dirs."""
    found = shutil.which(name)
    if found:
        return found
    for prefix in COMMON_BIN_PATHS:
        candidate = Path(prefix) / name
        if candidate.is_file():
            return str(candidate)
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
        status_text = "OK" if pkg["installed"] else "MISSING"
        status_color = "green" if pkg["installed"] else "red"
        status = colorize(f"[{status_text:>8}]", status_color, use_color)
        print(f"  {status}   {pkg['name']:<20} {pkg['version'] or '-'}")

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


def run_checks() -> dict:
    system = platform.system()
    os_key = "macos" if system == "Darwin" else "linux"

    binary_results = []
    missing_required: list[str] = []

    for bc in REQUIRED_BINARIES:
        bc.found_path = find_binary(bc.name)
        if bc.found_path:
            bc.version = get_version(bc.found_path, bc.version_flag)
        hint = bc.install_macos if os_key == "macos" else bc.install_linux
        binary_results.append(
            {
                "name": bc.name,
                "required": bc.required,
                "found": bc.found_path is not None,
                "path": bc.found_path,
                "version": bc.version,
                "purpose": bc.purpose,
                "install_hint": hint,
            }
        )
        if bc.required and not bc.found_path:
            missing_required.append(bc.name)

    pkg_results = []
    for pkg in REQUIRED_PYTHON_PACKAGES:
        installed, version = check_python_package(pkg)
        pkg_results.append({"name": pkg, "installed": installed, "version": version})
        if not installed:
            missing_required.append(f"python:{pkg}")

    return {
        "system": system,
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

    use_color = sys.stdout.isatty() and not args.no_color and not args.json
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
