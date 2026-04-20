#!/usr/bin/env python3
"""Unified cross-platform installer for PCAP Hunter.

Runs the full install flow on macOS, Linux, and Windows from a single file:

    python3 scripts/install.py                # full install + dependency check
    python3 scripts/install.py --skip-system  # pip only (system deps already present)
    python3 scripts/install.py --skip-python  # system deps only
    python3 scripts/install.py --check-only   # just run the dependency checker
    python3 scripts/install.py --yes          # non-interactive (assume "yes" to prompts)
    python3 scripts/install.py --dry-run      # print commands without executing

Package manager detection order:
    macOS     → brew
    Linux     → apt-get  (extend here for dnf/pacman/zypper as needed)
    Windows   → winget → choco → scoop

Thin wrappers delegate here:
    Makefile             (make install)
    scripts/install.ps1  (Windows bootstrap)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_dependencies.py"
REQUIREMENTS = REPO_ROOT / "requirements.txt"

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------


def _color(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


# flush=True keeps output ordering predictable when stdout is piped and
# we invoke subprocesses (they'd otherwise print before our buffered prints).
def info(msg: str) -> None:
    print(_color("96", f"ℹ  {msg}"), flush=True)


def ok(msg: str) -> None:
    print(_color("92", f"✓  {msg}"), flush=True)


def warn(msg: str) -> None:
    print(_color("93", f"⚠  {msg}"), flush=True)


def fail(msg: str) -> None:
    print(_color("91", f"✗  {msg}"), flush=True)


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------


def run(cmd: list[str], *, check: bool = True, dry_run: bool = False) -> int:
    """Run *cmd*, streaming output. Returns exit code (raises if check=True)."""
    pretty = " ".join(cmd)
    info(f"$ {pretty}")
    if dry_run:
        return 0
    proc = subprocess.run(cmd, check=False)
    if check and proc.returncode != 0:
        fail(f"Command failed (exit {proc.returncode}): {pretty}")
        sys.exit(proc.returncode)
    return proc.returncode


def has(cmd: str) -> bool:
    """Return True if *cmd* is on PATH."""
    return shutil.which(cmd) is not None


# ---------------------------------------------------------------------------
# Platform-specific system installers
# ---------------------------------------------------------------------------


def install_macos(dry_run: bool) -> None:
    if not has("brew"):
        fail("Homebrew not found. Install from https://brew.sh/ and re-run.")
        sys.exit(1)

    info("Installing system dependencies via Homebrew...")
    # Only install what's missing — brew is slow
    if not has("tshark"):
        run(["brew", "install", "wireshark"], dry_run=dry_run)
    else:
        ok("tshark already installed")
    if not has("zeek"):
        run(["brew", "install", "zeek"], dry_run=dry_run)
    else:
        ok("zeek already installed")
    if not has("yara"):
        run(["brew", "install", "yara"], dry_run=dry_run)
    else:
        ok("yara already installed")
    # WeasyPrint PDF export dependencies. Pango pulls in glib + cairo as
    # deps, but we install them explicitly to avoid surprises if that ever
    # changes, and to give a clearer progress line.
    for pkg in ("pango", "glib", "cairo"):
        rc = subprocess.run(["brew", "list", pkg], capture_output=True).returncode
        if rc != 0:
            run(["brew", "install", pkg], dry_run=dry_run)
        else:
            ok(f"{pkg} already installed")


def install_linux(dry_run: bool, assume_yes: bool) -> None:
    # Only apt is supported out of the box; other package managers can be
    # added here (dnf, pacman, zypper). For now give a useful message.
    if not has("apt-get"):
        warn("Non-apt Linux detected — install tshark, zeek, yara manually.")
        warn("  Fedora:      sudo dnf install wireshark-cli zeek yara pango-devel")
        warn("  Arch:        sudo pacman -S wireshark-cli zeek yara pango")
        return

    info("Installing system dependencies via apt...")
    sudo = ["sudo"] if os.geteuid() != 0 else []
    yes = ["-y"] if assume_yes or not sys.stdin.isatty() else []
    run([*sudo, "apt-get", "update"], dry_run=dry_run)
    run(
        [
            *sudo,
            "apt-get",
            "install",
            *yes,
            "tshark",
            "zeek",
            "yara",
            "libpcap0.8",
            # WeasyPrint (PDF export) runtime deps
            "libpango-1.0-0",
            "libpangoft2-1.0-0",
            "libharfbuzz0b",
            "libcairo2",
            "libgdk-pixbuf-2.0-0",
        ],
        dry_run=dry_run,
    )


def install_windows(dry_run: bool, assume_yes: bool) -> None:
    # Try package managers in preference order: winget > choco > scoop
    installer = None
    if has("winget"):
        installer = "winget"
    elif has("choco"):
        installer = "choco"
    elif has("scoop"):
        installer = "scoop"

    if installer is None:
        fail("No Windows package manager found (winget, choco, or scoop).")
        warn("  winget:  ships with Windows 10 1809+, or https://aka.ms/getwinget")
        warn("  choco:   https://chocolatey.org/install")
        warn("  scoop:   https://scoop.sh/")
        sys.exit(1)

    info(f"Using {installer} for system installs")

    if has("tshark"):
        ok("tshark already installed")
    else:
        if installer == "winget":
            run(
                [
                    "winget",
                    "install",
                    "--id",
                    "WiresharkFoundation.Wireshark",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    "-e",
                ],
                dry_run=dry_run,
                check=False,
            )
        elif installer == "choco":
            run(["choco", "install", "wireshark", "-y", "--no-progress"], dry_run=dry_run, check=False)
        else:  # scoop
            run(["scoop", "install", "wireshark"], dry_run=dry_run, check=False)

    if has("yara"):
        ok("yara already installed")
    else:
        if installer == "choco":
            run(["choco", "install", "yara", "-y", "--no-progress"], dry_run=dry_run, check=False)
        elif installer == "scoop":
            run(["scoop", "install", "yara"], dry_run=dry_run, check=False)
        else:
            warn("winget has no YARA package; install manually with choco or scoop (optional).")

    # Zeek: no native Windows build.
    warn("Zeek has NO native Windows build. The zeek stage will be disabled.")
    warn("  For the full pipeline, use WSL2 or Docker instead:")
    warn("    WSL2:    wsl --install -d Ubuntu && re-run this installer inside Ubuntu")
    warn("    Docker:  docker compose up --build")


# ---------------------------------------------------------------------------
# Python deps
# ---------------------------------------------------------------------------


def install_python_deps(dry_run: bool) -> None:
    info("Installing Python packages from requirements.txt...")
    run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], dry_run=dry_run)
    run([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)], dry_run=dry_run)


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------


def run_dependency_check() -> int:
    info("Verifying installed dependencies...")
    return subprocess.run([sys.executable, str(CHECK_SCRIPT)]).returncode


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unified cross-platform installer for PCAP Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--skip-system", action="store_true", help="skip system binary install")
    parser.add_argument("--skip-python", action="store_true", help="skip pip install")
    parser.add_argument("--check-only", action="store_true", help="only run the dependency checker")
    parser.add_argument("--yes", "-y", action="store_true", help="non-interactive (assume yes)")
    parser.add_argument("--dry-run", action="store_true", help="print commands without executing")
    args = parser.parse_args()

    print(_color("1", "╔════════════════════════════════════════════════╗"), flush=True)
    print(_color("1", "║   PCAP Hunter — unified installer             ║"), flush=True)
    print(_color("1", f"║   platform: {sys.platform:<34} ║"), flush=True)
    print(_color("1", f"║   python:   {sys.version.split()[0]:<34} ║"), flush=True)
    print(_color("1", "╚════════════════════════════════════════════════╝"), flush=True)

    if args.check_only:
        return run_dependency_check()

    if not args.skip_system:
        if IS_MACOS:
            install_macos(args.dry_run)
        elif IS_LINUX:
            install_linux(args.dry_run, args.yes)
        elif IS_WINDOWS:
            install_windows(args.dry_run, args.yes)
        else:
            warn(f"Unknown platform '{sys.platform}' — install system deps manually.")

    if not args.skip_python:
        install_python_deps(args.dry_run)

    rc = run_dependency_check()
    print()
    if rc == 0:
        ok("Install complete. Start the app with:")
        cmd = "streamlit run app/main.py" if IS_WINDOWS else "make run"
        print(f"    {cmd}")
    else:
        fail("Install finished, but some dependencies are still missing (see above).")
    return rc


if __name__ == "__main__":
    sys.exit(main())
