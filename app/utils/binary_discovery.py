from __future__ import annotations

import functools
import os
import shutil
import sys
from pathlib import Path


@functools.lru_cache(maxsize=32)
def _which_cached(name: str) -> str | None:
    """Cached $PATH probe — PATH contents don't change within a session.

    Only the ``shutil.which`` lookup is cached; config/env overrides in
    :func:`find_bin` stay live so mid-session changes still take effect.
    """
    return shutil.which(name)


def _windows_common_paths(name: str) -> list[str]:
    """Return likely Windows install locations for *name*."""
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    localappdata = os.environ.get("LOCALAPPDATA", "")

    candidates: list[str] = []
    for ext in (".exe", ""):
        stem = f"{name}{ext}"
        candidates += [
            rf"{program_files}\Wireshark\{stem}",
            rf"{program_files_x86}\Wireshark\{stem}",
            rf"{program_files}\Zeek\bin\{stem}",
            rf"{program_files}\YARA\{stem}",
            rf"{program_files}\Git\usr\bin\{stem}",
        ]
        if localappdata:
            candidates.append(rf"{localappdata}\Programs\Wireshark\{stem}")
    # Chocolatey + Scoop shims
    candidates += [
        rf"C:\ProgramData\chocolatey\bin\{name}.exe",
        rf"C:\ProgramData\chocolatey\bin\{name}",
    ]
    if "USERPROFILE" in os.environ:
        candidates.append(rf"{os.environ['USERPROFILE']}\scoop\shims\{name}.exe")
    return candidates


def _unix_common_paths(name: str) -> list[str]:
    """Return likely macOS / Linux install locations for *name*."""
    return [
        f"/Applications/Wireshark.app/Contents/MacOS/{name}",
        f"/Applications/Zeek.app/Contents/MacOS/{name}",
        f"/opt/zeek/bin/{name}",
        f"/usr/local/zeek/bin/{name}",
        f"/opt/homebrew/bin/{name}",
        f"/opt/local/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
    ]


def find_bin(name: str, env_key: str = "", cfg_key: str = "") -> str | None:
    """
    Find a binary by name, checking (in order):
        1. Streamlit session state config (if cfg_key provided)
        2. Environment variable (if env_key provided)
        3. $PATH (via shutil.which — handles Windows PATHEXT automatically)
        4. Common install locations for the current OS
    """
    # 1. Config
    if cfg_key:
        try:
            import streamlit as st

            val = st.session_state.get(cfg_key)
            if val and Path(val).is_file():
                return val
        except ImportError:
            pass

    # 2. Env var
    if env_key:
        val = os.environ.get(env_key)
        if val and Path(val).is_file():
            return val

    # 3. PATH
    path = _which_cached(name)
    if path:
        return path

    # 4. Common locations (OS-aware)
    candidates = _windows_common_paths(name) if sys.platform == "win32" else _unix_common_paths(name)
    for p in candidates:
        if Path(p).is_file():
            return p

    return None
