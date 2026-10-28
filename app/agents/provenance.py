"""Ingest receipts: input identity, tool versions, rules and selected options."""

from __future__ import annotations

import hashlib
import importlib.metadata
import shutil
import subprocess
from pathlib import Path

from app.agents.registry import digest


def capture_provenance(job, options):
    versions = {}
    for package in ("pyshark", "scapy", "yara-python", "cryptography"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "unavailable"
    for name in ("tshark", "zeek"):
        binary = shutil.which(name)
        if binary:
            try:
                result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=True)
                versions[name] = (result.stdout or result.stderr).splitlines()[0][:200]
            except (subprocess.SubprocessError, OSError, IndexError):
                versions[name] = "unavailable"
    path = Path(job.pcap_path)
    selected = {
        k: v
        for k, v in options.items()
        if k
        in {
            "osint_enabled",
            "llm_enabled",
            "do_pyshark",
            "do_zeek",
            "do_carve",
            "do_yara",
            "pre_count",
            "pyshark_packet_limit",
            "osint_top_n",
            "_max_wall_seconds",
        }
    }
    rule_hashes = []
    if options.get("do_yara", True):
        from app import config as C
        from app.utils.config_manager import get_config_manager

        try:
            configured = get_config_manager().load().get("cfg_yara_rules_dir")
        except (OSError, ValueError):
            configured = None
        directories = (
            [Path(configured)]
            if configured
            else [Path(__file__).resolve().parents[1] / "data" / "yara", C.DATA_DIR / "yara_rules"]
        )
        for directory in directories:
            if directory.is_dir():
                for rule in sorted(directory.rglob("*")):
                    if not rule.is_symlink() and rule.suffix.lower() in {".yar", ".yara"} and rule.is_file():
                        rule_hashes.append(hashlib.sha256(rule.read_bytes()).hexdigest())
    return {
        "schema_version": "1",
        "run_id": job.id,
        "attempt_id": job.id,
        "input_bytes": path.stat().st_size,
        "options": selected,
        "tool_versions": versions,
        "rules_sha256": digest(rule_hashes) if rule_hashes else None,
        "rules_coverage": "hashed" if rule_hashes else "none_or_unavailable",
    }
