from __future__ import annotations

import json
import pathlib
import subprocess

import pandas as pd

from app import config as C
from app.pipeline.state import PhaseHandle
from app.utils.common import ensure_dir, find_bin
from app.utils.logger import log_runtime_error


def run_zeek(pcap_path: str, out_dir: str, phase: PhaseHandle | None = None) -> dict[str, str]:
    ensure_dir(pathlib.Path(out_dir))
    zeek_bin = find_bin("zeek", env_key="ZEEK_BIN", cfg_key="cfg_zeek_bin")
    if not zeek_bin:
        msg = "Zeek binary not found. Please install Zeek or set ZEEK_BIN env var."
        log_runtime_error(msg)
        raise FileNotFoundError(msg)

    if phase and phase.should_skip():
        phase.done("Zeek skipped.")
        return {}

    # Resolve to absolute path since subprocess runs with cwd=out_dir
    abs_pcap = str(pathlib.Path(pcap_path).resolve())

    cmd_json = [zeek_bin, "-C", "-r", abs_pcap, "policy/tuning/json-logs.zeek"]
    cmd_ascii = [zeek_bin, "-C", "-r", abs_pcap]

    if phase:
        phase.set(5, "Launching Zeek (JSON logs)…")
    try:
        subprocess.run(
            cmd_json,
            cwd=out_dir,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=C.ZEEK_TIMEOUT_SECONDS,
        )
        if phase:
            phase.set(60, "Zeek (JSON) completed, collecting logs…")
    except subprocess.CalledProcessError as e:
        log_runtime_error(f"Zeek JSON failed: {e.stderr}")
        if phase:
            phase.set(20, "Retrying Zeek with ASCII logs…")
        try:
            subprocess.run(
                cmd_ascii,
                cwd=out_dir,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=C.ZEEK_TIMEOUT_SECONDS,
            )
            if phase:
                phase.set(60, "Zeek (ASCII) completed, collecting logs…")
        except subprocess.CalledProcessError as e2:
            log_runtime_error(f"Zeek ASCII failed: {e2.stderr}")
            raise e2

    logs = {}
    for name in ("conn.log", "dns.log", "http.log", "ssl.log"):
        p = pathlib.Path(out_dir) / name
        if p.exists():
            logs[name] = str(p)
    if phase:
        phase.done("Zeek processing complete.")
    return logs


def _load_json_lines(path: str) -> pd.DataFrame | None:
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if s and not s.startswith("#"):
                lines.append(json.loads(s))
    return pd.DataFrame(lines) if lines else None


def _load_ascii(path: str) -> pd.DataFrame:
    cols = None
    records = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            if not ln.strip():
                continue
            if ln.startswith("#fields"):
                cols = ln.strip().split("\t")[1:]
                continue
            if ln.startswith("#"):
                continue
            parts = ln.rstrip("\n").split("\t")
            if cols and len(parts) == len(cols):
                records.append(dict(zip(cols, parts)))
    return pd.DataFrame(records)


def load_zeek_any(path: str) -> pd.DataFrame:
    try:
        df = _load_json_lines(path)
        if df is not None:
            return df
    except Exception:
        pass
    return _load_ascii(path)


def merge_zeek_dns(zeek_tables: dict, features: dict) -> dict:
    """Merge DNS queries from Zeek logs into features artifacts."""
    if not isinstance(features, dict):
        features = {"artifacts": {"domains": []}}

    if "dns.log" in zeek_tables:
        df_dns = zeek_tables["dns.log"]
        if not df_dns.empty and "query" in df_dns.columns:
            queries = df_dns["query"].dropna().unique().tolist()

            # Ensure artifacts structure exists
            if "artifacts" not in features:
                features["artifacts"] = {}
            if "domains" not in features["artifacts"]:
                features["artifacts"]["domains"] = []

            from app.utils.common import uniq_sorted

            current = list(features["artifacts"]["domains"])
            features["artifacts"]["domains"] = uniq_sorted(current + list(queries))

    return features


def extract_ja3_from_zeek_tables(zeek_logs: dict[str, str]) -> tuple:
    """
    Extract JA3 data from Zeek ssl.log.

    Args:
        zeek_logs: Dict mapping log name to file path

    Returns:
        Tuple of (DataFrame with JA3 data, analysis summary dict)
    """
    import pandas as pd

    from app.pipeline.ja3 import analyze_ja3_results, extract_ja3_from_zeek

    if "ssl.log" not in zeek_logs:
        return pd.DataFrame(), {}

    ssl_log_path = zeek_logs["ssl.log"]
    df = extract_ja3_from_zeek(ssl_log_path)
    analysis = analyze_ja3_results(df)

    return df, analysis
