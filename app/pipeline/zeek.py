from __future__ import annotations

import json
import logging
import pathlib
import subprocess

import pandas as pd

from app import config as C
from app.pipeline.progress import PhaseHandle
from app.utils.common import ensure_dir, find_bin
from app.utils.logger import log_runtime_error

logger = logging.getLogger(__name__)

# The logs every consumer has always been able to rely on; ZEEK_LOG_NAMES in config
# extends this with optional extras (files / notice / weird / x509).
CORE_ZEEK_LOGS = ("conn.log", "dns.log", "http.log", "ssl.log")

# DataFrame.attrs keys set by load_zeek_any() describing how complete the load was.
ATTR_TOTAL_ROWS = "zeek_total_rows"  # data rows present in the log file
ATTR_BAD_LINES = "zeek_bad_lines"  # malformed lines skipped
ATTR_TRUNCATED = "zeek_truncated"  # True when max_rows stopped the load early


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
    for name in dict.fromkeys((*CORE_ZEEK_LOGS, *C.ZEEK_LOG_NAMES)):
        p = pathlib.Path(out_dir) / name
        if p.exists():
            logs[name] = str(p)
    if phase:
        phase.done("Zeek processing complete.")
    return logs


def _load_json_lines(path: str, max_rows: int | None = None) -> tuple[list[dict], int, int]:
    """Parse a Zeek JSON-lines log, tolerating individual malformed lines.

    Args:
        path: Log file path.
        max_rows: Stop materialising records after this many (remaining lines are
            still counted so the caller can report what was left out). None = all.

    Returns:
        ``(records, total_rows, bad_lines)`` where ``total_rows`` counts every
        non-comment, non-blank data line, including skipped and uncollected ones.
    """
    records: list[dict] = []
    total = 0
    bad = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            total += 1
            if max_rows is not None and len(records) >= max_rows:
                continue  # over the cap: count only
            try:
                obj = json.loads(s)
            except ValueError:
                bad += 1
                continue
            if not isinstance(obj, dict):
                bad += 1
                continue
            records.append(obj)
    return records, total, bad


def _load_ascii(path: str, max_rows: int | None = None) -> pd.DataFrame:
    """Parse a Zeek TSV (ASCII) log; rows whose column count is wrong are skipped and counted."""
    cols = None
    records = []
    total = 0
    bad = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            if not ln.strip():
                continue
            if ln.startswith("#fields"):
                cols = ln.strip().split("\t")[1:]
                continue
            if ln.startswith("#"):
                continue
            total += 1
            if max_rows is not None and len(records) >= max_rows:
                continue  # over the cap: count only
            parts = ln.rstrip("\n").split("\t")
            if cols and len(parts) == len(cols):
                records.append(dict(zip(cols, parts)))
            else:
                bad += 1
    df = pd.DataFrame(records)
    _stamp(df, total, bad, max_rows)
    return df


def _stamp(df: pd.DataFrame, total: int, bad: int, max_rows: int | None) -> None:
    """Record load-completeness metadata on ``df.attrs``."""
    df.attrs[ATTR_TOTAL_ROWS] = total
    df.attrs[ATTR_BAD_LINES] = bad
    df.attrs[ATTR_TRUNCATED] = bool(max_rows is not None and total - bad > len(df))


def _looks_like_json_log(path: str) -> bool:
    """Tell JSON-lines logs from Zeek TSV logs.

    TSV logs always open with ``#separator`` / ``#fields`` header lines; JSON logs
    have no header. Deciding on the header (not on whether the first record parses)
    keeps a JSON log with a corrupt first line on the JSON path.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for ln in f:
                s = ln.strip()
                if s:
                    return not s.startswith("#")
    except OSError:
        return False
    return False


def load_zeek_any(path: str, max_rows: int | None = None) -> pd.DataFrame:
    """Load a Zeek log (JSON-lines or TSV) into a DataFrame.

    A malformed line no longer discards the whole log: it is skipped, counted, and
    reported in a warning, and every other record is kept.

    Args:
        path: Log file path.
        max_rows: Optional memory guard — keep at most this many records. None
            (default) loads everything, as before.

    Returns:
        DataFrame of records. ``df.attrs`` carries ``zeek_total_rows``,
        ``zeek_bad_lines`` and ``zeek_truncated`` so callers can report partial
        coverage.
    """
    if max_rows is not None and max_rows <= 0:
        max_rows = None

    if _looks_like_json_log(path):
        records, total, bad = _load_json_lines(path, max_rows)
        df = pd.DataFrame(records)
        _stamp(df, total, bad, max_rows)
    else:
        df = _load_ascii(path, max_rows)
        bad = int(df.attrs.get(ATTR_BAD_LINES, 0))
        total = int(df.attrs.get(ATTR_TOTAL_ROWS, 0))

    name = pathlib.Path(path).name
    if bad:
        logger.warning("Zeek log %s: skipped %d malformed line(s) of %d; kept the rest", name, bad, total)
    if df.attrs.get(ATTR_TRUNCATED):
        logger.warning("Zeek log %s: loaded %d of %d rows (row cap %s)", name, len(df), total, max_rows)
    return df


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
