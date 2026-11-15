# app/pipeline/runner.py
"""Headless end-to-end pipeline runner.

Public surface (importable):
    PipelineOptions   — tunable knobs for a single pipeline run
    PipelineResult    — structured output (case_id, packet_count, stages_run, warnings)
    run_pipeline()    — end-to-end execution

Both the Streamlit UI (via StreamlitProgressAdapter) and the API worker
(via CallbackProgress) drive this function. Neither this module nor the stages
it imports load streamlit at import time (``app.pipeline.state`` resolves it
lazily), so the runner is safe to call from any process — including ones where
streamlit is not installed (guarded by tests/test_pipeline_headless_import.py).

Caller responsibilities:
    * Create the Case row before calling (run_pipeline does not write to the DB).
    * Persist PipelineResult and any features/iocs returned via repository APIs.
    * Provide a Progress implementation appropriate for the calling context.

The runner is best-effort: stages that fail (e.g., LLM offline, OSINT not
configured) are recorded in ``result.warnings`` rather than raising. Hard
failures (corrupt PCAP, disk full) raise ``RuntimeError``.
"""

from __future__ import annotations

import logging
import math
import os
import pathlib
import re
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

import pandas as pd

from app import config as C
from app.analysis.visibility import build_capture_metrics
from app.pipeline.beacon import rank_beaconing
from app.pipeline.carve import CarveError, carve_http_payloads
from app.pipeline.dns_analysis import analyze_dns
from app.pipeline.pcap_count import count_packets_fast
from app.pipeline.progress import Progress
from app.pipeline.pyshark_pass import parse_pcap_pyshark
from app.pipeline.tls_certs import analyze_certificates
from app.pipeline.zeek import (
    ATTR_BAD_LINES,
    ATTR_TOTAL_ROWS,
    ATTR_TRUNCATED,
    load_zeek_any,
    merge_zeek_dns,
    run_zeek,
)
from app.threat_intel.attack_mapping import ATTACKMapper
from app.utils.string_utils import uniq_sorted

logger = logging.getLogger(__name__)

# Warning codes that may appear in PipelineResult.warnings. These are part of the
# API's wire-format contract — keep them stable.
WARNING_PCAP_COUNT_UNAVAILABLE = "pcap_count_unavailable"
WARNING_PYSHARK_FAILED = "pyshark_failed"
WARNING_PYSHARK_NO_DATA = "pyshark_no_data"
WARNING_ZEEK_FAILED = "zeek_failed"
WARNING_ZEEK_NO_LOGS = "zeek_no_logs"
# Partial-coverage warnings: the stage ran, but did not see everything.
WARNING_PYSHARK_LINES_SKIPPED = "pyshark_lines_skipped"  # malformed tshark lines dropped
WARNING_PYSHARK_TIMEOUT = "pyshark_timeout"  # PYSHARK_TIMEOUT_SECONDS hit; flows are partial
WARNING_ZEEK_ROWS_CAPPED = "zeek_rows_capped"  # a log exceeded ZEEK_ANALYSIS_MAX_ROWS
WARNING_ZEEK_BAD_LINES = "zeek_bad_lines"  # malformed Zeek log lines skipped
WARNING_DNS_ANALYSIS_FAILED = "dns_analysis_failed"
WARNING_TLS_CERTS_FAILED = "tls_certs_failed"
WARNING_BEACON_FAILED = "beacon_failed"
WARNING_CARVE_FAILED = "carve_failed"


def _derive_run_id(case_id: str) -> str:
    """Unique, path-safe directory name for one pipeline run.

    The API job queue runs up to two pipeline processes concurrently, and Zeek
    writes fixed-name logs (conn.log, dns.log, ...) into its output cwd — so
    runs must never share an output directory or they silently clobber each
    other's logs. The uuid suffix keeps concurrent and repeated runs of the
    same case distinct; sanitization keeps hostile case_ids inside the base dir.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", case_id or "")[:40].lstrip(".") or "run"
    return f"{safe}_{uuid.uuid4().hex[:8]}"


def _prune_stale_run_dirs(base_dir: pathlib.Path, max_age_seconds: float) -> None:
    """Best-effort removal of per-run subdirectories older than the retention window.

    Only directories are touched — loose files from the old flat layout are left
    alone. Errors are swallowed: pruning must never break an analysis run.
    """
    if os.getenv("PCAP_HUNTER_PRESERVE_SAVED_DATA") == "1":
        return
    try:
        entries = list(base_dir.iterdir())
    except OSError:
        return
    cutoff = time.time() - max_age_seconds
    for entry in entries:
        try:
            if entry.is_dir() and not entry.is_symlink() and entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue


@dataclass
class PipelineOptions:
    """Tunable knobs for a pipeline run."""

    osint_enabled: bool = True
    llm_enabled: bool = True
    do_pyshark: bool = True
    do_zeek: bool = True
    do_carve: bool = True
    do_yara: bool = True
    pre_count: bool = True
    # None = use C.DEFAULT_PYSHARK_LIMIT; positive int = hard cap on parsed packets;
    # 0 (or negative) = explicitly unlimited.
    pyshark_packet_limit: int | None = None
    osint_top_n: int = 50


@dataclass
class PipelineResult:
    """Structured output of a pipeline run."""

    case_id: str = ""
    analysis_id: str | None = None
    packet_count: int = 0
    duration_seconds: float = 0.0
    stages_run: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary_narrative: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    attack_mapping: dict | None = None
    capture_metrics: dict | None = None
    dns_analysis: dict = field(default_factory=dict)
    tls_analysis: dict = field(default_factory=dict)
    beacon_df_records: list[dict] = field(default_factory=list)

    # Intermediate state — available to callers (e.g. Streamlit) that need to run
    # further stages (YARA, OSINT, JA3) on top of the runner output.  Not serialized
    # by to_dict() since the API constructs its response from the fields above.
    # zeek_log_paths points at this run's private output dir (ZEEK_DIR/<run_id>) —
    # consumers must use it instead of reconstructing paths from the shared base dir.
    features: dict = field(default_factory=dict)
    zeek_tables: dict = field(default_factory=dict)
    zeek_log_paths: dict[str, str] = field(default_factory=dict)
    carved_items: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "analysis_id": self.analysis_id,
            "packet_count": self.packet_count,
            "duration_seconds": self.duration_seconds,
            "stages_run": list(self.stages_run),
            "warnings": list(self.warnings),
            "summary_narrative": self.summary_narrative,
            "mitre_techniques": list(self.mitre_techniques),
            "attack_mapping": self.attack_mapping,
            "capture_metrics": self.capture_metrics,
            "dns_analysis": dict(self.dns_analysis),
            "tls_analysis": dict(self.tls_analysis),
            "beacon_df_records": list(self.beacon_df_records),
        }


def resolve_packet_limit(value: int | None) -> int:
    """Resolve ``PipelineOptions.pyshark_packet_limit`` to the value the parser gets.

    Args:
        value: The option as supplied by the caller.

    Returns:
        ``C.DEFAULT_PYSHARK_LIMIT`` for ``None`` (or an unusable value), ``0`` —
        meaning unlimited — for zero/negative values, otherwise the value itself.
    """
    if value is None or isinstance(value, bool):
        return int(C.DEFAULT_PYSHARK_LIMIT)
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return int(C.DEFAULT_PYSHARK_LIMIT)
    return limit if limit > 0 else 0


# Zeek logs whose full tables an analyzer reads: ``analyze_dns`` and ``merge_zeek_dns``
# read dns.log, ``analyze_certificates`` reads ssl.log. Every other log is only stored
# and displayed, so it is loaded at display size and never held in memory in full.
ZEEK_ANALYZED_LOGS = frozenset({"dns.log", "ssl.log"})


def _zeek_row_accounting(full: pd.DataFrame, display: pd.DataFrame, *, analyzed_log: bool = True) -> dict:
    """Describe how much of one Zeek log was loaded, analyzed and kept for display.

    Args:
        full: The table as loaded (``df.attrs`` carries the in-file row counts).
        display: The stored/displayed sample of it.
        analyzed_log: False for a log no analyzer consumes. Such a log is loaded at
            display size only; that is sampling for display, not truncated analysis,
            so it is reported against the rows in the file and never as a row-cap hit.

    Returns:
        ``total_rows`` (rows in the file), ``loaded_rows`` (rows read into memory),
        ``analyzed_rows`` (rows available to analyzers, or the rows in the file for a
        display-only log), ``displayed_rows``, ``bad_lines`` and the truncation flags.
    """
    loaded = len(full)
    total = full.attrs.get(ATTR_TOTAL_ROWS)
    total = int(total) if isinstance(total, int) and total >= loaded else loaded
    bad_lines = int(full.attrs.get(ATTR_BAD_LINES) or 0)
    analyzed = loaded if analyzed_log else max(loaded, total - bad_lines)
    return {
        "total_rows": total,
        "loaded_rows": loaded,
        "analyzed_rows": analyzed,
        "displayed_rows": len(display),
        "bad_lines": bad_lines,
        "analysis_truncated": bool(full.attrs.get(ATTR_TRUNCATED)) if analyzed_log else False,
        "display_truncated": len(display) < analyzed,
    }


def run_pipeline(
    pcap_path: str,
    case_id: str,
    options: PipelineOptions,
    progress: Progress,
    heartbeat: Callable[[], None] | None = None,
) -> PipelineResult:
    """Run the 10-stage pipeline against ``pcap_path`` and return a structured result.

    Stages 2 (PyShark) and 3 (Zeek) run concurrently via ThreadPoolExecutor when both
    are enabled — they're I/O-bound subprocesses against the same pcap and independent
    until the merge step.  After that join, stages 4–7 (DNS, TLS, beaconing, carving)
    fan out into a second ThreadPoolExecutor — they are mutually independent, and the
    main thread assembles ``stages_run``/``warnings`` in canonical order after the join
    so the output stays deterministic.  Each stage is gated by its corresponding
    ``PipelineOptions`` flag. Failures in individual stages are recorded in
    ``result.warnings`` rather than aborting the run.
    """
    start = time.time()
    filename = pathlib.Path(pcap_path).name
    stages_run: list[str] = []
    warnings: list[str] = []

    # Per-run output dirs: concurrent jobs (API queue, max_workers=2) must never
    # share Zeek/carve output or they clobber each other's fixed-name artifacts.
    run_id = _derive_run_id(case_id)
    zeek_run_dir = C.ZEEK_DIR / run_id
    carve_run_dir = C.CARVE_DIR / run_id
    if options.do_zeek:
        _prune_stale_run_dirs(C.ZEEK_DIR, C.RUN_DIR_RETENTION_SECONDS)
    if options.do_carve:
        _prune_stale_run_dirs(C.CARVE_DIR, C.RUN_DIR_RETENTION_SECONDS)

    # Working state accumulated across stages — declared up front so analyzer
    # returns always have safe defaults even when their stage is skipped or fails.
    features: dict = {
        "flows": [],
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
    }
    # zeek_tables holds the leading ZEEK_DISPLAY_ROWS rows of each log — what is
    # returned, shown and persisted. zeek_full holds what the analyzers read (every
    # row up to ZEEK_ANALYSIS_MAX_ROWS, for the logs in ZEEK_ANALYZED_LOGS only) and
    # is released as soon as the DNS/TLS analyzers have finished.
    zeek_tables: dict = {}
    zeek_full: dict = {}
    zeek_coverage: dict[str, dict] = {}
    zeek_log_paths: dict[str, str] = {}
    packet_limit = resolve_packet_limit(options.pyshark_packet_limit)
    total_pkts: int | None = None
    dns_result: dict = {}
    tls_result: dict = {}
    beacon_records: list[dict] = []
    carved: list[dict] = []

    def _emit_heartbeat() -> None:
        if heartbeat is not None:
            heartbeat()

    # --- Stage 1: Packet counting (tshark) ---
    if options.pre_count:
        h = progress.start_phase("Packet counting (tshark)")
        h.set(5, "Counting packets…")
        try:
            total_pkts = count_packets_fast(pcap_path)
        except Exception as exc:
            logger.warning("pcap_count failed for %s: %s", filename, exc)
            total_pkts = None
        if total_pkts is None:
            warnings.append(WARNING_PCAP_COUNT_UNAVAILABLE)
            h.done("Count unavailable.")
        else:
            stages_run.append("pcap_count")
            h.done(f"Found ~{total_pkts:,} packets.")
        _emit_heartbeat()

    # --- Stages 2 & 3: PyShark + Zeek (parallel when both enabled) ---
    #
    # IMPORTANT: Phase handles must be created on the main thread because
    # Streamlit widget creation (st.progress, st.caption, etc.) requires
    # the ScriptRunContext which is only available on the main thread.
    # Worker threads receive pre-created handles and only call set()/done().
    def _run_pyshark(h) -> None:
        nonlocal features
        try:
            features = parse_pcap_pyshark(
                pcap_path,
                limit_packets=packet_limit,
                phase=h,
                total_packets=total_pkts,
                progress_every=250,
            )
            if not features.get("flows") and not any(features.get("artifacts", {}).values()):
                warnings.append(WARNING_PYSHARK_NO_DATA)
            parse_stats = features.get("parse_stats") if isinstance(features.get("parse_stats"), dict) else {}
            if parse_stats.get("timed_out"):
                logger.warning("Packet parse for %s timed out; flows are partial", filename)
                warnings.append(WARNING_PYSHARK_TIMEOUT)
            if parse_stats.get("skipped_lines"):
                logger.warning(
                    "Packet parse for %s skipped %s malformed line(s)", filename, parse_stats.get("skipped_lines")
                )
                warnings.append(WARNING_PYSHARK_LINES_SKIPPED)
            stages_run.append("pyshark_pass")
            h.done("Packet parsing complete.")
        except Exception as exc:
            logger.error("PyShark failed for %s: %s", filename, exc)
            warnings.append(WARNING_PYSHARK_FAILED)
            h.done("Parsing failed.")

    def _run_zeek(h) -> None:
        nonlocal zeek_tables
        try:
            logs = run_zeek(pcap_path, str(zeek_run_dir), phase=h)
        except Exception as exc:
            logger.error("Zeek failed for %s: %s", filename, exc)
            logs = {}
            warnings.append(WARNING_ZEEK_FAILED)
        if logs:
            zeek_log_paths.update(logs)
            row_cap = C.ZEEK_ANALYSIS_MAX_ROWS if C.ZEEK_ANALYSIS_MAX_ROWS > 0 else None
            display_rows = max(0, C.ZEEK_DISPLAY_ROWS)
            for name, log_path in logs.items():
                analyzed_log = name in ZEEK_ANALYZED_LOGS
                try:
                    # A log no analyzer reads is loaded at display size (the loader
                    # still counts every row in the file for the coverage report).
                    df = load_zeek_any(log_path, max_rows=row_cap if analyzed_log else max(1, display_rows))
                except Exception as exc:
                    logger.warning("Could not load Zeek log %s: %s", name, exc)
                    df = pd.DataFrame()
                if not isinstance(df, pd.DataFrame):
                    df = pd.DataFrame()
                # Analyzers get every loaded row; only the stored/displayed copy is sampled.
                # The sample is an independent copy so releasing the full table frees it.
                zeek_tables[name] = df.head(display_rows).copy()
                if analyzed_log:
                    zeek_full[name] = df
                zeek_coverage[name] = _zeek_row_accounting(df, zeek_tables[name], analyzed_log=analyzed_log)
                del df
            if any(entry["analysis_truncated"] for entry in zeek_coverage.values()):
                warnings.append(WARNING_ZEEK_ROWS_CAPPED)
            if any(entry["bad_lines"] for entry in zeek_coverage.values()):
                warnings.append(WARNING_ZEEK_BAD_LINES)
            stages_run.append("zeek")
            h.done("Zeek logs loaded.")
        else:
            if WARNING_ZEEK_FAILED not in warnings:
                warnings.append(WARNING_ZEEK_NO_LOGS)
            h.done("Zeek produced no logs.")

    if options.do_pyshark and options.do_zeek:
        # Create phase handles on the main thread (widget creation needs ScriptRunContext),
        # then pass them to worker threads which only update existing widgets.
        h_pyshark = progress.start_phase("Parsing Packets")
        h_zeek = progress.start_phase("Zeek processing")
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="pipeline") as pool:
            futures = [pool.submit(_run_pyshark, h_pyshark), pool.submit(_run_zeek, h_zeek)]
            for fut in as_completed(futures):
                fut.result()  # re-raises if the callable raised past our try/except
        _emit_heartbeat()
    elif options.do_pyshark:
        h_pyshark = progress.start_phase("Parsing Packets")
        _run_pyshark(h_pyshark)
        _emit_heartbeat()
    elif options.do_zeek:
        h_zeek = progress.start_phase("Zeek processing")
        _run_zeek(h_zeek)
        _emit_heartbeat()

    # Merge Zeek DNS queries into artifacts (only meaningful when both stages ran)
    if options.do_pyshark and options.do_zeek and zeek_tables:
        try:
            features = merge_zeek_dns(zeek_full, features)
        except Exception as exc:
            logger.warning("merge_zeek_dns failed: %s", exc)

    # Row accounting rides on `features` so it is persisted with the analysis and
    # every later rebuild of the capture metrics can still report partial coverage.
    if zeek_coverage and isinstance(features, dict):
        features.setdefault("coverage", {})["zeek"] = zeek_coverage

    # --- Stages 4-7: post-parse analysis fan-out ---
    # DNS + TLS read the full Zeek tables (zeek_full); beacon reads features["flows"]; carve reads only the
    # pcap. They are mutually independent, so run them concurrently. Phase handles are
    # created on the main thread (Streamlit ScriptRunContext requirement) — workers only
    # call set()/done(). Workers never mutate shared state: each writes its own key in
    # `outcomes`, and the carve hash-backfill happens after the join.
    canonical = ("dns_analysis", "tls_certs", "beacon", "carve")
    outcomes: dict[str, dict] = {}

    def _run_dns(h) -> None:
        try:
            outcomes["dns_analysis"] = {"result": analyze_dns(zeek_full, phase=h) or {}}
            h.done("DNS analysis complete.")
        except Exception as exc:
            logger.error("DNS analysis failed: %s", exc)
            outcomes.setdefault("dns_analysis", {"warning": WARNING_DNS_ANALYSIS_FAILED})
            h.done("DNS analysis failed.")

    def _run_tls(h) -> None:
        try:
            outcomes["tls_certs"] = {
                "result": analyze_certificates(pcap_path=pcap_path, zeek_tables=zeek_full, phase=h) or {}
            }
            h.done("TLS analysis complete.")
        except Exception as exc:
            logger.error("TLS analysis failed: %s", exc)
            outcomes.setdefault("tls_certs", {"warning": WARNING_TLS_CERTS_FAILED})
            h.done("TLS analysis failed.")

    def _run_beacon(h) -> None:
        try:
            h.set(30, "Scoring flows…")
            beacon_df = rank_beaconing(features["flows"], top_n=20)
            if not isinstance(beacon_df, pd.DataFrame):
                beacon_df = pd.DataFrame()
            h.set(90, "Sorting top candidates…")
            records = beacon_df.to_dict("records") if not beacon_df.empty else []
            # pkt_times/pkt_lens are analysis inputs, not outputs — keep records lean for session state
            for rec in records:
                rec.pop("pkt_times", None)
                rec.pop("pkt_lens", None)
                # Pandas fills absent metrics with NaN, which strict JSON (the agent
                # result spool, the database) rejects. "Not measured" is None.
                for key, value in rec.items():
                    if isinstance(value, float) and not math.isfinite(value):
                        rec[key] = None
            outcomes["beacon"] = {"result": records}
            h.done("Beaconing step complete.")
        except Exception as exc:
            logger.error("Beaconing failed: %s", exc)
            outcomes.setdefault("beacon", {"warning": WARNING_BEACON_FAILED})
            h.done("Beaconing failed.")

    def _run_carve(h) -> None:
        try:
            outcomes["carve"] = {"result": carve_http_payloads(pcap_path, str(carve_run_dir), phase=h)}
            h.done("HTTP carving complete.")
        except CarveError as exc:
            logger.error("HTTP carving failed: %s", exc)
            outcomes.setdefault("carve", {"warning": WARNING_CARVE_FAILED})
            h.done("HTTP carving failed.")
        except Exception as exc:
            logger.error("HTTP carving raised unexpected error: %s", exc)
            outcomes.setdefault("carve", {"warning": WARNING_CARVE_FAILED})
            h.done("HTTP carving failed.")

    jobs = []
    if options.do_zeek and zeek_tables:
        jobs.append((_run_dns, progress.start_phase("DNS Analysis")))
        jobs.append((_run_tls, progress.start_phase("TLS Certificate Analysis")))
    if features.get("flows"):
        jobs.append((_run_beacon, progress.start_phase("Beaconing ranking")))
    if options.do_carve:
        jobs.append((_run_carve, progress.start_phase("HTTP carving (tshark)")))

    if jobs:
        with ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="analysis") as pool:
            futures = [pool.submit(fn, h) for fn, h in jobs]
            try:
                for fut in as_completed(futures):
                    fut.result()
            finally:
                # The analyzers are the last readers of the full tables; drop them
                # before ATT&CK mapping, metrics and the caller's OSINT/LLM stages.
                zeek_full = {}
        _emit_heartbeat()
    zeek_full = {}

    # Assemble results in canonical order so stages_run/warnings stay deterministic.
    for name in canonical:
        out = outcomes.get(name)
        if out is None:
            continue
        if "warning" in out:
            warnings.append(out["warning"])
            continue
        stages_run.append(name)
        if name == "dns_analysis":
            dns_result = out["result"]
        elif name == "tls_certs":
            tls_result = out["result"]
        elif name == "beacon":
            beacon_records = out["result"]
        elif name == "carve":
            carved = out["result"]

    # Carve hash-backfill (moved out of the worker so no thread mutates `features`).
    if carved:
        for item in carved:
            sha = item.get("sha256")
            if sha:
                features["artifacts"]["hashes"].append(sha)
        features["artifacts"]["hashes"] = uniq_sorted(features["artifacts"]["hashes"])

    partial_mapping = ATTACKMapper().map_analysis(
        features=features,
        dns_analysis=dns_result,
        tls_analysis=tls_result,
        beacon_results=beacon_records,
    )
    capture_metrics = build_capture_metrics(
        {
            "features": features,
            "__total_pkts": total_pkts,
            "dns_analysis": dns_result,
            "tls_analysis": tls_result,
            "zeek_tables": zeek_tables,
            "zeek_coverage": zeek_coverage,
            "pipeline_warnings": warnings,
        }
    )

    return PipelineResult(
        case_id=case_id,
        analysis_id=None,  # caller writes the Analysis row and fills this in
        packet_count=total_pkts or 0,
        duration_seconds=time.time() - start,
        stages_run=stages_run,
        warnings=warnings,
        dns_analysis=dns_result,
        tls_analysis=tls_result,
        beacon_df_records=beacon_records,
        features=features,
        zeek_tables=zeek_tables,
        zeek_log_paths=zeek_log_paths,
        carved_items=carved,
        mitre_techniques=[technique.technique_id for technique in partial_mapping.techniques],
        attack_mapping=partial_mapping.to_dict(),
        capture_metrics=capture_metrics,
    )
