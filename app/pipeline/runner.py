# app/pipeline/runner.py
"""Headless end-to-end pipeline runner.

The single shared entrypoint for running the 10-stage pipeline against a PCAP.
Both the Streamlit UI and the API worker call ``run_pipeline()``.

This file intentionally contains no Streamlit imports.
"""

from __future__ import annotations

import logging
import pathlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

import pandas as pd

from app import config as C
from app.pipeline.beacon import rank_beaconing
from app.pipeline.carve import CarveError, carve_http_payloads
from app.pipeline.dns_analysis import analyze_dns
from app.pipeline.pcap_count import count_packets_fast
from app.pipeline.progress import Progress
from app.pipeline.pyshark_pass import parse_pcap_pyshark
from app.pipeline.tls_certs import analyze_certificates
from app.pipeline.zeek import load_zeek_any, merge_zeek_dns, run_zeek
from app.utils.string_utils import uniq_sorted

logger = logging.getLogger(__name__)

# Warning codes that may appear in PipelineResult.warnings. These are part of the
# API's wire-format contract — keep them stable.
WARNING_PCAP_COUNT_UNAVAILABLE = "pcap_count_unavailable"
WARNING_PYSHARK_FAILED = "pyshark_failed"
WARNING_PYSHARK_NO_DATA = "pyshark_no_data"
WARNING_ZEEK_FAILED = "zeek_failed"
WARNING_ZEEK_NO_LOGS = "zeek_no_logs"
WARNING_DNS_ANALYSIS_FAILED = "dns_analysis_failed"
WARNING_TLS_CERTS_FAILED = "tls_certs_failed"
WARNING_BEACON_FAILED = "beacon_failed"
WARNING_CARVE_FAILED = "carve_failed"


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
    pyshark_packet_limit: int | None = None  # None = use config default; int = hard cap on parsed packets
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
    dns_analysis: dict = field(default_factory=dict)
    tls_analysis: dict = field(default_factory=dict)
    beacon_df_records: list[dict] = field(default_factory=list)

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
            "dns_analysis": dict(self.dns_analysis),
            "tls_analysis": dict(self.tls_analysis),
            "beacon_df_records": list(self.beacon_df_records),
        }


def run_pipeline(
    pcap_path: str,
    case_id: str,
    options: PipelineOptions,
    progress: Progress,
    # TODO(task-6): heartbeat plumbing is finalized in Task 6 — keep signature stable.
    heartbeat: Callable[[], None] | None = None,
) -> PipelineResult:
    """Run the 10-stage pipeline against ``pcap_path`` and return a structured result.

    Stages 2 (PyShark) and 3 (Zeek) run concurrently via ThreadPoolExecutor when both
    are enabled — they're I/O-bound subprocesses against the same pcap and independent
    until the merge step.  Each stage is gated by its corresponding ``PipelineOptions``
    flag. Failures in individual stages are recorded in ``result.warnings`` rather than
    aborting the run.
    """
    start = time.time()
    filename = pathlib.Path(pcap_path).name
    stages_run: list[str] = []
    warnings: list[str] = []

    # Working state accumulated across stages — declared up front so analyzer
    # returns always have safe defaults even when their stage is skipped or fails.
    features: dict = {
        "flows": [],
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
    }
    zeek_tables: dict = {}
    total_pkts: int | None = None
    dns_result: dict = {}
    tls_result: dict = {}
    beacon_records: list[dict] = []

    # TODO(task-6): per-stage heartbeats may be too coarse for >30s stages
    # (Zeek/PyShark on large pcaps). Task 6 owns mid-stage heartbeat injection.
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
    def _run_pyshark() -> None:
        nonlocal features
        h = progress.start_phase("Parsing Packets")
        try:
            features = parse_pcap_pyshark(
                pcap_path,
                limit_packets=options.pyshark_packet_limit,
                phase=h,
                total_packets=total_pkts,
                progress_every=250,
            )
            if not features.get("flows") and not any(features.get("artifacts", {}).values()):
                warnings.append(WARNING_PYSHARK_NO_DATA)
            stages_run.append("pyshark_pass")
            h.done("Packet parsing complete.")
        except Exception as exc:
            logger.error("PyShark failed for %s: %s", filename, exc)
            warnings.append(WARNING_PYSHARK_FAILED)
            h.done("Parsing failed.")

    def _run_zeek() -> None:
        nonlocal zeek_tables
        h = progress.start_phase("Zeek processing")
        try:
            logs = run_zeek(pcap_path, str(C.ZEEK_DIR), phase=h)
        except Exception as exc:
            logger.error("Zeek failed for %s: %s", filename, exc)
            logs = {}
            warnings.append(WARNING_ZEEK_FAILED)
        if logs:
            for name, log_path in logs.items():
                try:
                    df = load_zeek_any(log_path)
                except Exception:
                    df = pd.DataFrame()
                zeek_tables[name] = df.head(2000)
            stages_run.append("zeek")
            h.done("Zeek logs loaded.")
        else:
            if WARNING_ZEEK_FAILED not in warnings:
                warnings.append(WARNING_ZEEK_NO_LOGS)
            h.done("Zeek produced no logs.")

    if options.do_pyshark and options.do_zeek:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="pipeline") as pool:
            futures = [pool.submit(_run_pyshark), pool.submit(_run_zeek)]
            for fut in as_completed(futures):
                fut.result()  # re-raises if the callable raised past our try/except
        _emit_heartbeat()
    elif options.do_pyshark:
        _run_pyshark()
        _emit_heartbeat()
    elif options.do_zeek:
        _run_zeek()
        _emit_heartbeat()

    # Merge Zeek DNS queries into artifacts (only meaningful when both stages ran)
    if options.do_pyshark and options.do_zeek and zeek_tables:
        try:
            features = merge_zeek_dns(zeek_tables, features)
        except Exception as exc:
            logger.warning("merge_zeek_dns failed: %s", exc)

    # --- Stage 4: DNS Analysis (depends on Zeek) ---
    if options.do_zeek and zeek_tables:
        h = progress.start_phase("DNS Analysis")
        try:
            dns_result = analyze_dns(zeek_tables, features, phase=h) or {}
            stages_run.append("dns_analysis")
            h.done("DNS analysis complete.")
        except Exception as exc:
            logger.error("DNS analysis failed: %s", exc)
            warnings.append(WARNING_DNS_ANALYSIS_FAILED)
            h.done("DNS analysis failed.")
        _emit_heartbeat()

    # --- Stage 5: TLS Certificate Analysis (depends on Zeek) ---
    if options.do_zeek and zeek_tables:
        h = progress.start_phase("TLS Certificate Analysis")
        try:
            tls_result = analyze_certificates(pcap_path=pcap_path, zeek_tables=zeek_tables, phase=h) or {}
            stages_run.append("tls_certs")
            h.done("TLS analysis complete.")
        except Exception as exc:
            logger.error("TLS analysis failed: %s", exc)
            warnings.append(WARNING_TLS_CERTS_FAILED)
            h.done("TLS analysis failed.")
        _emit_heartbeat()

    # --- Stage 6: Beaconing ranking (uses features.flows) ---
    if features.get("flows"):
        h = progress.start_phase("Beaconing ranking")
        try:
            h.set(30, "Scoring flows…")
            beacon_df = rank_beaconing(features["flows"], top_n=20)
            if not isinstance(beacon_df, pd.DataFrame):
                beacon_df = pd.DataFrame()
            h.set(90, "Sorting top candidates…")
            beacon_records = beacon_df.to_dict("records") if not beacon_df.empty else []
            stages_run.append("beacon")
            h.done("Beaconing step complete.")
        except Exception as exc:
            logger.error("Beaconing failed: %s", exc)
            warnings.append(WARNING_BEACON_FAILED)
            h.done("Beaconing failed.")
        _emit_heartbeat()

    # --- Stage 7: HTTP carving ---
    if options.do_carve:
        h = progress.start_phase("HTTP carving (tshark)")
        try:
            carved = carve_http_payloads(pcap_path, str(C.CARVE_DIR), phase=h)
            # Backfill carved hashes into features.artifacts.hashes
            for item in carved:
                sha = item.get("sha256")
                if sha:
                    features["artifacts"]["hashes"].append(sha)
            features["artifacts"]["hashes"] = uniq_sorted(features["artifacts"]["hashes"])
            stages_run.append("carve")
            h.done("HTTP carving complete.")
        except CarveError as exc:
            logger.error("HTTP carving failed: %s", exc)
            warnings.append(WARNING_CARVE_FAILED)
            h.done("HTTP carving failed.")
        except Exception as exc:
            logger.error("HTTP carving raised unexpected error: %s", exc)
            warnings.append(WARNING_CARVE_FAILED)
            h.done("HTTP carving failed.")
        _emit_heartbeat()

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
    )
