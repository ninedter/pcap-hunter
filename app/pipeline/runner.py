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

logger = logging.getLogger(__name__)


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

    Sequential execution only — the parallel PyShark+Zeek branch is added in Task 4c.
    Each stage is gated by its corresponding ``PipelineOptions`` flag. Failures in
    individual stages are recorded in ``result.warnings`` rather than aborting the run.
    """
    start = time.time()
    filename = pathlib.Path(pcap_path).name
    stages_run: list[str] = []
    warnings: list[str] = []

    # Working state accumulated across stages
    features: dict = {
        "flows": [],
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
    }
    zeek_tables: dict = {}
    total_pkts: int | None = None

    def _beat() -> None:
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
            warnings.append("pcap_count_unavailable")
            total_pkts = None
        if total_pkts is None:
            h.done("Count unavailable.")
            if "pcap_count_unavailable" not in warnings:
                warnings.append("pcap_count_unavailable")
        else:
            h.done(f"Found ~{total_pkts:,} packets.")
            stages_run.append("pcap_count")
        _beat()

    # --- Stage 2: PyShark parsing ---
    if options.do_pyshark:
        h = progress.start_phase("Parsing Packets")
        try:
            features = parse_pcap_pyshark(
                pcap_path,
                limit_packets=options.pyshark_packet_limit,
                phase=h,
                total_packets=total_pkts,
                progress_every=250,
            )
            stages_run.append("pyshark_pass")
            h.done("Packet parsing complete.")
        except Exception as exc:
            logger.error("PyShark failed for %s: %s", filename, exc)
            warnings.append("pyshark_failed")
            h.done("Parsing failed.")
        _beat()

    # --- Stage 3: Zeek processing ---
    if options.do_zeek:
        h = progress.start_phase("Zeek processing")
        try:
            logs = run_zeek(pcap_path, str(C.ZEEK_DIR), phase=h)
        except Exception as exc:
            logger.error("Zeek failed for %s: %s", filename, exc)
            logs = {}
            warnings.append("zeek_failed")
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
            if "zeek_failed" not in warnings:
                warnings.append("zeek_no_logs")
            h.done("Zeek produced no logs.")
        _beat()

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
            analyze_dns(zeek_tables, features, phase=h)
            stages_run.append("dns_analysis")
            h.done("DNS analysis complete.")
        except Exception as exc:
            logger.error("DNS analysis failed: %s", exc)
            warnings.append("dns_analysis_failed")
            h.done("DNS analysis failed.")
        _beat()

    # --- Stage 5: TLS Certificate Analysis (depends on Zeek) ---
    if options.do_zeek and zeek_tables:
        h = progress.start_phase("TLS Certificate Analysis")
        try:
            analyze_certificates(pcap_path=pcap_path, zeek_tables=zeek_tables, phase=h)
            stages_run.append("tls_certs")
            h.done("TLS analysis complete.")
        except Exception as exc:
            logger.error("TLS analysis failed: %s", exc)
            warnings.append("tls_certs_failed")
            h.done("TLS analysis failed.")
        _beat()

    # --- Stage 6: Beaconing ranking (uses features.flows) ---
    if features.get("flows"):
        h = progress.start_phase("Beaconing ranking")
        try:
            h.set(30, "Scoring flows…")
            beacon_df = rank_beaconing(features["flows"], top_n=20)
            if not isinstance(beacon_df, pd.DataFrame):
                beacon_df = pd.DataFrame()
            h.set(90, "Sorting top candidates…")
            stages_run.append("beacon")
            h.done("Beaconing step complete.")
        except Exception as exc:
            logger.error("Beaconing failed: %s", exc)
            warnings.append("beacon_failed")
            h.done("Beaconing failed.")
        _beat()

    # --- Stage 7: HTTP carving (sequential — parallel branch lives in Task 4c) ---
    if options.do_carve:
        h = progress.start_phase("HTTP carving (tshark)")
        try:
            carved = carve_http_payloads(pcap_path, str(C.CARVE_DIR), phase=h)
            # Backfill carved hashes into features.artifacts.hashes
            for item in carved:
                sha = item.get("sha256")
                if sha:
                    features["artifacts"]["hashes"].append(sha)
            stages_run.append("carve")
            h.done("HTTP carving complete.")
        except CarveError as exc:
            logger.error("HTTP carving failed: %s", exc)
            warnings.append("carve_failed")
            h.done("HTTP carving failed.")
        except Exception as exc:
            logger.error("HTTP carving raised unexpected error: %s", exc)
            warnings.append("carve_failed")
            h.done("HTTP carving failed.")
        _beat()

    return PipelineResult(
        case_id=case_id,
        analysis_id=None,  # caller writes the Analysis row and fills this in
        packet_count=total_pkts or 0,
        duration_seconds=time.time() - start,
        stages_run=stages_run,
        warnings=warnings,
    )
