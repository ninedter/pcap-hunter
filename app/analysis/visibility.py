"""Capture quality and detector-visibility metrics.

PCAP analysis is only as trustworthy as the telemetry that made it through the
capture and pipeline.  These helpers turn the available flow/stage metadata
into explicit, serializable metrics for the analyst workspace and case record.
They intentionally distinguish an observed zero from an unavailable detector.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _flow_bounds(flow: Mapping[str, Any]) -> tuple[float | None, float | None]:
    first = _as_float(flow.get("first_ts"))
    last = _as_float(flow.get("last_ts"))
    samples = flow.get("pkt_times") or []
    if first is None and samples:
        sample_values = [value for item in samples if (value := _as_float(item)) is not None]
        first = min(sample_values, default=None)
    if last is None and samples:
        sample_values = [value for item in samples if (value := _as_float(item)) is not None]
        last = max(sample_values, default=None)
    return first, last


def _iso_utc(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def build_capture_metrics(state: Mapping[str, Any]) -> dict[str, Any]:
    """Build quality, scale, and visibility metrics from an analysis state."""
    features = state.get("features") if isinstance(state.get("features"), dict) else {}
    flows = features.get("flows") or []
    flows = [flow for flow in flows if isinstance(flow, Mapping)]
    artifacts = features.get("artifacts") or {}

    packet_count = state.get("__total_pkts")
    try:
        packet_count = int(packet_count) if packet_count is not None else 0
    except (TypeError, ValueError):
        packet_count = 0

    parsed_packets = sum(int(flow.get("count") or 0) for flow in flows)
    total_bytes = sum(int(flow.get("bytes") or 0) for flow in flows)
    sources = {str(flow.get("src")) for flow in flows if flow.get("src")}
    destinations = {str(flow.get("dst")) for flow in flows if flow.get("dst")}
    protocols = {str(flow.get("proto")) for flow in flows if flow.get("proto")}
    flow_bounds = [_flow_bounds(flow) for flow in flows]
    first_values = [first for first, _ in flow_bounds if first is not None]
    last_values = [last for _, last in flow_bounds if last is not None]
    first_seen = min(first_values, default=None)
    last_seen = max(last_values, default=None)
    duration = max(0.0, last_seen - first_seen) if first_seen is not None and last_seen is not None else None

    sampled_flows = sum(1 for flow in flows if int(flow.get("count") or 0) > len(flow.get("pkt_times") or []))
    parse_ratio = parsed_packets / packet_count if packet_count > 0 else None
    detector_status = {
        "packet_flow": "available" if isinstance(state.get("features"), dict) else "unavailable",
        "zeek": "available" if state.get("zeek_tables") else "unavailable",
        "dns": "available"
        if state.get("dns_analysis") and not state.get("dns_analysis", {}).get("error")
        else "partial",
        "tls": "available"
        if state.get("tls_analysis") and not state.get("tls_analysis", {}).get("error")
        else "partial",
        "yara": "available" if isinstance(state.get("yara_results"), dict) else "unavailable",
        "osint": "available" if state.get("osint") else "unavailable",
        "correlation": "available" if isinstance(state.get("correlations"), list) else "unavailable",
    }
    warnings = [str(value) for value in (state.get("pipeline_warnings") or [])]
    gaps = [name for name, status in detector_status.items() if status in {"partial", "unavailable"}]
    limitations: list[str] = []
    if packet_count and parsed_packets < packet_count:
        limitations.append(
            "Parsed packet count is below the capture count; packet parsing may be capped or incomplete."
        )
    if sampled_flows:
        limitations.append(
            "Per-flow packet samples are capped; flow totals and first/last timestamps remain authoritative."
        )
    if warnings:
        limitations.append("One or more pipeline stages reported warnings: " + ", ".join(warnings[:5]))
    if not state.get("zeek_tables"):
        limitations.append("Zeek protocol logs are unavailable, so application-layer visibility is reduced.")

    return {
        "packet_count": packet_count,
        "parsed_packet_count": parsed_packets,
        "parse_ratio": round(parse_ratio, 4) if parse_ratio is not None else None,
        "flow_count": len(flows),
        "total_bytes": total_bytes,
        "unique_sources": len(sources),
        "unique_destinations": len(destinations),
        "unique_protocols": len(protocols),
        "unique_ips": len(artifacts.get("ips") or []),
        "unique_domains": len(artifacts.get("domains") or []),
        "sampled_flow_count": sampled_flows,
        "first_seen": _iso_utc(first_seen),
        "last_seen": _iso_utc(last_seen),
        "duration_seconds": round(duration, 3) if duration is not None else None,
        "detectors": detector_status,
        "visibility_gaps": gaps,
        "pipeline_warnings": warnings,
        "limitations": limitations,
    }
