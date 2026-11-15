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


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _zeek_coverage(state: Mapping[str, Any], features: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Per-log Zeek row accounting recorded by the pipeline runner.

    Looked up from an explicit ``state["zeek_coverage"]`` first, then from
    ``features["coverage"]["zeek"]`` — the latter travels with the persisted
    features, so the limitation survives every later rebuild of these metrics
    (post-OSINT, case restore) where only the 2,000-row display tables remain.
    """
    raw = state.get("zeek_coverage")
    if not isinstance(raw, Mapping):
        coverage = features.get("coverage")
        raw = coverage.get("zeek") if isinstance(coverage, Mapping) else None
    if not isinstance(raw, Mapping):
        return {}
    return {str(name): dict(entry) for name, entry in raw.items() if isinstance(entry, Mapping)}


def _coverage_limitations(
    zeek_coverage: Mapping[str, Mapping[str, Any]],
    parse_stats: Mapping[str, Any],
    osint: Any,
) -> list[str]:
    """Turn truncation / skip accounting into analyst-readable limitation strings."""
    limitations: list[str] = []

    capped = []
    sampled = []
    bad = []
    for name in sorted(zeek_coverage):
        entry = zeek_coverage[name]
        total = _as_int(entry.get("total_rows"))
        analyzed = _as_int(entry.get("analyzed_rows"))
        displayed = _as_int(entry.get("displayed_rows"))
        bad_lines = _as_int(entry.get("bad_lines"))
        if entry.get("analysis_truncated"):
            capped.append(f"{name} (first {analyzed:,} of {total:,} rows)")
        if entry.get("display_truncated"):
            sampled.append(f"{name} ({displayed:,} of {analyzed:,})")
        if bad_lines:
            bad.append(f"{name} ({bad_lines:,})")
    if capped:
        limitations.append(
            "Zeek log analysis hit the row cap, so activity late in the capture was not analyzed: "
            + ", ".join(capped)
            + "."
        )
    if sampled:
        limitations.append(
            "Stored and displayed Zeek tables are leading samples, not the full logs: "
            + ", ".join(sampled)
            + ". DNS and TLS detections were computed on the analyzed rows, not on these samples."
        )
    if bad:
        limitations.append("Malformed Zeek log lines were skipped: " + ", ".join(bad) + ".")

    skipped_lines = _as_int(parse_stats.get("skipped_lines"))
    if skipped_lines:
        limitations.append(
            f"Packet parsing skipped {skipped_lines:,} malformed tshark line(s); flow totals exclude those packets."
        )
    if parse_stats.get("timed_out"):
        limitations.append("Packet parsing hit its time limit; flows cover only the packets parsed before the timeout.")

    if isinstance(osint, Mapping):
        limits = osint.get("limits") if isinstance(osint.get("limits"), Mapping) else {}
        dom_skipped = _as_int(limits.get("domains_skipped"))
        if dom_skipped:
            limitations.append(
                f"OSINT domain enrichment was capped: {_as_int(limits.get('domains_queried')):,} of "
                f"{_as_int(limits.get('domains_total')):,} domains queried (DNS-flagged domains first)."
            )
        health = osint.get("provider_health") if isinstance(osint.get("provider_health"), Mapping) else {}
        disabled = sorted(
            str(name) for name, info in health.items() if isinstance(info, Mapping) and info.get("circuit_open")
        )
        if disabled:
            limitations.append(
                "OSINT providers stopped answering (rate limit or server errors) and were skipped for the "
                "rest of the run: " + ", ".join(disabled) + ". Their reputation data is incomplete."
            )
    return limitations


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
    zeek_coverage = _zeek_coverage(state, features)
    parse_stats = features.get("parse_stats") if isinstance(features.get("parse_stats"), Mapping) else {}
    limitations.extend(_coverage_limitations(zeek_coverage, parse_stats, state.get("osint")))

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
        "parse_skipped_lines": _as_int(parse_stats.get("skipped_lines")),
        "zeek_coverage": zeek_coverage,
        "first_seen": _iso_utc(first_seen),
        "last_seen": _iso_utc(last_seen),
        "duration_seconds": round(duration, 3) if duration is not None else None,
        "detectors": detector_status,
        "visibility_gaps": gaps,
        "pipeline_warnings": warnings,
        "limitations": limitations,
    }
