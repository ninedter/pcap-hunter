"""Build the compact, UI-oriented state consumed by the production React workbench."""

from __future__ import annotations

import json
import math
import shutil
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from app import __version__
from app.database.models import Analysis, Case
from app.database.repository import CaseRepository
from app.pipeline.geoip import GeoIP
from app.pipeline.rdns_cache import get_rdns_cache
from app.utils.common import is_public_ipv4
from app.utils.config_manager import get_config_manager

_SERIES_COLORS = ["#2b8de0", "#7d46c8", "#2fac55", "#f3aa35", "#5f6f89"]


def _as_number(value: Any, default: float = 0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _flow_weight(flow: dict[str, Any]) -> int:
    return max(1, int(_as_number(flow.get("count"), 1)))


def _flow_bytes(flow: dict[str, Any]) -> int:
    packet_lengths = flow.get("pkt_lens") or []
    if packet_lengths:
        return max(0, int(sum(_as_number(value) for value in packet_lengths)))
    return _flow_weight(flow)


def _latest_case_and_analysis(repo: CaseRepository) -> tuple[Case | None, Analysis | None]:
    latest_case: Case | None = None
    latest_analysis: Analysis | None = None
    for case_summary in repo.list_cases(limit=100):
        case = repo.get_case(case_summary.id)
        if case is None:
            continue
        if latest_case is None:
            latest_case = case
        for analysis in case.analyses:
            if latest_analysis is None or analysis.analyzed_at > latest_analysis.analyzed_at:
                latest_case = case
                latest_analysis = analysis
    return latest_case, latest_analysis


def _serialize_cases(repo: CaseRepository) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for summary in repo.list_cases(limit=100):
        case = repo.get_case(summary.id)
        if case is None:
            continue
        rows.append(
            {
                "id": case.id,
                "title": case.title,
                "description": case.description,
                "status": case.status.value,
                "severity": case.severity.value,
                "tags": case.tags,
                "created_at": case.created_at.isoformat(),
                "updated_at": case.updated_at.isoformat(),
                "analysis_count": len(case.analyses),
                "ioc_count": case.ioc_count,
                "note_count": len(case.notes),
                "analyses": [
                    {
                        "id": analysis.id,
                        "name": Path(analysis.pcap_path).name,
                        "packet_count": analysis.packet_count,
                        "flow_count": len((analysis.features or {}).get("flows") or []),
                        "ioc_count": len(analysis.iocs),
                        "analyzed_at": analysis.analyzed_at.isoformat(),
                    }
                    for analysis in case.analyses
                ],
                "notes": [note.to_dict() for note in case.notes],
            }
        )
    return rows


def _serialize_jobs(repo: CaseRepository, case_titles: dict[str, str] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for job in repo.list_jobs(limit=100):
        try:
            options = json.loads(job.options_json or "{}")
        except (TypeError, json.JSONDecodeError):
            options = {}
        case_title = (case_titles or {}).get(job.case_id, "")
        display_name = options.get("display_name") or (
            case_title if case_title.lower().endswith((".pcap", ".pcapng")) else Path(job.pcap_path).name
        )
        phase_percent = int(job.progress_percent or 0)
        fractional_done = job.progress_done + (phase_percent / 100 if job.status.value == "running" else 0)
        percent = int(min(fractional_done / max(job.progress_total, 1), 1) * 100)
        rows.append(
            {
                "id": job.id,
                "case_id": job.case_id,
                "name": str(display_name),
                "status": job.status.value,
                "stage": job.progress_stage,
                "progress": percent,
                "completed_stages": job.progress_done,
                "total_stages": job.progress_total,
                "stage_progress": phase_percent,
                "stage_message": job.progress_message,
                "submitted_at": job.submitted_at.isoformat(),
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "error": job.error_detail,
            }
        )
    return rows


def _protocol_rows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(flow.get("proto") or "Unknown").upper() for flow in flows)
    return [
        {"name": name, "value": value, "color": _SERIES_COLORS[index % len(_SERIES_COLORS)]}
        for index, (name, value) in enumerate(counts.most_common())
    ]


def _flow_time_label(flow: dict[str, Any]) -> str | None:
    times = flow.get("pkt_times") or []
    timestamp = flow.get("first_ts") or (times[0] if times else None)
    if timestamp is None:
        return None
    try:
        return datetime.utcfromtimestamp(float(timestamp)).strftime("%H:%M")
    except (OSError, OverflowError, TypeError, ValueError):
        return None


def _traffic_rows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: Counter[str] = Counter()
    for flow in flows:
        if label := _flow_time_label(flow):
            buckets[label] += 1
    return [{"time": label, "flows": buckets[label]} for label in sorted(buckets)]


def _top_talkers(flows: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for flow in flows:
        if flow.get("src"):
            counts[str(flow["src"])] += _flow_bytes(flow)
    return [{"name": name, "bytes": value} for name, value in counts.most_common(limit)]


def _top_ips(flows: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for flow in flows:
        for field in ("src", "dst"):
            value = flow.get(field)
            if value:
                counts[str(value)] += _flow_weight(flow)
    return [{"name": name, "value": value} for name, value in counts.most_common(limit)]


def _sankey(flows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    edge_counts: Counter[tuple[str, str, str]] = Counter()
    for flow in flows:
        src, dst = str(flow.get("src") or ""), str(flow.get("dst") or "")
        if not src or not dst:
            continue
        proto = str(flow.get("proto") or "Unknown").upper()
        port = flow.get("dport")
        service = f"{port} / {proto}" if port not in (None, "") else proto
        edge_counts[(src, service, dst)] += _flow_weight(flow)
    top_edges = edge_counts.most_common(10)
    # Keep source, service, and destination nodes in separate layers. Reusing
    # one IP node on both sides turns bidirectional traffic into a graph cycle,
    # which the Sankey layout cannot resolve safely.
    node_keys: list[tuple[str, str]] = []
    for (src, service, dst), _ in top_edges:
        for key in (("source", src), ("service", service), ("destination", dst)):
            if key not in node_keys:
                node_keys.append(key)
    indices = {key: index for index, key in enumerate(node_keys)}
    links: list[dict[str, Any]] = []
    for (src, service, dst), value in top_edges:
        links.append({"source": indices[("source", src)], "target": indices[("service", service)], "value": value})
        links.append({"source": indices[("service", service)], "target": indices[("destination", dst)], "value": value})
    return {"nodes": [{"name": name, "layer": layer} for layer, name in node_keys], "links": links}


def _network(flows: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for flow in flows:
        for field in ("src", "dst"):
            if flow.get(field):
                counts[str(flow[field])] += _flow_weight(flow)
    top = counts.most_common(limit)
    output: list[dict[str, Any]] = []
    for index, (name, size) in enumerate(top):
        angle = 2 * math.pi * index / max(1, len(top))
        output.append(
            {
                "x": round(50 + math.cos(angle) * 36, 2),
                "y": round(50 + math.sin(angle) * 36, 2),
                "size": size,
                "name": name,
                "private": not is_public_ipv4(name),
            }
        )
    return output


def _map_flows(flows: list[dict[str, Any]], osint: dict[str, Any], limit: int = 50) -> list[dict[str, Any]]:
    aggregate: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "protocols": set(),
            "traffic_slices": defaultdict(lambda: {"packets": 0, "bytes": 0}),
        }
    )
    for flow in flows:
        protocol = str(flow.get("proto") or "Unknown").upper()
        time_label = _flow_time_label(flow)
        flow_packets = _flow_weight(flow)
        flow_bytes = _flow_bytes(flow)
        for field in ("src", "dst"):
            ip = flow.get(field)
            if not ip or not is_public_ipv4(str(ip)):
                continue
            row = aggregate[str(ip)]
            row["packets"] += flow_packets
            row["bytes"] += flow_bytes
            row["protocols"].add(protocol)
            if time_label:
                traffic_slice = row["traffic_slices"][(protocol, time_label)]
                traffic_slice["packets"] += flow_packets
                traffic_slice["bytes"] += flow_bytes

    output: list[dict[str, Any]] = []
    for ip, row in sorted(aggregate.items(), key=lambda item: item[1]["packets"], reverse=True):
        location = GeoIP.lookup(ip)
        if not location:
            continue
        reputation = (osint or {}).get("ips", {}).get(ip, {})
        score = max(
            _as_number(reputation.get("score")),
            _as_number(reputation.get("abuseConfidenceScore")) / 100,
        )
        status = "Review" if score >= 0.35 else "Expected"
        byte_count = int(row["bytes"])
        byte_label = (
            f"{byte_count / 1_048_576:.1f} MB" if byte_count >= 1_048_576 else f"{max(1, byte_count // 1024)} KB"
        )
        output.append(
            {
                "ip": ip,
                "city": location.get("city") or "Unknown",
                "country": location.get("country") or "Unknown",
                "continent": location.get("continent") or "Unknown",
                "coordinates": [location["lon"], location["lat"]],
                "packets": int(row["packets"]),
                "byte_count": byte_count,
                "bytes": byte_label,
                "protocols": sorted(row["protocols"]),
                "traffic_slices": [
                    {
                        "protocol": protocol,
                        "time": time_label,
                        "packets": int(values["packets"]),
                        "bytes": int(values["bytes"]),
                    }
                    for (protocol, time_label), values in sorted(row["traffic_slices"].items())
                ],
                "status": status,
                "color": "#ffbd59" if status == "Review" else "#47a8ff",
            }
        )
        if len(output) >= limit:
            break
    return output


def _analysis_rdns_map(analysis: Analysis) -> dict[str, str]:
    """Combine persisted PTR data with still-valid cached resolutions."""
    artifacts = analysis.session_artifacts or {}
    rdns_map: dict[str, str] = {}
    for ip, hostname in (artifacts.get("rdns_map") or {}).items():
        cleaned = str(hostname or "").strip().rstrip(".")
        if ip and cleaned:
            rdns_map[str(ip)] = cleaned
    for ip, details in ((analysis.osint or {}).get("ips") or {}).items():
        if isinstance(details, dict) and details.get("ptr"):
            cleaned = str(details["ptr"]).strip().rstrip(".")
            if cleaned:
                rdns_map.setdefault(str(ip), cleaned)

    candidates = {
        str(ioc.value) for ioc in analysis.iocs if ioc.ioc_type.value == "ip" and is_public_ipv4(str(ioc.value))
    }
    candidates.update(
        str(ip) for ip in ((analysis.features or {}).get("artifacts") or {}).get("ips") or [] if is_public_ipv4(str(ip))
    )
    missing = sorted(candidates.difference(rdns_map))
    if missing:
        try:
            for ip, hostname in get_rdns_cache().get_batch(missing).items():
                cleaned = str(hostname or "").strip().rstrip(".")
                if cleaned:
                    rdns_map[ip] = cleaned
        except Exception:
            pass
    return rdns_map


def _evidence_rows(analysis: Analysis | None) -> list[dict[str, Any]]:
    if analysis is None:
        return []
    source = Path(analysis.pcap_path).name
    rdns_map = _analysis_rdns_map(analysis)
    if analysis.iocs:
        return [
            {
                "value": ioc.value,
                "hostname": rdns_map.get(str(ioc.value)),
                "type": ioc.ioc_type.value.upper() if ioc.ioc_type.value != "domain" else "Domain",
                "context": ioc.context or "Observed in capture",
                "status": ioc.severity.value.title(),
                "source": source,
            }
            for ioc in analysis.iocs[:100]
        ]

    artifacts = (analysis.features or {}).get("artifacts") or {}
    rows: list[dict[str, Any]] = []
    labels = {"ips": "IP", "domains": "Domain", "hashes": "Hash", "ja3": "JA3", "urls": "URL"}
    for key, label in labels.items():
        for value in artifacts.get(key) or []:
            rows.append(
                {
                    "value": str(value),
                    "hostname": rdns_map.get(str(value)) if label == "IP" else None,
                    "type": label,
                    "context": "Observed in capture",
                    "status": "Observed",
                    "source": source,
                }
            )
    return rows[:100]


def _raw_flow_rows(flows: list[dict[str, Any]], limit: int = 250) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for flow in flows[:limit]:
        times = flow.get("pkt_times") or []
        timestamp = flow.get("first_ts") or (times[0] if times else None)
        try:
            first_seen = datetime.utcfromtimestamp(float(timestamp)).strftime("%H:%M:%S")
        except (OSError, OverflowError, TypeError, ValueError):
            first_seen = "—"
        proto = str(flow.get("proto") or "Unknown").upper()
        dport = flow.get("dport")
        rows.append(
            {
                "first_seen": first_seen,
                "source": str(flow.get("src") or "—"),
                "destination": str(flow.get("dst") or "—"),
                "protocol": f"{proto}/{dport}" if dport not in (None, "") else proto,
                "packets": _flow_weight(flow),
                "bytes": _flow_bytes(flow),
            }
        )
    return rows


def _osint_rows(analysis: Analysis | None) -> list[dict[str, Any]]:
    if analysis is None:
        return []
    rows: list[dict[str, Any]] = []
    for value, details in ((analysis.osint or {}).get("ips") or {}).items():
        details = details if isinstance(details, dict) else {}
        rows.append(
            {
                "value": str(value),
                "hostname": str(details.get("ptr") or "").strip().rstrip(".") or None,
                "kind": "IP",
                "verdict": details.get("verdict") or details.get("classification") or "Observed",
                "organization": details.get("organization") or details.get("asn") or "No organization data",
                "score": _as_number(details.get("score")),
            }
        )
    return rows[:100]


def _histogram(values: list[float], buckets: int = 8) -> list[dict[str, int | str]]:
    if not values:
        return []
    low, high = min(values), max(values)
    if high <= low:
        return [{"bucket": str(round(low, 2)), "count": len(values)}]
    width = (high - low) / buckets
    counts = [0] * buckets
    for value in values:
        index = min(buckets - 1, int((value - low) / width))
        counts[index] += 1
    return [{"bucket": str(round(low + index * width, 2)), "count": count} for index, count in enumerate(counts)]


def _dashboard_state(analysis: Analysis | None) -> dict[str, Any]:
    config = get_config_manager().load()
    home = {
        "lat": _as_number(config.get("cfg_home_lat"), 0),
        "lon": _as_number(config.get("cfg_home_lon"), 0),
        "city": config.get("cfg_home_city") or "Home",
        "country": config.get("cfg_home_country") or "",
        "continent": config.get("cfg_home_continent") or "",
    }
    if analysis is None:
        return {
            "risk": "N/A",
            "packets": 0,
            "flows": 0,
            "alerts": 0,
            "beacons": 0,
            "yara_issues": 0,
            "cert_issues": 0,
            "protocols": [],
            "traffic": [],
            "top_talkers": [],
            "top_ips": [],
            "top_domains": [],
            "map_flows": [],
            "evidence": [],
            "packet_sizes": [],
            "inter_arrivals": [],
            "heatmap": [],
            "sankey": {"nodes": [], "links": []},
            "network": [],
            "attack_timeline": [],
            "report": "",
            "stages": [],
            "warnings": [],
            "raw_flows": [],
            "attack_mapping": {},
            "osint_rows": [],
            "dns_analysis": {},
            "tls_analysis": {},
            "yara_results": {},
            "home": home,
        }

    features = analysis.features or {}
    flows = features.get("flows") or []
    artifacts = analysis.session_artifacts or {}
    beacon_rows = artifacts.get("beacon_records") or features.get("beacon_records") or []
    beacons = sum(1 for row in beacon_rows if _as_number(row.get("score")) >= 0.6)
    yara = analysis.yara_results or {}
    yara_issues = int(_as_number(yara.get("matched"), 0))
    tls = analysis.tls_analysis or {}
    cert_issues = int(_as_number(tls.get("self_signed"), 0) + _as_number(tls.get("expired"), 0))
    evidence = _evidence_rows(analysis)
    alerts = sum(1 for item in evidence if str(item.get("status", "")).lower() in {"high", "critical"})
    risk = "HIGH" if alerts or yara_issues else "MEDIUM" if beacons >= 3 or cert_issues else "LOW"

    packet_lengths: list[float] = []
    inter_arrivals: list[float] = []
    heatmap_buckets = [0] * 48
    timestamps: list[float] = []
    for flow in flows:
        packet_lengths.extend(_as_number(value) for value in flow.get("pkt_lens") or [])
        times = sorted(_as_number(value) for value in flow.get("pkt_times") or [])
        timestamps.extend(times)
        inter_arrivals.extend(max(0, b - a) for a, b in zip(times, times[1:]))
    if timestamps:
        start, end = min(timestamps), max(timestamps)
        span = max(1, end - start)
        for timestamp in timestamps:
            heatmap_buckets[min(47, int((timestamp - start) / span * 48))] += 1
        peak = max(heatmap_buckets) or 1
        heatmap = [min(5, math.ceil(value / peak * 5)) for value in heatmap_buckets]
    else:
        heatmap = []

    domains = Counter(str(value) for value in (features.get("artifacts") or {}).get("domains") or [])
    return {
        "risk": risk,
        "packets": analysis.packet_count,
        "flows": len(flows),
        "alerts": alerts,
        "beacons": beacons,
        "yara_issues": yara_issues,
        "cert_issues": cert_issues,
        "protocols": _protocol_rows(flows),
        "traffic": _traffic_rows(flows),
        "top_talkers": _top_talkers(flows),
        "top_ips": _top_ips(flows),
        "top_domains": [{"name": name, "value": value} for name, value in domains.most_common(10)],
        "map_flows": _map_flows(flows, analysis.osint or {}),
        "evidence": evidence,
        "packet_sizes": _histogram(packet_lengths),
        "inter_arrivals": _histogram(inter_arrivals, buckets=6),
        "heatmap": heatmap,
        "sankey": _sankey(flows),
        "network": _network(flows),
        "attack_timeline": [],
        "report": analysis.report or "",
        "stages": artifacts.get("pipeline_stages") or [],
        "warnings": artifacts.get("pipeline_warnings") or [],
        "raw_flows": _raw_flow_rows(flows),
        "attack_mapping": analysis.attack_mapping or {},
        "osint_rows": _osint_rows(analysis),
        "dns_analysis": analysis.dns_analysis or {},
        "tls_analysis": analysis.tls_analysis or {},
        "yara_results": analysis.yara_results or {},
        "home": home,
    }


def public_config() -> dict[str, Any]:
    """Return saved configuration without exposing provider secrets to the browser."""
    config = get_config_manager().load()
    sensitive = {
        "cfg_vt_key",
        "cfg_greynoise_key",
        "cfg_shodan_key",
        "cfg_abuseipdb_key",
        "cfg_otx_key",
        "cfg_openai_key",
        "cfg_openai_cloud_key",
        "cfg_anthropic_key",
    }
    result = {key: value for key, value in config.items() if key not in sensitive}
    result["configured_providers"] = {key: bool(config.get(key)) for key in sensitive}
    return result


def build_workbench_state(repo: CaseRepository) -> dict[str, Any]:
    """Create the single bootstrap payload used by the production workbench."""
    latest_case, latest_analysis = _latest_case_and_analysis(repo)
    cases = _serialize_cases(repo)
    jobs = _serialize_jobs(repo, {row["id"]: row["title"] for row in cases})
    dashboard = _dashboard_state(latest_analysis)
    tools = [
        {"name": "tshark", "ready": bool(shutil.which("tshark"))},
        {"name": "Zeek", "ready": bool(shutil.which("zeek"))},
        {"name": "worker", "ready": True},
    ]
    return {
        "version": __version__,
        "capture_count": len(latest_case.analyses) if latest_case else 0,
        "analysis_complete": latest_analysis is not None,
        "active_case_id": latest_case.id if latest_case else None,
        "active_case_title": latest_case.title if latest_case else None,
        "active_analysis_id": latest_analysis.id if latest_analysis else None,
        "dashboard": dashboard,
        "cases": cases,
        "jobs": jobs,
        "config": public_config(),
        "system": {"healthy": all(tool["ready"] for tool in tools), "tools": tools},
    }
