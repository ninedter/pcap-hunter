"""Build the compact, UI-oriented state consumed by the production React workbench."""

from __future__ import annotations

import ipaddress
import json
import math
import os
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
_TRAFFIC_REPLAY_MAX_EVENTS = 2_000


def _as_number(value: Any, default: float = 0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _flow_weight(flow: dict[str, Any]) -> int:
    return max(1, int(_as_number(flow.get("count"), 1)))


def _sample_sequence(value: Any) -> list[Any] | tuple[Any, ...]:
    return value if isinstance(value, (list, tuple)) else []


def _flow_bytes(flow: dict[str, Any]) -> int:
    scalar_bytes = _nonnegative_int(flow.get("bytes"))
    if scalar_bytes is not None:
        return scalar_bytes
    packet_lengths = _sample_sequence(flow.get("pkt_lens"))
    if packet_lengths:
        return max(0, int(sum(_as_number(value) for value in packet_lengths)))
    return _flow_weight(flow)


def _nonnegative_int(value: Any) -> int | None:
    number = _as_number(value, default=float("nan"))
    if not math.isfinite(number) or number < 0:
        return None
    return int(number)


def _finite_timestamp(value: Any) -> float | None:
    number = _as_number(value, default=float("nan"))
    return number if math.isfinite(number) else None


def _metric_timestamp(value: Any) -> float | None:
    timestamp = _finite_timestamp(value)
    if timestamp is not None:
        return timestamp
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
    return timestamp if math.isfinite(timestamp) else None


def _flow_packet_count(flow: dict[str, Any]) -> int:
    return _nonnegative_int(flow.get("count")) or 0


def _flow_stat_bytes(flow: dict[str, Any]) -> tuple[int | None, bool]:
    """Return bytes for analyst statistics and whether the flow is complete."""
    scalar_bytes = _nonnegative_int(flow.get("bytes"))
    if scalar_bytes is not None:
        return scalar_bytes, True
    lengths = _sample_sequence(flow.get("pkt_lens"))
    valid_lengths = [_nonnegative_int(value) for value in lengths]
    if lengths and all(value is not None for value in valid_lengths):
        measured = sum(value for value in valid_lengths if value is not None)
        # Packet samples are useful measurements but do not establish that the
        # persisted flow-byte total is complete, even when their count matches.
        return measured, False
    return None, False


def _ip_scope(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return "special"
    if address.is_multicast or address.is_unspecified:
        return "special"
    if address.is_loopback or address.is_link_local:
        return "internal"
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network("10.0.0.0/8"):
        return "internal"
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network("172.16.0.0/12"):
        return "internal"
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network("192.168.0.0/16"):
        return "internal"
    if isinstance(address, ipaddress.IPv6Address) and address in ipaddress.ip_network("fc00::/7"):
        return "internal"
    if address.is_reserved:
        return "special"
    return "external" if address.is_global else "special"


def _canonical_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _capture_file_bytes(path: str) -> int | None:
    try:
        capture_path = Path(path)
        if not path or not capture_path.is_file():
            return None
        return capture_path.stat().st_size
    except (OSError, TypeError, ValueError):
        return None


def _capture_summary(analysis: Analysis, flows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = analysis.capture_metrics or {}
    analysis_packet_count = _nonnegative_int(analysis.packet_count) or 0
    metrics_packet_count = _nonnegative_int(metrics.get("packet_count")) or 0
    packet_count = analysis_packet_count if analysis_packet_count > 0 else metrics_packet_count
    parsed_packet_count = sum(_flow_packet_count(flow) for flow in flows)
    byte_rows = [_flow_stat_bytes(flow) for flow in flows]
    measured_bytes = [value for value, _ in byte_rows if value is not None]
    parsed_traffic_bytes = sum(measured_bytes)
    all_flow_bytes_complete = bool(flows) and all(complete for _, complete in byte_rows)
    packets_complete = packet_count > 0 and parsed_packet_count == packet_count
    if measured_bytes and all_flow_bytes_complete and packets_complete:
        byte_coverage = "complete"
    elif measured_bytes:
        byte_coverage = "partial"
    else:
        byte_coverage = "unknown"
    first_seen = _metric_timestamp(metrics.get("first_seen"))
    last_seen = _metric_timestamp(metrics.get("last_seen"))
    sample_timestamps = [
        timestamp
        for flow in flows
        for timestamp in (_finite_timestamp(value) for value in _sample_sequence(flow.get("pkt_times")))
        if timestamp is not None
    ]
    if first_seen is None or last_seen is None:
        first_candidates = [_finite_timestamp(flow.get("first_ts")) for flow in flows]
        last_candidates = [_finite_timestamp(flow.get("last_ts")) for flow in flows]
        first_seen = (
            first_seen
            if first_seen is not None
            else min((value for value in first_candidates if value is not None), default=None)
        )
        last_seen = (
            last_seen
            if last_seen is not None
            else max((value for value in last_candidates if value is not None), default=None)
        )
    if (first_seen is None or last_seen is None) and sample_timestamps:
        first_seen = first_seen if first_seen is not None else min(sample_timestamps)
        last_seen = last_seen if last_seen is not None else max(sample_timestamps)
    return {
        "packet_count": packet_count,
        "flow_count": len(flows),
        "endpoint_count": len(
            {
                canonical
                for flow in flows
                for field in ("src", "dst")
                if (canonical := _canonical_ip(flow.get(field))) is not None
            }
        ),
        "parsed_traffic_bytes": parsed_traffic_bytes,
        "parsed_packet_count": parsed_packet_count,
        "capture_file_bytes": _capture_file_bytes(analysis.pcap_path),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": (
            round(max(0, last_seen - first_seen), 3) if first_seen is not None and last_seen is not None else None
        ),
        "byte_coverage": byte_coverage,
    }


def _protocol_distribution(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, int]] = defaultdict(lambda: {"bytes": 0, "packets": 0, "flow_count": 0})
    for flow in flows:
        row = rows[str(flow.get("proto") or "Unknown").upper()]
        byte_count, _ = _flow_stat_bytes(flow)
        row["bytes"] += byte_count or 0
        row["packets"] += _flow_packet_count(flow)
        row["flow_count"] += 1
    total_bytes = sum(row["bytes"] for row in rows.values())
    return [
        {"name": name, **row, "percent": round(row["bytes"] / total_bytes * 100, 2) if total_bytes else 0}
        for name, row in sorted(rows.items(), key=lambda item: (-item[1]["bytes"], item[0]))
    ]


def _endpoint_ranking(flows: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, int]] = defaultdict(
        lambda: {"bytes": 0, "packets": 0, "flow_count": 0, "sent_bytes": 0, "received_bytes": 0}
    )
    for flow in flows:
        byte_count, _ = _flow_stat_bytes(flow)
        packets = _flow_packet_count(flow)
        for field, direction in (("src", "sent_bytes"), ("dst", "received_bytes")):
            ip = _canonical_ip(flow.get(field))
            if ip is None:
                continue
            row = rows[ip]
            row["bytes"] += byte_count or 0
            row["packets"] += packets
            row["flow_count"] += 1
            row[direction] += byte_count or 0
    return [
        {"ip": ip, **row} for ip, row in sorted(rows.items(), key=lambda item: (-item[1]["bytes"], item[0]))[:limit]
    ]


def _traffic_replay(flows: list[dict[str, Any]], summary: dict[str, Any]) -> dict[str, Any]:
    sampled: list[tuple[float, int, int]] = []
    represented_packet_count = 0
    sampled_flow_ids: set[int] = set()
    for flow_index, flow in enumerate(flows):
        timestamps = _sample_sequence(flow.get("pkt_times"))
        has_valid_timestamp = False
        for packet_index, timestamp_value in enumerate(timestamps):
            timestamp = _finite_timestamp(timestamp_value)
            if timestamp is None:
                continue
            has_valid_timestamp = True
            sampled_flow_ids.add(flow_index)
            sampled.append((timestamp, flow_index, packet_index))
        if has_valid_timestamp:
            represented_packet_count += _flow_packet_count(flow)
    sampled.sort()
    sampled_event_count = len(sampled)
    truncated = sampled_event_count > _TRAFFIC_REPLAY_MAX_EVENTS
    if truncated:
        first_timestamp, last_timestamp = sampled[0][0], sampled[-1][0]
        span = last_timestamp - first_timestamp
        bucket_representatives: dict[int, int] = {}
        for index, (timestamp, _, _) in enumerate(sampled):
            bucket = (
                min(
                    _TRAFFIC_REPLAY_MAX_EVENTS - 1,
                    int((timestamp - first_timestamp) / span * _TRAFFIC_REPLAY_MAX_EVENTS),
                )
                if span > 0
                else 0
            )
            if bucket == 0:
                bucket_representatives.setdefault(bucket, index)
            else:
                # Keep the final event for each later bucket so the final
                # capture event remains visible when its bucket is occupied.
                bucket_representatives[bucket] = index
        selected_indices = set(bucket_representatives.values())
        for rank in range(_TRAFFIC_REPLAY_MAX_EVENTS):
            if len(selected_indices) >= _TRAFFIC_REPLAY_MAX_EVENTS:
                break
            selected_indices.add(rank * (sampled_event_count - 1) // (_TRAFFIC_REPLAY_MAX_EVENTS - 1))
        if len(selected_indices) < _TRAFFIC_REPLAY_MAX_EVENTS:
            for index in range(sampled_event_count):
                if len(selected_indices) >= _TRAFFIC_REPLAY_MAX_EVENTS:
                    break
                selected_indices.add(index)
        returned = [sampled[index] for index in sorted(selected_indices)]
    else:
        returned = sampled
    first_seen = sampled[0][0] if sampled else None
    events: list[dict[str, Any]] = []
    if first_seen is not None:
        for timestamp, flow_index, packet_index in returned:
            flow = flows[flow_index]
            lengths = _sample_sequence(flow.get("pkt_lens"))
            # A timestamp sample is evidence of an observed packet even when
            # the corresponding packet length was not retained.
            events.append(
                {
                    "timestamp": timestamp,
                    "offset_seconds": round(timestamp - first_seen, 6),
                    "flow_id": f"flow-{flow_index + 1}",
                    "src": str(flow.get("src") or ""),
                    "dst": str(flow.get("dst") or ""),
                    "sport": flow.get("sport"),
                    "dport": flow.get("dport"),
                    "protocol": str(flow.get("proto") or "Unknown").upper(),
                    "sampled_length": _nonnegative_int(lengths[packet_index]) if packet_index < len(lengths) else None,
                    "src_scope": _ip_scope(flow.get("src")),
                    "dst_scope": _ip_scope(flow.get("dst")),
                }
            )
    complete = (
        bool(sampled)
        and not truncated
        and represented_packet_count == sampled_event_count
        and summary["packet_count"] > 0
        and represented_packet_count == summary["packet_count"]
    )
    return {
        "events": events,
        "sampled_event_count": sampled_event_count,
        "returned_event_count": len(events),
        "max_events": _TRAFFIC_REPLAY_MAX_EVENTS,
        "truncated": truncated,
        "sampled_flow_count": len(sampled_flow_ids),
        "total_flow_count": len(flows),
        "represented_packet_count": represented_packet_count,
        "total_packet_count": summary["packet_count"],
        "first_seen": first_seen,
        "last_seen": sampled[-1][0] if sampled else None,
        "coverage": "complete" if complete else "sampled" if sampled else "unavailable",
    }


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
            if latest_analysis is None or analysis.sort_timestamp > latest_analysis.sort_timestamp:
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
    times = _sample_sequence(flow.get("pkt_times"))
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
            for ioc in sorted(
                analysis.iocs,
                key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item.severity.value, 4),
            )[:100]
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
        times = _sample_sequence(flow.get("pkt_times"))
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
            "capture_summary": {
                "packet_count": 0,
                "flow_count": 0,
                "endpoint_count": 0,
                "parsed_traffic_bytes": 0,
                "parsed_packet_count": 0,
                "capture_file_bytes": None,
                "first_seen": None,
                "last_seen": None,
                "duration_seconds": None,
                "byte_coverage": "unknown",
            },
            "protocol_distribution": [],
            "endpoint_ranking": [],
            "traffic_replay": {
                "events": [],
                "sampled_event_count": 0,
                "returned_event_count": 0,
                "max_events": _TRAFFIC_REPLAY_MAX_EVENTS,
                "truncated": False,
                "sampled_flow_count": 0,
                "total_flow_count": 0,
                "represented_packet_count": 0,
                "total_packet_count": 0,
                "first_seen": None,
                "last_seen": None,
                "coverage": "unavailable",
            },
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
    alerts = sum(1 for item in analysis.iocs if item.severity.value in {"high", "critical"})
    risk = "HIGH" if alerts or yara_issues else "MEDIUM" if beacons >= 3 or cert_issues else "LOW"

    packet_lengths: list[float] = []
    inter_arrivals: list[float] = []
    heatmap_buckets = [0] * 48
    timestamps: list[float] = []
    for flow in flows:
        packet_lengths.extend(_as_number(value) for value in _sample_sequence(flow.get("pkt_lens")))
        times = sorted(_as_number(value) for value in _sample_sequence(flow.get("pkt_times")))
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
    capture_summary = _capture_summary(analysis, flows)
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
        "evidence_total": len(analysis.iocs)
        if analysis.iocs
        else sum(len(values) for values in ((features.get("artifacts") or {}).values()) if isinstance(values, list)),
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
        "capture_summary": capture_summary,
        "protocol_distribution": _protocol_distribution(flows),
        "endpoint_ranking": _endpoint_ranking(flows),
        "traffic_replay": _traffic_replay(flows, capture_summary),
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


def build_workbench_state(repo: CaseRepository, analysis_id: str | None = None) -> dict[str, Any]:
    """Create the single bootstrap payload used by the production workbench."""
    latest_case, latest_analysis = _latest_case_and_analysis(repo)
    if analysis_id:
        from fastapi import HTTPException

        selected = repo.get_analysis(analysis_id)
        if selected is None:
            raise HTTPException(status_code=404, detail="analysis_not_found")
        latest_analysis = selected
        latest_case = repo.get_case(selected.case_id)
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
        "system": {
            "healthy": all(tool["ready"] for tool in tools),
            "tools": tools,
            "preserve_saved_data": os.getenv("PCAP_HUNTER_PRESERVE_SAVED_DATA") == "1",
        },
    }
