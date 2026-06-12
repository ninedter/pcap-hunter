"""Flow-level analysis for data exfiltration and port anomaly detection."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Well-known service ports and expected protocols
KNOWN_SERVICES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    8080: "http-alt",
    8443: "https-alt",
}

# Ports commonly used by C2 frameworks
C2_COMMON_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}

# Thresholds
ASYMMETRY_MIN_BYTES = 1_000_000  # 1 MB minimum to flag
ASYMMETRY_RATIO_THRESHOLD = 10.0  # 10:1 outbound:inbound
HIGH_PORT_THRESHOLD = 10000


@dataclass
class FlowAsymmetryResult:
    """Data exfiltration detection result for a src->dst pair."""

    src: str
    dst: str
    outbound_bytes: int
    inbound_bytes: int
    ratio: float
    total_packets: int
    score: float  # 0.0 - 1.0
    is_suspicious: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "outbound_bytes": self.outbound_bytes,
            "inbound_bytes": self.inbound_bytes,
            "ratio": round(self.ratio, 2),
            "total_packets": self.total_packets,
            "score": round(self.score, 3),
            "is_suspicious": self.is_suspicious,
            "reason": self.reason,
        }


@dataclass
class PortAnomalyResult:
    """Port/protocol anomaly detection result."""

    src: str
    dst: str
    port: int
    proto: str
    anomaly_type: str  # non_standard, c2_port, high_port_pair
    expected_service: str
    score: float
    reason: str

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "port": self.port,
            "proto": self.proto,
            "anomaly_type": self.anomaly_type,
            "expected_service": self.expected_service,
            "score": round(self.score, 3),
            "reason": self.reason,
        }


def detect_flow_asymmetry(flows: list[dict[str, Any]]) -> list[FlowAsymmetryResult]:
    """
    Detect potential data exfiltration via upload/download byte ratio analysis.

    Groups flows by (src, dst) pair and calculates byte ratio in each direction.
    Flags pairs with high outbound:inbound ratio above threshold.

    Args:
        flows: List of flow dicts from pyshark_pass

    Returns:
        List of FlowAsymmetryResult sorted by score descending
    """
    # Group flows by (src, dst) pair
    pair_stats: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"outbound_bytes": 0, "inbound_bytes": 0, "total_packets": 0}
    )

    for flow in flows:
        src = flow.get("src", "")
        dst = flow.get("dst", "")
        if not src or not dst:
            continue

        pkt_lens = flow.get("pkt_lens", [])
        count = flow.get("count", 0)

        # Prefer the true byte total tracked by pyshark_pass — it survives the
        # per-flow sample cap, while sum(pkt_lens) undercounts capped flows.
        # Fall back to summing packet lengths (legacy data without the field),
        # then to a per-packet estimate.
        flow_bytes = flow.get("bytes")
        if flow_bytes:
            total_bytes = flow_bytes
        elif pkt_lens:
            total_bytes = sum(pkt_lens)
        else:
            total_bytes = count * 800  # estimate 800 bytes per packet

        pair_stats[(src, dst)]["outbound_bytes"] += total_bytes
        pair_stats[(src, dst)]["total_packets"] += count

        # Track reverse direction
        pair_stats[(dst, src)]["inbound_bytes"] += total_bytes

    results: list[FlowAsymmetryResult] = []

    # Deduplicate pairs (only check each direction once)
    checked: set[tuple[str, str]] = set()

    for (src, dst), stats in pair_stats.items():
        if (src, dst) in checked or (dst, src) in checked:
            continue
        checked.add((src, dst))

        outbound = stats["outbound_bytes"]
        inbound = pair_stats[(dst, src)].get("outbound_bytes", 0)
        total_packets = stats["total_packets"] + pair_stats[(dst, src)].get("total_packets", 0)

        if outbound < ASYMMETRY_MIN_BYTES:
            continue

        ratio = outbound / max(inbound, 1)

        # Score based on ratio magnitude and volume
        score = 0.0
        reasons = []

        if ratio >= 100:
            score += 0.5
            reasons.append(f"extreme ratio ({ratio:.0f}:1)")
        elif ratio >= ASYMMETRY_RATIO_THRESHOLD:
            score += 0.3
            reasons.append(f"high ratio ({ratio:.1f}:1)")
        elif ratio >= 5:
            score += 0.15
            reasons.append(f"elevated ratio ({ratio:.1f}:1)")
        else:
            continue  # Below threshold

        # Volume bonus
        if outbound > 100_000_000:  # >100MB
            score += 0.3
            reasons.append(f"large volume ({outbound / 1_000_000:.1f} MB)")
        elif outbound > 10_000_000:  # >10MB
            score += 0.15
            reasons.append(f"notable volume ({outbound / 1_000_000:.1f} MB)")

        score = min(score, 1.0)
        is_suspicious = score >= 0.4

        results.append(
            FlowAsymmetryResult(
                src=src,
                dst=dst,
                outbound_bytes=outbound,
                inbound_bytes=inbound,
                ratio=ratio,
                total_packets=total_packets,
                score=score,
                is_suspicious=is_suspicious,
                reason="; ".join(reasons),
            )
        )

    results.sort(key=lambda r: r.score, reverse=True)
    return results


def detect_port_anomalies(flows: list[dict[str, Any]]) -> list[PortAnomalyResult]:
    """
    Detect port and protocol anomalies that may indicate C2 or lateral movement.

    Checks for:
    - Non-standard ports for known protocols
    - Known C2 framework ports
    - High-port-to-high-port communication patterns

    Args:
        flows: List of flow dicts from pyshark_pass

    Returns:
        List of PortAnomalyResult sorted by score descending
    """
    results: list[PortAnomalyResult] = []
    seen: set[tuple[str, str, int]] = set()

    for flow in flows:
        src = flow.get("src", "")
        dst = flow.get("dst", "")
        proto = flow.get("proto", "").lower()

        try:
            dport = int(flow.get("dport", 0))
            sport = int(flow.get("sport", 0))
        except (ValueError, TypeError):
            continue

        if not src or not dst or not dport:
            continue

        # Deduplicate per (dst, dport) to avoid flood
        key = (dst, src, dport)
        if key in seen:
            continue
        seen.add(key)

        # Check known C2 ports
        if dport in C2_COMMON_PORTS:
            results.append(
                PortAnomalyResult(
                    src=src,
                    dst=dst,
                    port=dport,
                    proto=proto,
                    anomaly_type="c2_port",
                    expected_service="n/a",
                    score=0.7,
                    reason=f"Port {dport} commonly used by C2 frameworks",
                )
            )
            continue

        # Check high-port to high-port (potential covert channel)
        if sport > HIGH_PORT_THRESHOLD and dport > HIGH_PORT_THRESHOLD:
            count = flow.get("count", 0)
            if count > 10:  # Only flag if sustained
                results.append(
                    PortAnomalyResult(
                        src=src,
                        dst=dst,
                        port=dport,
                        proto=proto,
                        anomaly_type="high_port_pair",
                        expected_service="n/a",
                        score=0.4,
                        reason=f"High-port-to-high-port ({sport}->{dport}, {count} packets)",
                    )
                )

        # Check for protocol mismatch on well-known ports
        if dport in KNOWN_SERVICES:
            expected = KNOWN_SERVICES[dport]
            # HTTP/HTTPS traffic on DNS port, etc.
            if dport == 53 and proto == "tcp":
                count = flow.get("count", 0)
                if count > 20:
                    results.append(
                        PortAnomalyResult(
                            src=src,
                            dst=dst,
                            port=dport,
                            proto=proto,
                            anomaly_type="non_standard",
                            expected_service=expected,
                            score=0.5,
                            reason=f"TCP traffic on DNS port 53 ({count} packets) - possible DNS-over-TCP tunneling",
                        )
                    )
            elif dport == 80 and proto == "udp":
                results.append(
                    PortAnomalyResult(
                        src=src,
                        dst=dst,
                        port=dport,
                        proto=proto,
                        anomaly_type="non_standard",
                        expected_service=expected,
                        score=0.5,
                        reason="UDP traffic on HTTP port 80 - unexpected protocol",
                    )
                )

    results.sort(key=lambda r: r.score, reverse=True)
    return results[:50]  # Limit output
