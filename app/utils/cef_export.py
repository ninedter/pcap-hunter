"""CEF (Common Event Format) and Syslog export for SIEM integration.

Generates ArcSight-compatible CEF messages from PCAP Hunter analysis
results so they can be forwarded to any SIEM that accepts CEF over
syslog (Splunk, QRadar, Sentinel, Elastic, etc.).

CEF format reference:
    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions

Usage::

    from app.utils.cef_export import generate_cef_events, format_syslog

    events = generate_cef_events(correlations=correlations, beacon_df=beacon_df)
    syslog_lines = [format_syslog(e) for e in events]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_CEF_VERSION = "0"
_VENDOR = "PCAPHunter"
_PRODUCT = "ThreatWorkbench"
_PRODUCT_VERSION = "1.0"

# Map internal verdicts to CEF severity (0-10 scale)
_SEVERITY_MAP = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
    "unknown": 0,
}


@dataclass
class CEFEvent:
    """A single CEF event ready for syslog emission."""

    signature_id: str
    name: str
    severity: int
    extensions: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def to_cef(self) -> str:
        """Render as a CEF-formatted string (without syslog header)."""
        ext_parts = []
        for k, v in self.extensions.items():
            # CEF extension values: escape = and backslash
            safe_v = str(v).replace("\\", "\\\\").replace("=", "\\=")
            ext_parts.append(f"{k}={safe_v}")
        ext_str = " ".join(ext_parts)

        # Escape pipe characters in header fields
        name_safe = self.name.replace("|", "\\|")

        return (
            f"CEF:{_CEF_VERSION}|{_VENDOR}|{_PRODUCT}|{_PRODUCT_VERSION}"
            f"|{self.signature_id}|{name_safe}|{self.severity}|{ext_str}"
        )


def format_syslog(event: CEFEvent, hostname: str = "pcap-hunter") -> str:
    """Wrap a CEF event in a BSD-style syslog header.

    Args:
        event: The CEF event to format.
        hostname: Hostname for the syslog header.

    Returns:
        Complete syslog line ready for network transmission.
    """
    ts = event.timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts} {hostname} {event.to_cef()}"


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------


def _events_from_correlations(correlations: list) -> list[CEFEvent]:
    """Convert correlation results to CEF events."""
    events: list[CEFEvent] = []
    for c in correlations:
        # Support both dataclass and dict
        if hasattr(c, "indicator"):
            indicator = c.indicator
            verdict = getattr(c, "verdict", "unknown")
            signals = getattr(c, "signals", [])
            score = getattr(c, "score", 0)
        elif isinstance(c, dict):
            indicator = c.get("indicator", "")
            verdict = c.get("verdict", "unknown")
            signals = c.get("signals", [])
            score = c.get("score", 0)
        else:
            continue

        severity = _SEVERITY_MAP.get(str(verdict).lower(), 0)
        signal_str = ", ".join(str(s) for s in signals) if signals else ""

        events.append(
            CEFEvent(
                signature_id="CORR-001",
                name=f"Threat Correlation: {verdict}",
                severity=severity,
                extensions={
                    "src": indicator,
                    "cs1Label": "Verdict",
                    "cs1": str(verdict),
                    "cs2Label": "Signals",
                    "cs2": signal_str,
                    "cfp1Label": "Score",
                    "cfp1": f"{score:.2f}" if isinstance(score, (int, float)) else str(score),
                },
            )
        )
    return events


def _events_from_beacons(beacon_df: Any) -> list[CEFEvent]:
    """Convert beacon DataFrame rows to CEF events."""
    events: list[CEFEvent] = []
    if beacon_df is None or (hasattr(beacon_df, "empty") and beacon_df.empty):
        return events

    try:
        for _, row in beacon_df.iterrows():
            score = row.get("score", 0)
            if score < 0.3:
                continue  # Only emit notable beacons
            severity = 8 if score >= 0.6 else 5 if score >= 0.4 else 3

            events.append(
                CEFEvent(
                    signature_id="BEACON-001",
                    name="C2 Beacon Candidate",
                    severity=severity,
                    extensions={
                        "src": str(row.get("src", "")),
                        "dst": str(row.get("dst", "")),
                        "dpt": str(row.get("dport", "")),
                        "cnt": str(row.get("count", "")),
                        "cfp1Label": "BeaconScore",
                        "cfp1": f"{score:.2f}",
                    },
                )
            )
    except Exception as e:
        logger.warning("Beacon CEF generation failed: %s", e)
    return events


def _events_from_dns(dns_analysis: dict | None) -> list[CEFEvent]:
    """Convert DNS analysis alerts to CEF events."""
    events: list[CEFEvent] = []
    if not dns_analysis:
        return events

    # DGA detections
    for d in dns_analysis.get("dga_detections", []):
        events.append(
            CEFEvent(
                signature_id="DNS-DGA-001",
                name="DGA Domain Detected",
                severity=7,
                extensions={
                    "dhost": str(d.get("domain", "")),
                    "cfp1Label": "EntropyScore",
                    "cfp1": f"{d.get('score', 0):.2f}",
                    "cs1Label": "Reason",
                    "cs1": str(d.get("reason", "")),
                },
            )
        )

    # Tunneling
    for t in dns_analysis.get("tunneling_suspects", []):
        domain = t if isinstance(t, str) else t.get("domain", "")
        events.append(
            CEFEvent(
                signature_id="DNS-TUNNEL-001",
                name="DNS Tunneling Suspect",
                severity=8,
                extensions={"dhost": str(domain)},
            )
        )

    return events


def _events_from_iocs(
    osint: dict | None,
    scored_iocs: list | None = None,
) -> list[CEFEvent]:
    """Convert high-priority IOCs to CEF events."""
    events: list[CEFEvent] = []
    if not scored_iocs:
        return events

    for ioc in scored_iocs:
        # Support ScoredIOC dataclass
        if hasattr(ioc, "priority_score"):
            score = ioc.priority_score
            if score < 0.4:
                continue
            label = getattr(ioc, "priority_label", "medium")
            value = getattr(ioc, "value", "")
            ioc_type = getattr(ioc, "ioc_type", "ip")
        elif isinstance(ioc, dict):
            score = ioc.get("priority_score", 0)
            if score < 0.4:
                continue
            label = ioc.get("priority_label", "medium")
            value = ioc.get("value", "")
            ioc_type = ioc.get("type", "ip")
        else:
            continue

        severity = _SEVERITY_MAP.get(label, 5)
        ext = {
            "cs1Label": "IOCType",
            "cs1": str(ioc_type),
            "cfp1Label": "PriorityScore",
            "cfp1": f"{score:.2f}",
        }
        if ioc_type == "ip":
            ext["src"] = str(value)
        else:
            ext["dhost"] = str(value)

        events.append(
            CEFEvent(
                signature_id="IOC-001",
                name=f"High-Priority IOC ({label})",
                severity=severity,
                extensions=ext,
            )
        )

    return events


def generate_cef_events(
    correlations: list | None = None,
    beacon_df: Any = None,
    dns_analysis: dict | None = None,
    osint: dict | None = None,
    scored_iocs: list | None = None,
) -> list[CEFEvent]:
    """Generate CEF events from all available analysis results.

    Args:
        correlations: Correlation results list.
        beacon_df: Beacon scoring DataFrame.
        dns_analysis: DNS analysis dict.
        osint: OSINT enrichment dict.
        scored_iocs: List of scored IOC objects.

    Returns:
        List of CEFEvent objects ready for syslog formatting.
    """
    events: list[CEFEvent] = []
    events.extend(_events_from_correlations(correlations or []))
    events.extend(_events_from_beacons(beacon_df))
    events.extend(_events_from_dns(dns_analysis))
    events.extend(_events_from_iocs(osint, scored_iocs))
    return events


def export_cef_text(
    correlations: list | None = None,
    beacon_df: Any = None,
    dns_analysis: dict | None = None,
    osint: dict | None = None,
    scored_iocs: list | None = None,
    hostname: str = "pcap-hunter",
) -> str:
    """Generate a complete CEF/syslog export as a multi-line string.

    Convenience wrapper that calls :func:`generate_cef_events` and formats
    each event as a syslog line.

    Returns:
        Newline-separated syslog lines.
    """
    events = generate_cef_events(
        correlations=correlations,
        beacon_df=beacon_df,
        dns_analysis=dns_analysis,
        osint=osint,
        scored_iocs=scored_iocs,
    )
    return "\n".join(format_syslog(e, hostname=hostname) for e in events)
