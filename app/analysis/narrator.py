"""Attack narrative generation using LLM."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePath
from typing import TYPE_CHECKING, Any

from app.pipeline.tls_certs import certificate_alerts_from_analysis

if TYPE_CHECKING:
    from app.threat_intel.attack_mapping import AttackMapping

logger = logging.getLogger(__name__)

# Limits to prevent unbounded memory usage
MAX_TIMELINE_EVENTS = 50
MAX_BEACON_RESULTS = 10
MAX_YARA_RESULTS = 10
MAX_DNS_DETECTIONS = 10
MAX_TLS_ALERTS = 10
MAX_TECHNIQUES_IN_PROMPT = 15
MAX_IOCS_IN_PROMPT = 20

# Keys an analysis record may carry its observation time under, most specific
# first. Flows and beacon rows use ``first_ts``; carved-file results use
# ``observed_time``; DNS detections use ``first_seen``.
EVENT_TIME_FIELDS = (
    "timestamp",
    "time",
    "observed_time",
    "observed_at",
    "first_ts",
    "first_seen",
    "start_time",
    "ts",
    "last_ts",
    "last_seen",
)
# Placeholder ``TimelineEvent.timestamp`` for an event whose time was not observed.
NO_OBSERVED_TIME = ""


def parse_observed_time(value: Any) -> datetime | None:
    """Convert an observed time value into a timezone-aware UTC datetime.

    Args:
        value: Epoch seconds (number or numeric string), ISO-8601 string, or datetime.

    Returns:
        Aware UTC datetime, or None when the value is empty or unparseable. Naive
        datetimes and offset-less ISO strings are taken to be UTC (capture
        timestamps are epoch-based).
    """
    if value is None or isinstance(value, bool) or value == "":
        return None
    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)):
            if value <= 0 or value != value:  # zero/negative epoch or NaN: not an observation
                return None
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            try:
                epoch = float(text)
            except ValueError:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            else:
                return parse_observed_time(epoch)
        else:
            return None
    except (ValueError, OverflowError, OSError):
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


# Prompt template for attack narrative
NARRATIVE_PROMPT = """Based on the timeline of events and detected techniques, write a concise
attack narrative that explains:

1. How the attack likely began (initial access)
2. What the attacker did (execution, persistence)
3. How they communicated with C2 (command and control)
4. What data may have been exfiltrated (if applicable)
5. Current status and recommended actions

Timeline of key events:
{timeline_events}

Detected MITRE ATT&CK Techniques:
{techniques}

Key IOCs:
{iocs}

Analysis Summary:
- Total flows: {flow_count}
- Beacon candidates: {beacon_count}
- YARA matches: {yara_matches}
- DNS alerts: {dns_alerts}

Write in {language}, using professional security terminology.
Keep the narrative to 3-5 paragraphs. Focus on the most critical findings.
Do not repeat raw data - synthesize it into a coherent story."""


@dataclass
class TimelineEvent:
    """A single event on the attack timeline."""

    timestamp: datetime | str
    event_type: str  # connection, dns_query, file_download, alert, yara_match
    description: str
    severity: str  # info, low, medium, high, critical
    source_ip: str = ""
    dest_ip: str = ""
    iocs: list[str] | None = None
    # False when no time was observed for this event; ``timestamp`` is then
    # ``NO_OBSERVED_TIME`` rather than an invented value.
    time_observed: bool = True

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "timestamp": str(self.timestamp),
            "time_observed": self.time_observed,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "iocs": self.iocs or [],
        }

    def __str__(self) -> str:
        """String representation for prompt."""
        return f"[{self.severity.upper()}] {self.event_type}: {self.description}"


def _count_dns_alerts(dns_analysis: dict | None) -> int:
    """Number of confirmed DNS detections (DGA + tunneling + fast flux).

    The DNS ``alerts`` dict also holds a boolean and a ratio; summing every value
    (as was done before) added the NXDOMAIN ratio to a count.
    """
    alerts = (dns_analysis or {}).get("alerts")
    if not isinstance(alerts, dict):
        return 0
    return sum(int(alerts.get(key, 0) or 0) for key in ("dga_count", "tunneling_count", "fast_flux_count"))


def _yara_file_name(result: dict) -> str:
    """Display name of a scanned file (results carry ``file_path``, older callers ``file_name``)."""
    name = result.get("file_name") or PurePath(str(result.get("file_path") or "")).name
    return name or "unknown"


class AttackNarrator:
    """Generate attack narratives from analysis results."""

    def __init__(self, llm_generate_func: Any | None = None):
        """
        Initialize narrator.

        Args:
            llm_generate_func: Function to call LLM (base_url, api_key, model, context, language) -> str
        """
        self.llm_generate = llm_generate_func

    def capture_start(self, features: dict | None) -> datetime | None:
        """Earliest flow start time in the capture (aware UTC), or None if unknown."""
        return self._extract_base_timestamp(features)

    def create_timeline(
        self,
        features: dict | None = None,
        dns_analysis: dict | None = None,
        yara_results: dict | None = None,
        beacon_results: list | None = None,
        tls_analysis: dict | None = None,
        base_timestamp: datetime | None = None,
    ) -> list[TimelineEvent]:
        """
        Extract chronological events from analysis results.

        Args:
            features: Flow and artifact features
            dns_analysis: DNS analysis results
            yara_results: YARA scan results
            beacon_results: Beacon candidates
            tls_analysis: TLS analysis results
            base_timestamp: Deprecated and ignored. It used to seed fabricated
                per-event times; events now carry only times observed in the
                capture. Use ``capture_start`` for the capture's first flow time.

        Returns:
            List of TimelineEvents sorted by severity. Events whose source record
            has no time carry ``timestamp == NO_OBSERVED_TIME`` and
            ``time_observed=False``.
        """
        events: list[TimelineEvent] = []

        def add(
            source: dict | None,
            event_type: str,
            description: str,
            severity: str,
            *,
            observed: datetime | None = None,
            **fields: Any,
        ) -> None:
            when = observed or self._get_event_timestamp(source or {})
            events.append(
                TimelineEvent(
                    timestamp=when if when is not None else NO_OBSERVED_TIME,
                    event_type=event_type,
                    description=description,
                    severity=severity,
                    time_observed=when is not None,
                    **fields,
                )
            )

        # Add beacon events (highest priority)
        if beacon_results:
            for beacon in beacon_results[:MAX_BEACON_RESULTS]:
                if isinstance(beacon, dict):
                    score = beacon.get("score", 0)
                    if score >= 0.5:
                        add(
                            beacon,
                            "c2_beacon",
                            f"C2 beaconing to {beacon.get('dst', 'unknown')}:{beacon.get('dport', '')} "
                            f"(score: {score:.2f})",
                            "critical" if score >= 0.8 else "high",
                            source_ip=beacon.get("src", ""),
                            dest_ip=beacon.get("dst", ""),
                            iocs=[beacon.get("dst", "")],
                        )

        # Add YARA events (``results`` lists every scanned file; only matches are events)
        if yara_results and yara_results.get("matched", 0) > 0:
            matched = [
                r
                for r in yara_results.get("results", [])
                if isinstance(r, dict) and (r.get("has_matches") or r.get("matches"))
            ]
            for result in matched[:MAX_YARA_RESULTS]:
                severity = result.get("severity", "medium")
                matches = result.get("matches", [])
                rule_names = [m.get("rule_name", "") for m in matches[:3]]
                file_name = _yara_file_name(result)
                add(
                    result,
                    "yara_match",
                    f"Malware detected in {file_name}: {', '.join(rule_names)}",
                    severity,
                    source_ip=str(result.get("src_ip") or ""),
                    dest_ip=str(result.get("dst_ip") or ""),
                    iocs=[file_name],
                )

        # Add DNS events
        if dns_analysis:
            alerts = dns_analysis.get("alerts", {})
            if not isinstance(alerts, dict):
                alerts = {}

            # DGA detections
            if alerts.get("dga_count", 0) > 0:
                dga_list = dns_analysis.get("dga_detections", [])[:MAX_DNS_DETECTIONS]
                domains = [d.get("domain", "") for d in dga_list]
                add(
                    None,
                    "dga_detection",
                    f"DGA domains detected: {', '.join(domains)}",
                    "high",
                    observed=self._earliest_time(dga_list),
                    iocs=domains,
                )

            # DNS tunneling
            if alerts.get("tunneling_count", 0) > 0:
                tunnels = [t for t in dns_analysis.get("tunneling_detections", []) if t.get("is_tunneling")]
                add(
                    None,
                    "dns_tunneling",
                    f"DNS tunneling indicators ({alerts['tunneling_count']} suspicious queries)",
                    "high",
                    observed=self._earliest_time(tunnels),
                    iocs=[t.get("domain", "") for t in tunnels[:MAX_DNS_DETECTIONS]],
                )

        # Add TLS events. The stage's ``alerts`` key is a dict of counters; the
        # per-certificate list is resolved by the shared helper for every saved shape.
        if tls_analysis:
            for alert in certificate_alerts_from_analysis(tls_analysis)[:MAX_TLS_ALERTS]:
                alert_type = alert.get("type", "")
                cert = alert.get("cert", "unknown")
                severity = alert.get("severity", "medium")
                label = {"self_signed": "Self-signed", "expired": "Expired"}.get(alert_type)
                if label is None:
                    continue
                add(
                    alert,
                    "tls_anomaly",
                    f"{label} certificate for {cert}",
                    severity,
                    dest_ip=str(alert.get("dst_ip") or ""),
                    iocs=[cert],
                )

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        events.sort(key=lambda e: severity_order.get(e.severity, 5))

        # Limit total events to prevent unbounded memory usage
        if len(events) > MAX_TIMELINE_EVENTS:
            logger.warning("Limiting timeline to %d events (from %d)", MAX_TIMELINE_EVENTS, len(events))
            events = events[:MAX_TIMELINE_EVENTS]

        return events

    def _extract_base_timestamp(self, features: dict | None) -> datetime | None:
        """Return the capture start: the earliest flow start time, as aware UTC.

        Args:
            features: Flow and artifact features (flows carry ``first_ts``).

        Returns:
            Earliest observed flow time, or None when no flow has one.
        """
        if not features:
            return None

        earliest: datetime | None = None
        for flow in features.get("flows", []) or []:
            if not isinstance(flow, dict):
                continue
            when = self._get_event_timestamp(flow)
            if when is not None and (earliest is None or when < earliest):
                earliest = when
        return earliest

    def _get_event_timestamp(
        self,
        data: dict,
        base_timestamp: datetime | None = None,
        event_idx: int = 0,
    ) -> datetime | None:
        """Get the observed time of an event from its own record.

        Args:
            data: Analysis record (beacon row, YARA result, TLS alert, flow...).
            base_timestamp: Ignored. Formerly the origin for fabricated offsets.
            event_idx: Ignored. Formerly the fabricated offset in minutes.

        Returns:
            Aware UTC datetime, or None when the record carries no usable time.
            Never invents a time.
        """
        for ts_field in EVENT_TIME_FIELDS:
            when = parse_observed_time(data.get(ts_field))
            if when is not None:
                return when
        return None

    def _earliest_time(self, records: list[dict]) -> datetime | None:
        """Earliest observed time across a list of records, or None."""
        times = [t for t in (self._get_event_timestamp(r) for r in records if isinstance(r, dict)) if t is not None]
        return min(times) if times else None

    def generate_narrative(
        self,
        features: dict | None = None,
        dns_analysis: dict | None = None,
        tls_analysis: dict | None = None,
        yara_results: dict | None = None,
        beacon_results: list | None = None,
        attack_mapping: "AttackMapping | None" = None,
        language: str = "English",
        llm_config: dict | None = None,
    ) -> str:
        """
        Generate attack narrative using LLM.

        Args:
            features: Analysis features
            dns_analysis: DNS analysis results
            tls_analysis: TLS analysis results
            yara_results: YARA scan results
            beacon_results: Beacon candidates
            attack_mapping: ATT&CK mapping
            language: Output language
            llm_config: LLM configuration (base_url, api_key, model)

        Returns:
            Generated narrative text
        """
        # Create timeline
        timeline = self.create_timeline(
            features=features,
            dns_analysis=dns_analysis,
            yara_results=yara_results,
            beacon_results=beacon_results,
            tls_analysis=tls_analysis,
        )

        # If no LLM function provided, return basic narrative
        if not self.llm_generate or not llm_config:
            return self._generate_basic_narrative(timeline, attack_mapping, features)

        # Build prompt with limits
        timeline_text = "\n".join(str(e) for e in timeline[:MAX_TIMELINE_EVENTS])

        techniques_text = ""
        if attack_mapping:
            techniques_text = "\n".join(
                f"- {t.technique_id} ({t.technique_name}): {', '.join(t.evidence[:2])}"
                for t in attack_mapping.techniques[:MAX_TECHNIQUES_IN_PROMPT]
            )

        # Extract IOCs with limits
        artifacts = (features or {}).get("artifacts", {})
        iocs = []
        iocs.extend(artifacts.get("ips", [])[: MAX_IOCS_IN_PROMPT // 2])
        iocs.extend(artifacts.get("domains", [])[: MAX_IOCS_IN_PROMPT // 2])
        iocs_text = ", ".join(iocs) if iocs else "No critical IOCs identified"

        # Build context
        prompt = NARRATIVE_PROMPT.format(
            timeline_events=timeline_text or "No significant events detected",
            techniques=techniques_text or "No ATT&CK techniques mapped",
            iocs=iocs_text,
            flow_count=len((features or {}).get("flows", [])),
            beacon_count=len(beacon_results or []),
            yara_matches=(yara_results or {}).get("matched", 0),
            dns_alerts=_count_dns_alerts(dns_analysis),
            language=language,
        )

        try:
            # Call LLM
            context = {"prompt": prompt}
            narrative = self.llm_generate(
                llm_config.get("base_url", ""),
                llm_config.get("api_key", ""),
                llm_config.get("model", ""),
                context,
                language,
            )
            return narrative
        except Exception as e:
            logger.error("Error generating narrative: %s", e)
            return self._generate_basic_narrative(timeline, attack_mapping, features)

    def _generate_basic_narrative(
        self,
        timeline: list[TimelineEvent],
        attack_mapping: "AttackMapping | None",
        features: dict | None,
    ) -> str:
        """Generate basic narrative without LLM."""
        lines = ["## Attack Summary\n"]

        if not timeline:
            lines.append("No significant security events were detected in this capture.\n")
            return "\n".join(lines)

        # Group by severity
        critical = [e for e in timeline if e.severity == "critical"]
        high = [e for e in timeline if e.severity == "high"]
        medium = [e for e in timeline if e.severity == "medium"]

        if critical:
            lines.append("### Critical Findings\n")
            for event in critical[:3]:
                lines.append(f"- **{event.event_type}**: {event.description}")
            lines.append("")

        if high:
            lines.append("### High Priority Findings\n")
            for event in high[:3]:
                lines.append(f"- **{event.event_type}**: {event.description}")
            lines.append("")

        if medium:
            lines.append("### Notable Observations\n")
            for event in medium[:3]:
                lines.append(f"- {event.event_type}: {event.description}")
            lines.append("")

        # Add ATT&CK summary
        if attack_mapping and attack_mapping.techniques:
            lines.append("### MITRE ATT&CK Coverage\n")
            lines.append(f"**Kill Chain Phase**: {attack_mapping.kill_chain_phase}")
            lines.append(f"**Overall Severity**: {attack_mapping.overall_severity.upper()}\n")

            tactics = attack_mapping.tactics_summary
            if tactics:
                lines.append("**Tactics Detected**:")
                for tactic, count in sorted(tactics.items(), key=lambda x: -x[1]):
                    lines.append(f"- {tactic}: {count} technique(s)")
            lines.append("")

        # Recommendations
        lines.append("### Recommended Actions\n")
        if critical or (attack_mapping and attack_mapping.overall_severity == "critical"):
            lines.append("1. **Immediate**: Isolate affected hosts")
            lines.append("2. **Block**: Add IOCs to firewall/proxy blocklist")
            lines.append("3. **Investigate**: Conduct full forensic analysis")
        elif high:
            lines.append("1. **Monitor**: Enable enhanced logging for affected hosts")
            lines.append("2. **Block**: Consider blocking suspicious IPs/domains")
            lines.append("3. **Review**: Analyze related network activity")
        else:
            lines.append("1. **Continue Monitoring**: No immediate action required")
            lines.append("2. **Document**: Record findings for future reference")

        return "\n".join(lines)
