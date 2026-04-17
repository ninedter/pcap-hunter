"""Attack narrative generation using LLM."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

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

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "timestamp": str(self.timestamp),
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


class AttackNarrator:
    """Generate attack narratives from analysis results."""

    def __init__(self, llm_generate_func: Any | None = None):
        """
        Initialize narrator.

        Args:
            llm_generate_func: Function to call LLM (base_url, api_key, model, context, language) -> str
        """
        self.llm_generate = llm_generate_func

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
            base_timestamp: Base timestamp for events (defaults to analysis time)

        Returns:
            List of TimelineEvents sorted by severity
        """
        events: list[TimelineEvent] = []

        # Use provided base timestamp or extract from features, fallback to now
        if base_timestamp is None:
            base_timestamp = self._extract_base_timestamp(features) or datetime.now()

        # Event index for relative time offset when no timestamp available
        event_idx = 0

        # Add beacon events (highest priority)
        if beacon_results:
            for beacon in beacon_results[:MAX_BEACON_RESULTS]:
                if isinstance(beacon, dict):
                    score = beacon.get("score", 0)
                    if score >= 0.5:
                        # Try to get timestamp from beacon data
                        event_time = self._get_event_timestamp(beacon, base_timestamp, event_idx)
                        event_idx += 1
                        events.append(
                            TimelineEvent(
                                timestamp=event_time,
                                event_type="c2_beacon",
                                description=f"C2 beaconing to {beacon.get('dst', 'unknown')}:{beacon.get('dport', '')} "
                                f"(score: {score:.2f})",
                                severity="critical" if score >= 0.8 else "high",
                                source_ip=beacon.get("src", ""),
                                dest_ip=beacon.get("dst", ""),
                                iocs=[beacon.get("dst", "")],
                            )
                        )

        # Add YARA events
        if yara_results and yara_results.get("matched", 0) > 0:
            for result in yara_results.get("results", [])[:MAX_YARA_RESULTS]:
                severity = result.get("severity", "medium")
                matches = result.get("matches", [])
                rule_names = [m.get("rule_name", "") for m in matches[:3]]
                event_time = self._get_event_timestamp(result, base_timestamp, event_idx)
                event_idx += 1
                events.append(
                    TimelineEvent(
                        timestamp=event_time,
                        event_type="yara_match",
                        description=f"Malware detected in {result.get('file_name', 'unknown')}: "
                        f"{', '.join(rule_names)}",
                        severity=severity,
                        iocs=[result.get("file_name", "")],
                    )
                )

        # Add DNS events
        if dns_analysis:
            alerts = dns_analysis.get("alerts", {})

            # DGA detections
            if alerts.get("dga_count", 0) > 0:
                dga_list = dns_analysis.get("dga_detections", [])[:MAX_DNS_DETECTIONS]
                domains = [d.get("domain", "") for d in dga_list]
                event_time = self._get_event_timestamp(dns_analysis, base_timestamp, event_idx)
                event_idx += 1
                events.append(
                    TimelineEvent(
                        timestamp=event_time,
                        event_type="dga_detection",
                        description=f"DGA domains detected: {', '.join(domains)}",
                        severity="high",
                        iocs=domains,
                    )
                )

            # DNS tunneling
            if alerts.get("tunneling_count", 0) > 0:
                event_time = self._get_event_timestamp(dns_analysis, base_timestamp, event_idx)
                event_idx += 1
                events.append(
                    TimelineEvent(
                        timestamp=event_time,
                        event_type="dns_tunneling",
                        description=f"DNS tunneling indicators ({alerts['tunneling_count']} suspicious queries)",
                        severity="high",
                    )
                )

        # Add TLS events
        if tls_analysis:
            for alert in tls_analysis.get("alerts", [])[:MAX_TLS_ALERTS]:
                alert_type = alert.get("type", "")
                cert = alert.get("cert", "unknown")
                severity = alert.get("severity", "medium")
                event_time = self._get_event_timestamp(alert, base_timestamp, event_idx)
                event_idx += 1

                if alert_type == "self_signed":
                    events.append(
                        TimelineEvent(
                            timestamp=event_time,
                            event_type="tls_anomaly",
                            description=f"Self-signed certificate for {cert}",
                            severity=severity,
                            iocs=[cert],
                        )
                    )
                elif alert_type == "expired":
                    events.append(
                        TimelineEvent(
                            timestamp=event_time,
                            event_type="tls_anomaly",
                            description=f"Expired certificate for {cert}",
                            severity=severity,
                            iocs=[cert],
                        )
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
        """Extract base timestamp from features data (e.g., earliest flow time)."""
        if not features:
            return None

        # Try to get timestamp from flows
        flows = features.get("flows", [])
        if flows:
            for flow in flows:
                # Try common timestamp field names
                for ts_field in ["timestamp", "start_time", "first_seen", "ts"]:
                    ts_val = flow.get(ts_field)
                    if ts_val:
                        try:
                            if isinstance(ts_val, datetime):
                                return ts_val
                            if isinstance(ts_val, (int, float)):
                                return datetime.fromtimestamp(ts_val)
                            if isinstance(ts_val, str):
                                return datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                        except (ValueError, OSError):
                            continue
        return None

    def _get_event_timestamp(self, data: dict, base_timestamp: datetime, event_idx: int) -> datetime:
        """Get timestamp for an event, using actual data or relative offset."""
        # Try to extract timestamp from event data
        for ts_field in ["timestamp", "time", "first_seen", "last_seen", "ts"]:
            ts_val = data.get(ts_field)
            if ts_val:
                try:
                    if isinstance(ts_val, datetime):
                        return ts_val
                    if isinstance(ts_val, (int, float)):
                        return datetime.fromtimestamp(ts_val)
                    if isinstance(ts_val, str):
                        return datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                except (ValueError, OSError):
                    continue

        # Fallback: create relative timestamp (offset by event index)
        # Events are spaced 1 minute apart for readability
        return base_timestamp + timedelta(minutes=event_idx)

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
            dns_alerts=sum((dns_analysis or {}).get("alerts", {}).values()) if dns_analysis else 0,
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
