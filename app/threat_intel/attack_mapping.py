"""MITRE ATT&CK mapping engine for PCAP analysis results."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from app import config as C

logger = logging.getLogger(__name__)

# Valid IOC types for validation
VALID_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "file", "ja3"}

# Maximum values to process to prevent resource exhaustion
MAX_BEACON_RESULTS = 20
MAX_YARA_RESULTS = 20
MAX_TLS_ALERTS = 20
MAX_JA3_FINGERPRINTS = 50
MAX_FLOWS = 1000
ATTACK_VERSION = "19.1"
MAPPING_SCHEMA_VERSION = 2
VALID_DISPOSITIONS = {"unreviewed", "confirmed", "dismissed"}

# Average packet size estimate (bytes) when only packet count is available
AVG_PACKET_SIZE_ESTIMATE = 800


@dataclass
class TechniqueMatch:
    """A matched ATT&CK technique."""

    technique_id: str  # e.g., T1071.001
    technique_name: str  # e.g., Web Protocols
    tactic: str  # e.g., command-and-control
    confidence: float  # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)  # What triggered this detection
    analytic_id: str | None = None
    data_components: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    disposition: str = "unreviewed"
    analyst_note: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "analytic_id": self.analytic_id,
            "data_components": self.data_components,
            "limitations": self.limitations,
            "references": self.references,
            "disposition": self.disposition,
            "analyst_note": self.analyst_note,
        }


@dataclass
class AttackMapping:
    """Complete ATT&CK mapping for an analysis."""

    techniques: list[TechniqueMatch] = field(default_factory=list)
    tactics_summary: dict[str, int] = field(default_factory=dict)  # tactic -> count
    kill_chain_phase: str = "unknown"  # Most advanced phase detected
    overall_severity: str = "low"  # low, medium, high, critical
    attack_version: str = ATTACK_VERSION
    mapping_schema_version: int = MAPPING_SCHEMA_VERSION

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "attack_version": self.attack_version,
            "mapping_schema_version": self.mapping_schema_version,
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics_summary": self.tactics_summary,
            "kill_chain_phase": self.kill_chain_phase,
            "overall_severity": self.overall_severity,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackMapping":
        """Restore a mapping from a session or persisted JSON payload."""
        techniques = [
            TechniqueMatch(
                technique_id=str(item.get("technique_id", "")),
                technique_name=str(item.get("technique_name", "")),
                tactic=str(item.get("tactic", "")),
                confidence=float(item.get("confidence", 0.0)),
                evidence=[str(value) for value in item.get("evidence", [])],
                analytic_id=item.get("analytic_id") or None,
                data_components=[str(value) for value in item.get("data_components", [])],
                limitations=[str(value) for value in item.get("limitations", [])],
                references=[str(value) for value in item.get("references", [])],
                disposition=item.get("disposition", "unreviewed")
                if item.get("disposition", "unreviewed") in VALID_DISPOSITIONS
                else "unreviewed",
                analyst_note=str(item.get("analyst_note", "")),
            )
            for item in data.get("techniques", [])
            if isinstance(item, dict)
        ]
        return cls(
            techniques=techniques,
            tactics_summary={str(key): int(value) for key, value in (data.get("tactics_summary") or {}).items()},
            kill_chain_phase=str(data.get("kill_chain_phase", "unknown")),
            overall_severity=str(data.get("overall_severity", "low")),
            attack_version=str(data.get("attack_version", ATTACK_VERSION)),
            mapping_schema_version=int(data.get("mapping_schema_version", MAPPING_SCHEMA_VERSION)),
        )


# Kill chain phases in order of advancement
KILL_CHAIN_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Detection rules mapping analysis findings to ATT&CK techniques
DETECTION_RULES = {
    # C2 Communication patterns
    "beacon_score": {
        "threshold": 0.7,
        "techniques": [
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "command-and-control",
            },
            {
                "id": "T1571",
                "name": "Non-Standard Port",
                "tactic": "command-and-control",
            },
            {
                "id": "T1573",
                "name": "Encrypted Channel",
                "tactic": "command-and-control",
            },
        ],
    },
    # DNS-based techniques
    "dns_tunneling": {
        "threshold": 0.6,
        "techniques": [
            {
                "id": "T1071.004",
                "name": "Application Layer Protocol: DNS",
                "tactic": "command-and-control",
            },
            {
                "id": "T1048.003",
                "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
                "tactic": "exfiltration",
            },
        ],
    },
    "dga_detected": {
        "threshold": 0.7,
        "techniques": [
            {
                "id": "T1568.002",
                "name": "Dynamic Resolution: Domain Generation Algorithms",
                "tactic": "command-and-control",
            },
        ],
    },
    "dns_fast_flux": {
        "threshold": 0.6,
        "techniques": [
            {
                "id": "T1568.001",
                "name": "Dynamic Resolution: Fast Flux DNS",
                "tactic": "command-and-control",
            },
        ],
    },
    # TLS/Certificate anomalies
    "self_signed_cert": {
        "techniques": [
            {
                "id": "T1573.002",
                "name": "Encrypted Channel: Asymmetric Cryptography",
                "tactic": "command-and-control",
            },
        ],
    },
    "expired_cert": {
        "techniques": [
            {
                "id": "T1573.002",
                "name": "Encrypted Channel: Asymmetric Cryptography",
                "tactic": "command-and-control",
            },
        ],
    },
    # JA3 fingerprint matches
    "ja3_malware": {
        "techniques": [
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "command-and-control",
            },
            {
                "id": "T1095",
                "name": "Non-Application Layer Protocol",
                "tactic": "command-and-control",
            },
        ],
    },
    # YARA matches by severity
    "yara_critical": {
        "techniques": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "execution",
            },
            {
                "id": "T1027",
                "name": "Obfuscated Files or Information",
                "tactic": "defense-evasion",
            },
            {
                "id": "T1055",
                "name": "Process Injection",
                "tactic": "defense-evasion",
            },
        ],
    },
    "yara_high": {
        "techniques": [
            {
                "id": "T1027",
                "name": "Obfuscated Files or Information",
                "tactic": "defense-evasion",
            },
            {
                "id": "T1105",
                "name": "Ingress Tool Transfer",
                "tactic": "command-and-control",
            },
        ],
    },
    # Large data transfers
    "large_outbound": {
        "threshold": 10_000_000,  # 10MB
        "techniques": [
            {
                "id": "T1048",
                "name": "Exfiltration Over Alternative Protocol",
                "tactic": "exfiltration",
            },
            {
                "id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "tactic": "exfiltration",
            },
        ],
    },
    # Suspicious ports
    "non_standard_port": {
        "techniques": [
            {
                "id": "T1571",
                "name": "Non-Standard Port",
                "tactic": "command-and-control",
            },
        ],
    },
}

# ATT&CK context is kept separate from the detector rules so the UI can show
# what an analytic actually supports without pretending that every heuristic
# is a complete ATT&CK detection.  IDs are only populated where the current
# ATT&CK site has a relevant network analytic; otherwise the match remains an
# unlinked technique hypothesis.
TECHNIQUE_METADATA = {
    "T1071.001": {
        "data_components": ["Network Traffic: Web Protocols"],
        "analytic_id": "DET0027",
        "references": ["https://attack.mitre.org/detectionstrategies/DET0027/"],
        "limitations": ["Beacon periodicity alone does not prove HTTP or web-protocol C2."],
    },
    "T1573": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["Beacon periodicity alone does not prove an encrypted channel."],
    },
    "T1071.004": {
        "data_components": ["Network Traffic: DNS"],
        "limitations": ["DNS anomaly scoring does not establish operator intent or exfiltration."],
    },
    "T1568.001": {
        "data_components": ["Network Traffic: DNS"],
        "limitations": ["Fast-flux indicators require infrastructure corroboration to distinguish benign CDNs."],
    },
    "T1568.002": {
        "data_components": ["Network Traffic: DNS"],
        "limitations": ["DGA scoring is probabilistic and should be confirmed with domain-age or endpoint evidence."],
    },
    "T1571": {
        "analytic_id": "DET0227",
        "data_components": ["Network Traffic Flow"],
        "references": ["https://attack.mitre.org/detectionstrategies/DET0227/"],
        "limitations": ["A non-standard port is not malicious without protocol and asset context."],
    },
    "T1573.002": {
        "data_components": ["Network Traffic: SSL/TLS"],
        "limitations": ["Certificate anomalies do not prove encrypted C2 or attacker-controlled keys."],
    },
    "T1041": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["High outbound volume alone does not establish exfiltration or C2 use."],
    },
    "T1048": {
        "data_components": ["Network Traffic Flow"],
        "limitations": ["High outbound volume alone does not identify an alternative exfiltration protocol."],
    },
    "T1027": {
        "limitations": [
            "YARA severity alone does not identify obfuscation; rule semantics and file context are required."
        ],
    },
    "T1059": {
        "limitations": ["A carved-file YARA severity does not prove command or scripting execution."],
    },
    "T1055": {
        "limitations": ["A carved-file YARA severity does not prove process injection."],
    },
    "T1105": {
        "limitations": ["A YARA match does not prove tool transfer without transfer lineage and endpoint evidence."],
    },
    "T1095": {
        "limitations": ["JA3 reputation alone does not prove a non-application-layer protocol."],
    },
}


class ATTACKMapper:
    """Maps analysis results to ATT&CK v19.1 technique hypotheses.

    The mapper deliberately distinguishes a technique hypothesis from direct
    analytic coverage.  Network-only evidence cannot prove endpoint execution,
    identity, or intent, so each match carries limitations and may omit an
    analytic ID when the required protocol context is missing.
    """

    def __init__(self):
        """Initialize the mapper."""
        self.detection_rules = DETECTION_RULES

    def map_analysis(
        self,
        features: dict | None = None,
        dns_analysis: dict | None = None,
        tls_analysis: dict | None = None,
        yara_results: dict | None = None,
        beacon_results: list | None = None,
        osint: dict | None = None,
    ) -> AttackMapping:
        """
        Map analysis results to ATT&CK techniques.

        Args:
            features: Flow and artifact features
            dns_analysis: DNS analysis results
            tls_analysis: TLS certificate analysis
            yara_results: YARA scan results
            beacon_results: C2 beaconing candidates
            osint: OSINT enrichment data

        Returns:
            AttackMapping with detected techniques
        """
        techniques: list[TechniqueMatch] = []

        # Check beacon scores (with limit)
        if beacon_results:
            limited_beacons = beacon_results[:MAX_BEACON_RESULTS]
            if len(beacon_results) > MAX_BEACON_RESULTS:
                logger.warning("Limiting beacon analysis to %d results", MAX_BEACON_RESULTS)
            techniques.extend(self._check_beaconing(limited_beacons))

        # Check DNS analysis
        if dns_analysis:
            techniques.extend(self._check_dns(dns_analysis))

        # Check TLS certificates
        if tls_analysis:
            techniques.extend(self._check_tls(tls_analysis))

        # Check YARA results
        if yara_results:
            techniques.extend(self._check_yara(yara_results))

        # Check JA3 fingerprints from OSINT or features
        if osint and osint.get("ja3"):
            techniques.extend(self._check_ja3(osint["ja3"]))
        elif features and features.get("artifacts", {}).get("ja3"):
            techniques.extend(self._check_ja3_from_features(features))

        # Check for large data transfers
        if features:
            techniques.extend(self._check_data_transfer(features))
            techniques.extend(self._check_suspicious_ports(features))

        # Deduplicate techniques
        techniques = self._deduplicate_techniques(techniques)
        self._annotate_techniques(techniques)

        # Calculate tactics summary
        tactics_summary = self._calculate_tactics_summary(techniques)

        # Determine kill chain phase
        kill_chain_phase = self._determine_kill_chain_phase(tactics_summary)

        # Calculate overall severity
        overall_severity = self._calculate_severity(techniques)

        return AttackMapping(
            techniques=techniques,
            tactics_summary=tactics_summary,
            kill_chain_phase=kill_chain_phase,
            overall_severity=overall_severity,
        )

    def _check_beaconing(self, beacon_results: list) -> list[TechniqueMatch]:
        """Check beaconing results for C2 indicators."""
        techniques = []
        rule = self.detection_rules["beacon_score"]
        threshold = rule["threshold"]

        for beacon in beacon_results:
            score = beacon.get("score", 0) if isinstance(beacon, dict) else 0
            if score >= threshold:
                for tech in rule["techniques"]:
                    proto = beacon.get("proto") or beacon.get("protocol")
                    protocol_note = f" over {proto}" if proto else ""
                    evidence = (
                        f"Beaconing detected with score {score:.2f} to {beacon.get('dst', 'unknown')}{protocol_note}"
                    )
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=min(score, 1.0),
                            evidence=[evidence],
                        )
                    )
        return techniques

    def _check_dns(self, dns_analysis: dict) -> list[TechniqueMatch]:
        """Check DNS analysis for suspicious patterns."""
        techniques = []
        alerts = dns_analysis.get("alerts", {})

        # DGA detection
        dga_count = alerts.get("dga_count", 0)
        if dga_count > 0:
            rule = self.detection_rules["dga_detected"]
            dga_detections = dns_analysis.get("dga_detections", [])
            domains = [d.get("domain", "") for d in dga_detections[:5]]
            for tech in rule["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=min(0.5 + (dga_count * 0.1), 1.0),
                        evidence=[f"DGA domains detected: {', '.join(domains)}"],
                    )
                )

        # DNS tunneling
        tunneling_count = alerts.get("tunneling_count", 0)
        if tunneling_count > 0:
            rule = self.detection_rules["dns_tunneling"]
            for tech in rule["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=min(0.6 + (tunneling_count * 0.1), 1.0),
                        evidence=[f"DNS tunneling indicators: {tunneling_count} suspicious queries"],
                    )
                )

        # Fast flux
        fast_flux_count = alerts.get("fast_flux_count", 0)
        if fast_flux_count > 0:
            rule = self.detection_rules["dns_fast_flux"]
            for tech in rule["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=min(0.5 + (fast_flux_count * 0.15), 1.0),
                        evidence=[f"Fast flux DNS detected for {fast_flux_count} domains"],
                    )
                )

        return techniques

    def _check_tls(self, tls_analysis: dict) -> list[TechniqueMatch]:
        """Check TLS certificate analysis for anomalies."""
        techniques = []
        alerts = tls_analysis.get("alerts", [])
        # The TLS stage uses ``alerts`` for aggregate counters while older
        # callers may provide a list of detailed alert objects.  Only the
        # latter can support a certificate-level ATT&CK hypothesis.
        if isinstance(alerts, dict):
            alerts = tls_analysis.get("certificate_alerts", [])

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            alert_type = alert.get("type", "")

            if alert_type == "self_signed":
                rule = self.detection_rules["self_signed_cert"]
                cert = alert.get("cert", "unknown")
                for tech in rule["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=0.7,
                            evidence=[f"Self-signed certificate: {cert}"],
                        )
                    )

            elif alert_type == "expired":
                rule = self.detection_rules["expired_cert"]
                cert = alert.get("cert", "unknown")
                for tech in rule["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=0.5,
                            evidence=[f"Expired certificate: {cert}"],
                        )
                    )

        return techniques

    def _check_yara(self, yara_results: dict) -> list[TechniqueMatch]:
        """Check YARA scan results."""
        techniques = []
        by_severity = yara_results.get("by_severity", {})

        # Critical matches
        if by_severity.get("critical", 0) > 0:
            rule = self.detection_rules["yara_critical"]
            results = yara_results.get("results", [])
            critical_files = [r.get("file_name", "") for r in results if r.get("severity") == "critical"]
            for tech in rule["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=0.9,
                        evidence=[f"Critical YARA matches in: {', '.join(critical_files[:3])}"],
                    )
                )

        # High matches
        if by_severity.get("high", 0) > 0:
            rule = self.detection_rules["yara_high"]
            results = yara_results.get("results", [])
            high_files = [r.get("file_name", "") for r in results if r.get("severity") == "high"]
            for tech in rule["techniques"]:
                techniques.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=0.75,
                        evidence=[f"High-severity YARA matches in: {', '.join(high_files[:3])}"],
                    )
                )

        return techniques

    def _check_ja3(self, ja3_data: dict) -> list[TechniqueMatch]:
        """Check JA3 fingerprints for known malware."""
        techniques = []
        rule = self.detection_rules["ja3_malware"]

        for ja3_hash, info in ja3_data.items():
            if isinstance(info, dict) and info.get("malware"):
                client = info.get("client", "Unknown")
                for tech in rule["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=0.85,
                            evidence=[f"Malicious JA3 fingerprint: {client} ({ja3_hash[:16]}...)"],
                        )
                    )

        return techniques

    def _check_ja3_from_features(self, features: dict) -> list[TechniqueMatch]:
        """Check JA3 fingerprints from features artifacts for known malware signatures."""
        techniques = []
        artifacts = features.get("artifacts", {})
        ja3_list = artifacts.get("ja3", [])[:MAX_JA3_FINGERPRINTS]

        if not ja3_list:
            return techniques

        # Known malicious JA3 patterns (subset for demonstration)
        # In production, this would query a threat intel database
        known_malware_ja3 = {
            "72a589da586844d7f0818ce684948eea": "Emotet",
            "a0e9f5d64349fb13191bc781f81f42e1": "TrickBot",
        }

        for ja3 in ja3_list:
            ja3_hash = ja3 if isinstance(ja3, str) else ja3.get("hash", "")
            if ja3_hash in known_malware_ja3:
                malware_name = known_malware_ja3[ja3_hash]
                techniques.append(
                    TechniqueMatch(
                        technique_id="T1071.001",
                        technique_name="Web Protocols",
                        tactic="command-and-control",
                        confidence=0.85,
                        evidence=[f"Known malware JA3 fingerprint detected: {malware_name}"],
                    )
                )

        return techniques

    def _check_data_transfer(self, features: dict) -> list[TechniqueMatch]:
        """Check for large data transfers indicating exfiltration."""
        techniques = []
        flows = features.get("flows", [])
        rule = self.detection_rules["large_outbound"]
        threshold = rule["threshold"]

        # Calculate total outbound bytes per destination
        outbound_by_dst: dict[str, int] = {}
        for flow in flows:
            dst = flow.get("dst", "")
            bytes_count = flow.get("bytes", 0) or flow.get("count", 0) * AVG_PACKET_SIZE_ESTIMATE
            if dst:
                outbound_by_dst[dst] = outbound_by_dst.get(dst, 0) + bytes_count

        for dst, total_bytes in outbound_by_dst.items():
            if total_bytes >= threshold:
                for tech in rule["techniques"]:
                    techniques.append(
                        TechniqueMatch(
                            technique_id=tech["id"],
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=min(0.5 + (total_bytes / threshold) * 0.1, 0.9),
                            evidence=[f"Large data transfer to {dst}: {total_bytes / 1_000_000:.1f} MB"],
                        )
                    )

        return techniques

    def _check_suspicious_ports(self, features: dict) -> list[TechniqueMatch]:
        """Map configured C2-suspect ports without treating every high port as C2."""
        matches: list[TechniqueMatch] = []
        seen: set[tuple[str, int]] = set()
        rule = self.detection_rules["non_standard_port"]
        for flow in (features.get("flows") or [])[:MAX_FLOWS]:
            try:
                port = int(flow.get("dport"))
            except (TypeError, ValueError):
                continue
            dst = str(flow.get("dst") or "unknown")
            key = (dst, port)
            if port not in C.C2_SUSPECT_PORTS or key in seen:
                continue
            seen.add(key)
            for tech in rule["techniques"]:
                matches.append(
                    TechniqueMatch(
                        technique_id=tech["id"],
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=0.7,
                        evidence=[f"C2-suspect destination port {port} observed to {dst}"],
                    )
                )
        return matches

    def _deduplicate_techniques(self, techniques: list[TechniqueMatch]) -> list[TechniqueMatch]:
        """Deduplicate techniques, keeping highest confidence and merging evidence."""
        seen: dict[str, TechniqueMatch] = {}

        for tech in techniques:
            key = f"{tech.technique_id}:{tech.tactic}"
            if key in seen:
                # Merge evidence and keep higher confidence
                existing = seen[key]
                existing.confidence = max(existing.confidence, tech.confidence)
                existing.evidence.extend(tech.evidence)
                existing.data_components.extend(tech.data_components)
                existing.limitations.extend(tech.limitations)
                existing.references.extend(tech.references)
            else:
                seen[key] = TechniqueMatch(
                    technique_id=tech.technique_id,
                    technique_name=tech.technique_name,
                    tactic=tech.tactic,
                    confidence=tech.confidence,
                    evidence=list(tech.evidence),
                    analytic_id=tech.analytic_id,
                    data_components=list(tech.data_components),
                    limitations=list(tech.limitations),
                    references=list(tech.references),
                    disposition=tech.disposition,
                    analyst_note=tech.analyst_note,
                )

        return list(seen.values())

    def _annotate_techniques(self, techniques: list[TechniqueMatch]) -> None:
        """Attach ATT&CK analytic context and de-duplicate evidence metadata."""
        for technique in techniques:
            metadata = TECHNIQUE_METADATA.get(technique.technique_id, {})
            analytic_id = metadata.get("analytic_id")
            evidence_text = " ".join(technique.evidence).lower()
            # DET0027 is specifically a web-protocol analytic. A generic
            # periodic flow may still be a T1071.001 hypothesis, but it must
            # not be presented as coverage of that analytic without HTTP/S
            # evidence.
            if technique.technique_id == "T1071.001" and not any(
                token in evidence_text for token in ("http", "https", "web protocol")
            ):
                analytic_id = None
            technique.analytic_id = technique.analytic_id or analytic_id
            metadata_components = metadata.get("data_components", [])
            if technique.technique_id == "T1071.001" and analytic_id is None:
                metadata_components = ["Network Traffic Flow"]
            technique.data_components = list(dict.fromkeys(technique.data_components + metadata_components))
            technique.limitations = list(dict.fromkeys(technique.limitations + metadata.get("limitations", [])))
            technique.references = list(dict.fromkeys(technique.references + metadata.get("references", [])))
            technique.disposition = (
                technique.disposition if technique.disposition in VALID_DISPOSITIONS else "unreviewed"
            )

    def _calculate_tactics_summary(self, techniques: list[TechniqueMatch]) -> dict[str, int]:
        """Calculate tactics summary from techniques."""
        summary: dict[str, int] = {}
        for tech in techniques:
            tactic = tech.tactic
            summary[tactic] = summary.get(tactic, 0) + 1
        return summary

    def _determine_kill_chain_phase(self, tactics_summary: dict[str, int]) -> str:
        """Determine the most advanced kill chain phase detected."""
        if not tactics_summary:
            return "unknown"

        # Find the most advanced phase
        max_index = -1
        advanced_phase = "unknown"

        for tactic in tactics_summary.keys():
            if tactic in KILL_CHAIN_ORDER:
                index = KILL_CHAIN_ORDER.index(tactic)
                if index > max_index:
                    max_index = index
                    advanced_phase = tactic

        return advanced_phase

    def _calculate_severity(self, techniques: list[TechniqueMatch]) -> str:
        """Calculate overall severity based on techniques and confidence."""
        if not techniques:
            return "low"

        # Check for high-impact tactics
        high_impact_tactics = {"exfiltration", "impact", "command-and-control"}
        max_confidence = max(t.confidence for t in techniques)

        has_high_impact = any(t.tactic in high_impact_tactics for t in techniques)
        technique_count = len(techniques)

        if has_high_impact and max_confidence >= 0.8:
            return "critical"
        elif has_high_impact or max_confidence >= 0.7:
            return "high"
        elif technique_count >= 3 or max_confidence >= 0.5:
            return "medium"
        else:
            return "low"

    def to_json(self, mapping: AttackMapping) -> str:
        """Convert mapping to JSON string."""
        return json.dumps(mapping.to_dict(), indent=2)
