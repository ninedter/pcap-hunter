"""MITRE ATT&CK mapping engine for PCAP analysis results."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from app.pipeline.ja3 import lookup_ja3

logger = logging.getLogger(__name__)

# Valid IOC types for validation
VALID_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "file", "ja3"}

# Maximum values to process to prevent resource exhaustion
MAX_BEACON_RESULTS = 20
MAX_YARA_RESULTS = 20
MAX_TLS_ALERTS = 20
MAX_JA3_FINGERPRINTS = 50
MAX_FLOWS = 1000

# Confidence assigned to a malicious JA3 match, keyed by the authoritative
# severity from app.pipeline.ja3.KNOWN_JA3_FINGERPRINTS. Unknown/missing
# severities fall back to JA3_DEFAULT_CONFIDENCE.
JA3_SEVERITY_CONFIDENCE = {
    "critical": 0.9,
    "high": 0.75,
    "medium": 0.6,
    "low": 0.4,
}
JA3_DEFAULT_CONFIDENCE = 0.75

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

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class AttackMapping:
    """Complete ATT&CK mapping for an analysis."""

    techniques: list[TechniqueMatch] = field(default_factory=list)
    tactics_summary: dict[str, int] = field(default_factory=dict)  # tactic -> count
    kill_chain_phase: str = "unknown"  # Most advanced phase detected
    overall_severity: str = "low"  # low, medium, high, critical

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics_summary": self.tactics_summary,
            "kill_chain_phase": self.kill_chain_phase,
            "overall_severity": self.overall_severity,
        }


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
                "id": "T1587.003",
                "name": "Develop Capabilities: Digital Certificates",
                "tactic": "resource-development",
            },
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


class ATTACKMapper:
    """Maps analysis results to MITRE ATT&CK techniques."""

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

        # Deduplicate techniques
        techniques = self._deduplicate_techniques(techniques)

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
                    evidence = f"Beaconing detected with score {score:.2f} to {beacon.get('dst', 'unknown')}"
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

        for alert in alerts:
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

        for ja3 in ja3_list:
            ja3_hash = ja3 if isinstance(ja3, str) else ja3.get("hash", "")
            match = lookup_ja3(ja3_hash)
            if match and match.get("malware"):
                client = match.get("client", "Unknown")
                confidence = JA3_SEVERITY_CONFIDENCE.get(match.get("severity"), JA3_DEFAULT_CONFIDENCE)
                techniques.append(
                    TechniqueMatch(
                        technique_id="T1071.001",
                        technique_name="Web Protocols",
                        tactic="command-and-control",
                        confidence=confidence,
                        evidence=[f"Known malware JA3 fingerprint detected: {client}"],
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
            else:
                seen[key] = TechniqueMatch(
                    technique_id=tech.technique_id,
                    technique_name=tech.technique_name,
                    tactic=tech.tactic,
                    confidence=tech.confidence,
                    evidence=list(tech.evidence),
                )

        return list(seen.values())

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
