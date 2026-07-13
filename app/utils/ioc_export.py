"""IOC export utilities for multiple formats."""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.utils.export import _sanitize_csv_value

# Namespace UUID for deterministic STIX ID generation
STIX_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

logger = logging.getLogger(__name__)


@dataclass
class IOCRecord:
    """Represents an extracted IOC."""

    ioc_type: str  # ip, domain, hash, ja3, url
    value: str
    context: str = ""  # Where it was found
    first_seen: str = ""
    last_seen: str = ""
    priority_score: float = 0.0
    osint_summary: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.ioc_type,
            "value": self.value,
            "context": self.context,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "priority_score": self.priority_score,
            "osint_summary": self.osint_summary,
            "tags": self.tags,
        }


class IOCExporter:
    """Export IOCs in multiple formats."""

    def __init__(
        self,
        features: dict | None = None,
        osint: dict | None = None,
        scores: dict | None = None,
    ):
        """
        Initialize IOC exporter.

        Args:
            features: Analysis features containing artifacts
            osint: OSINT enrichment results
            scores: IOC priority scores (optional)
        """
        self.features = features or {}
        self.osint = osint or {}
        self.scores = scores or {}
        self._iocs: list[IOCRecord] | None = None

    def extract_iocs(self) -> list[IOCRecord]:
        """Extract all IOCs from analysis results."""
        if self._iocs is not None:
            return self._iocs

        iocs: list[IOCRecord] = []
        artifacts = self.features.get("artifacts", {})

        # Extract IPs
        for ip in artifacts.get("ips", []):
            osint_data = self._get_osint_for_ip(ip)
            score = self.scores.get(ip, 0.0)
            iocs.append(
                IOCRecord(
                    ioc_type="ip",
                    value=ip,
                    context="Network flow",
                    priority_score=score,
                    osint_summary=osint_data,
                    tags=self._get_tags_for_osint(osint_data),
                )
            )

        # Extract domains
        for domain in artifacts.get("domains", []):
            osint_data = self._get_osint_for_domain(domain)
            score = self.scores.get(domain, 0.0)
            iocs.append(
                IOCRecord(
                    ioc_type="domain",
                    value=domain,
                    context="DNS query or HTTP host",
                    priority_score=score,
                    osint_summary=osint_data,
                    tags=self._get_tags_for_osint(osint_data),
                )
            )

        # Extract hashes
        for hash_value in artifacts.get("hashes", []):
            iocs.append(
                IOCRecord(
                    ioc_type="hash",
                    value=hash_value,
                    context="Carved file",
                    priority_score=self.scores.get(hash_value, 0.0),
                )
            )

        # Extract JA3 fingerprints
        for ja3 in artifacts.get("ja3", []):
            ja3_info = self.osint.get("ja3", {}).get(ja3, {})
            tags = []
            if ja3_info.get("malware"):
                tags.append("malware")
            if ja3_info.get("client"):
                tags.append(ja3_info["client"])

            iocs.append(
                IOCRecord(
                    ioc_type="ja3",
                    value=ja3,
                    context="TLS handshake",
                    priority_score=self.scores.get(ja3, 0.0),
                    osint_summary=ja3_info,
                    tags=tags,
                )
            )

        # Extract URLs if present
        for url in artifacts.get("urls", []):
            iocs.append(
                IOCRecord(
                    ioc_type="url",
                    value=url,
                    context="HTTP request",
                    priority_score=self.scores.get(url, 0.0),
                )
            )

        self._iocs = iocs
        return iocs

    def _get_osint_for_ip(self, ip: str) -> dict:
        """Get OSINT data for an IP."""
        ip_osint = self.osint.get("ips", {}).get(ip, {})
        summary = {}

        if "virustotal" in ip_osint:
            vt = ip_osint["virustotal"]
            summary["vt_detections"] = vt.get("detections", 0)
            summary["vt_total"] = vt.get("total", 0)

        if "greynoise" in ip_osint:
            gn = ip_osint["greynoise"]
            summary["greynoise"] = gn.get("classification", "unknown")

        if "abuseipdb" in ip_osint:
            abuse = ip_osint["abuseipdb"]
            summary["abuseipdb_score"] = abuse.get("score", 0)

        return summary

    def _get_osint_for_domain(self, domain: str) -> dict:
        """Get OSINT data for a domain."""
        domain_osint = self.osint.get("domains", {}).get(domain, {})
        summary = {}

        if "virustotal" in domain_osint:
            vt = domain_osint["virustotal"]
            summary["vt_detections"] = vt.get("detections", 0)
            summary["vt_total"] = vt.get("total", 0)

        if "category" in domain_osint:
            summary["category"] = domain_osint["category"]

        return summary

    def _get_tags_for_osint(self, osint_data: dict) -> list[str]:
        """Generate tags based on OSINT data."""
        tags = []

        if osint_data.get("vt_detections", 0) > 0:
            tags.append("vt-positive")
        if osint_data.get("greynoise") == "malicious":
            tags.append("malicious")
        if osint_data.get("abuseipdb_score", 0) > 50:
            tags.append("abused")
        if osint_data.get("category") in ["malware", "phishing", "c2"]:
            tags.append(osint_data["category"])

        return tags

    def filter_iocs(
        self,
        iocs: list[IOCRecord],
        ioc_types: list[str] | None = None,
        min_score: float = 0.0,
        tags: list[str] | None = None,
    ) -> list[IOCRecord]:
        """Filter IOCs by criteria."""
        filtered = iocs

        if ioc_types:
            filtered = [i for i in filtered if i.ioc_type in ioc_types]

        if min_score > 0:
            filtered = [i for i in filtered if i.priority_score >= min_score]

        if tags:
            filtered = [i for i in filtered if any(t in i.tags for t in tags)]

        return filtered

    def export_csv(self, ioc_types: list[str] | None = None, min_score: float = 0.0) -> bytes:
        """
        Export IOCs to CSV format.

        Args:
            ioc_types: Filter to specific types (ip, domain, hash, ja3, url)
            min_score: Minimum priority score

        Returns:
            UTF-8 encoded CSV bytes
        """
        iocs = self.extract_iocs()
        iocs = self.filter_iocs(iocs, ioc_types, min_score)

        if not iocs:
            return b"type,value,context,priority_score,tags,osint_summary\n"

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(["type", "value", "context", "priority_score", "tags", "osint_summary"])

        for ioc in iocs:
            writer.writerow(
                [
                    _sanitize_csv_value(ioc.ioc_type),
                    _sanitize_csv_value(ioc.value),
                    _sanitize_csv_value(ioc.context),
                    f"{ioc.priority_score:.2f}",
                    _sanitize_csv_value("; ".join(ioc.tags)),
                    _sanitize_csv_value(json.dumps(ioc.osint_summary) if ioc.osint_summary else ""),
                ]
            )

        return output.getvalue().encode("utf-8")

    def export_json(self, ioc_types: list[str] | None = None, min_score: float = 0.0) -> bytes:
        """
        Export IOCs to JSON format.

        Args:
            ioc_types: Filter to specific types
            min_score: Minimum priority score

        Returns:
            UTF-8 encoded JSON bytes
        """
        iocs = self.extract_iocs()
        iocs = self.filter_iocs(iocs, ioc_types, min_score)

        data = {
            "exported_at": datetime.now(tz=timezone.utc).isoformat(),
            "total_count": len(iocs),
            "iocs": [ioc.to_dict() for ioc in iocs],
        }

        return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")

    def export_txt(self, ioc_types: list[str] | None = None, min_score: float = 0.0) -> bytes:
        """
        Export IOCs as plain text (one per line).

        Useful for firewall block lists.

        Args:
            ioc_types: Filter to specific types
            min_score: Minimum priority score

        Returns:
            UTF-8 encoded text bytes
        """
        iocs = self.extract_iocs()
        iocs = self.filter_iocs(iocs, ioc_types, min_score)

        lines = [ioc.value for ioc in iocs]
        return "\n".join(lines).encode("utf-8")

    def export_stix(self, ioc_types: list[str] | None = None, min_score: float = 0.0) -> bytes:
        """
        Export IOCs as STIX 2.1 Bundle.

        Args:
            ioc_types: Filter to specific types
            min_score: Minimum priority score

        Returns:
            UTF-8 encoded STIX JSON bytes
        """
        # Import here to make stix2 optional
        try:
            from app.utils.stix_export import STIXExporter

            exporter = STIXExporter(self.features, self.osint)
            iocs = self.extract_iocs()
            iocs = self.filter_iocs(iocs, ioc_types, min_score)
            return exporter.export_bundle(iocs)
        except ImportError:
            logger.warning("stix2 library not installed, falling back to basic format")
            return self._export_stix_basic(ioc_types, min_score)

    def _export_stix_basic(self, ioc_types: list[str] | None = None, min_score: float = 0.0) -> bytes:
        """Basic STIX export without stix2 library."""
        iocs = self.extract_iocs()
        iocs = self.filter_iocs(iocs, ioc_types, min_score)

        # Create basic STIX-like structure
        objects = []

        # Identity
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--pcap-hunter",
            "name": "PCAP Hunter",
            "identity_class": "tool",
        }
        objects.append(identity)

        # Indicators
        for ioc in iocs:
            pattern = self._ioc_to_stix_pattern(ioc)
            if pattern:
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid5(STIX_NAMESPACE, ioc.value)}",
                    "name": f"{ioc.ioc_type.upper()}: {ioc.value}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                    "labels": ioc.tags or ["network-activity"],
                    "confidence": int(ioc.priority_score * 100),
                    "created_by_ref": identity["id"],
                }
                objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        return json.dumps(bundle, indent=2).encode("utf-8")

    def _ioc_to_stix_pattern(self, ioc: IOCRecord) -> str | None:
        """Convert IOC to STIX pattern via the shared serializer."""
        from app.utils.stix_export import ioc_to_stix_pattern

        return ioc_to_stix_pattern(ioc.ioc_type, ioc.value)


def generate_ioc_filename(format_type: str) -> str:
    """Generate timestamped filename for IOC export."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    extensions = {
        "csv": "csv",
        "json": "json",
        "txt": "txt",
        "stix": "json",
    }
    ext = extensions.get(format_type, "txt")
    return f"iocs_{timestamp}.{ext}"
