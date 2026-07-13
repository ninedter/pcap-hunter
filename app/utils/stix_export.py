"""STIX 2.1 export utilities."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.utils.ioc_export import IOCRecord

logger = logging.getLogger(__name__)


def _escape_stix_value(value: str) -> str:
    """Escape single quotes in STIX pattern values."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_hash_property(value: str) -> str | None:
    """STIX hash property name from hex-digest length. None if unrecognized."""
    return {32: "MD5", 40: "'SHA-1'", 64: "'SHA-256'", 128: "'SHA-512'"}.get(len(value))


def ioc_to_stix_pattern(ioc_type: str, value: str) -> str | None:
    """Build a STIX 2.1 comparison-expression pattern for an IOC. None if unmappable."""
    escaped = _escape_stix_value(value)
    if ioc_type == "ip":
        kind = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{kind}:value = '{escaped}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{escaped}']"
    if ioc_type == "url":
        return f"[url:value = '{escaped}']"
    if ioc_type == "hash":
        prop = stix_hash_property(value)
        return f"[file:hashes.{prop} = '{escaped}']" if prop else None
    if ioc_type == "ja3":
        return f"[x509-certificate:hashes.'JA3' = '{escaped}']"
    return None


# Try to import stix2 library
try:
    import stix2

    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False
    logger.info("stix2 library not installed, using basic STIX export")


def generate_stix_id(type_name: str, value: str) -> str:
    """Generate deterministic STIX ID from type and value."""
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace
    generated_uuid = uuid.uuid5(namespace, f"{type_name}:{value}")
    return f"{type_name}--{generated_uuid}"


class STIXExporter:
    """Export analysis results to STIX 2.1 format."""

    def __init__(
        self,
        features: dict | None = None,
        osint: dict | None = None,
        identity_name: str = "PCAP Hunter",
    ):
        """
        Initialize STIX exporter.

        Args:
            features: Analysis features containing artifacts
            osint: OSINT enrichment results
            identity_name: Name for the identity object
        """
        self.features = features or {}
        self.osint = osint or {}
        self.identity_name = identity_name
        self._identity_id = generate_stix_id("identity", identity_name)

    def _create_identity(self) -> dict:
        """Create identity object for the tool."""
        if STIX2_AVAILABLE:
            identity = stix2.Identity(
                id=self._identity_id,
                name=self.identity_name,
                identity_class="system",
                description="Automated PCAP analysis tool for threat hunting",
            )
            return json.loads(identity.serialize())
        else:
            return {
                "type": "identity",
                "spec_version": "2.1",
                "id": self._identity_id,
                "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "modified": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "name": self.identity_name,
                "identity_class": "system",
                "description": "Automated PCAP analysis tool for threat hunting",
            }

    def _ioc_to_pattern(self, ioc: "IOCRecord") -> str | None:
        """Convert IOC to STIX pattern."""
        return ioc_to_stix_pattern(ioc.ioc_type, ioc.value)

    def _get_indicator_labels(self, ioc: "IOCRecord") -> list[str]:
        """Get indicator labels based on IOC data."""
        labels = []

        # Add type-based label
        type_labels = {
            "ip": "network-activity",
            "domain": "network-activity",
            "url": "network-activity",
            "hash": "malicious-activity",
            "ja3": "malicious-activity",
        }
        labels.append(type_labels.get(ioc.ioc_type, "anomalous-activity"))

        # Add tags as labels
        for tag in ioc.tags:
            if tag not in labels:
                labels.append(tag)

        return labels

    def _create_indicator(self, ioc: "IOCRecord") -> dict | None:
        """
        Create STIX Indicator from IOC.

        Args:
            ioc: IOC record to convert

        Returns:
            STIX indicator dict or None if creation failed
        """
        try:
            pattern = self._ioc_to_pattern(ioc)
            if not pattern:
                return None

            indicator_id = generate_stix_id("indicator", ioc.value)
            labels = self._get_indicator_labels(ioc)
            now = datetime.now(timezone.utc)

            # Determine confidence (1-100)
            confidence = min(int(ioc.priority_score * 100), 100)
        except (ValueError, TypeError, KeyError) as e:
            logger.warning("Failed to create indicator for IOC %s: %s", ioc.value, e)
            return None

        # Build description
        description_parts = ["IOC extracted from PCAP analysis"]
        if ioc.context:
            description_parts.append(f"Context: {ioc.context}")
        if ioc.osint_summary:
            osint_info = []
            if "vt_detections" in ioc.osint_summary:
                osint_info.append(f"VT: {ioc.osint_summary['vt_detections']}/{ioc.osint_summary.get('vt_total', 70)}")
            if "greynoise" in ioc.osint_summary:
                osint_info.append(f"GreyNoise: {ioc.osint_summary['greynoise']}")
            if "abuseipdb_score" in ioc.osint_summary:
                osint_info.append(f"AbuseIPDB: {ioc.osint_summary['abuseipdb_score']}%")
            if osint_info:
                description_parts.append(f"OSINT: {', '.join(osint_info)}")
        description = ". ".join(description_parts)

        if STIX2_AVAILABLE:
            try:
                indicator = stix2.Indicator(
                    id=indicator_id,
                    name=f"{ioc.ioc_type.upper()}: {ioc.value}",
                    description=description,
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=now,
                    labels=labels,
                    confidence=confidence,
                    created_by_ref=self._identity_id,
                )
                return json.loads(indicator.serialize())
            except Exception as e:
                logger.warning("Failed to create STIX indicator with stix2: %s", e)
                # Fall through to basic format

        # Basic format fallback
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now.isoformat().replace("+00:00", "Z"),
            "modified": now.isoformat().replace("+00:00", "Z"),
            "name": f"{ioc.ioc_type.upper()}: {ioc.value}",
            "description": description,
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now.isoformat().replace("+00:00", "Z"),
            "labels": labels,
            "confidence": confidence,
            "created_by_ref": self._identity_id,
        }

    def _create_observable(self, ioc: "IOCRecord") -> dict | None:
        """Create STIX Cyber Observable from IOC."""
        # Create the appropriate SCO (STIX Cyber Observable)
        sco = None

        if ioc.ioc_type == "ip":
            sco_type = "ipv6-addr" if ":" in ioc.value else "ipv4-addr"
            sco_id = generate_stix_id(sco_type, ioc.value)
            sco = {
                "type": sco_type,
                "spec_version": "2.1",
                "id": sco_id,
                "value": ioc.value,
            }
        elif ioc.ioc_type == "domain":
            sco_id = generate_stix_id("domain-name", ioc.value)
            sco = {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": sco_id,
                "value": ioc.value,
            }
        elif ioc.ioc_type == "url":
            sco_id = generate_stix_id("url", ioc.value)
            sco = {
                "type": "url",
                "spec_version": "2.1",
                "id": sco_id,
                "value": ioc.value,
            }
        elif ioc.ioc_type == "hash":
            sco_id = generate_stix_id("file", ioc.value)
            hash_type = self._determine_hash_type(ioc.value)
            sco = {
                "type": "file",
                "spec_version": "2.1",
                "id": sco_id,
                "hashes": {hash_type: ioc.value},
            }

        return sco

    def _determine_hash_type(self, hash_value: str) -> str:
        """Determine hash type from length."""
        hash_len = len(hash_value)
        if hash_len == 32:
            return "MD5"
        elif hash_len == 40:
            return "SHA-1"
        elif hash_len == 64:
            return "SHA-256"
        elif hash_len == 128:
            return "SHA-512"
        return "UNKNOWN"

    def export_bundle(self, iocs: list["IOCRecord"]) -> bytes:
        """
        Export IOCs as STIX 2.1 Bundle.

        Args:
            iocs: List of IOCRecord objects

        Returns:
            UTF-8 encoded STIX JSON bytes
        """
        objects = []

        # Add identity
        identity = self._create_identity()
        objects.append(identity)

        # Track created SCOs for relationships
        sco_objects = []

        # Create indicators and observables
        for ioc in iocs:
            # Create indicator
            indicator = self._create_indicator(ioc)
            if indicator:
                objects.append(indicator)

            # Create observable
            sco = self._create_observable(ioc)
            if sco:
                sco_objects.append(sco)

        # Add all SCOs
        objects.extend(sco_objects)

        # Create bundle
        bundle_id = f"bundle--{uuid.uuid4()}"

        if STIX2_AVAILABLE:
            try:
                bundle = stix2.Bundle(id=bundle_id, objects=objects)
                return bundle.serialize(pretty=True).encode("utf-8")
            except Exception as e:
                logger.warning("Failed to create STIX bundle with stix2: %s", e)
                # Fall through to basic format

        # Basic format fallback
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

        return json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8")

    def export_with_attack_patterns(
        self,
        iocs: list["IOCRecord"],
        attack_mapping: Any | None = None,
    ) -> bytes:
        """
        Export IOCs with ATT&CK patterns as STIX 2.1 Bundle.

        Args:
            iocs: List of IOCRecord objects
            attack_mapping: Optional AttackMapping object

        Returns:
            UTF-8 encoded STIX JSON bytes
        """
        objects = []

        # Add identity
        identity = self._create_identity()
        objects.append(identity)

        # Create indicators
        indicator_ids = []
        for ioc in iocs:
            indicator = self._create_indicator(ioc)
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator["id"])

        # Add attack patterns if mapping provided
        if attack_mapping and hasattr(attack_mapping, "techniques"):
            for tech in attack_mapping.techniques:
                attack_pattern_id = generate_stix_id("attack-pattern", tech.technique_id)

                attack_pattern = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": attack_pattern_id,
                    "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "modified": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "name": tech.technique_name,
                    "description": f"MITRE ATT&CK Technique {tech.technique_id}",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tech.technique_id,
                            "url": f"https://attack.mitre.org/techniques/{tech.technique_id.replace('.', '/')}/",
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": tech.tactic,
                        }
                    ],
                }
                objects.append(attack_pattern)

                # Create relationships from indicators to attack patterns
                for indicator_id in indicator_ids:
                    relationship = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": generate_stix_id("relationship", f"{indicator_id}:{attack_pattern_id}"),
                        "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "modified": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "relationship_type": "indicates",
                        "source_ref": indicator_id,
                        "target_ref": attack_pattern_id,
                        "created_by_ref": self._identity_id,
                    }
                    objects.append(relationship)

        # Create bundle
        bundle_id = f"bundle--{uuid.uuid4()}"
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

        return json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8")


def generate_stix_filename() -> str:
    """Generate timestamped filename for STIX export."""
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"stix_bundle_{timestamp}.json"


def validate_stix_bundle(bundle_json: bytes) -> tuple[bool, list[str]]:
    """
    Validate STIX bundle structure.

    Args:
        bundle_json: JSON bytes to validate

    Returns:
        Tuple of (is_valid, list of errors)
    """
    errors = []

    try:
        data = json.loads(bundle_json.decode("utf-8"))
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]

    # Check bundle structure
    if data.get("type") != "bundle":
        errors.append("Missing or invalid 'type' field (expected 'bundle')")

    if "id" not in data:
        errors.append("Missing 'id' field")
    elif not data["id"].startswith("bundle--"):
        errors.append("Invalid bundle ID format")

    if "objects" not in data:
        errors.append("Missing 'objects' field")
    elif not isinstance(data["objects"], list):
        errors.append("'objects' field must be an array")
    else:
        # Validate each object
        for i, obj in enumerate(data["objects"]):
            if not isinstance(obj, dict):
                errors.append(f"Object {i} is not a dictionary")
                continue
            if "type" not in obj:
                errors.append(f"Object {i} missing 'type' field")
            if "id" not in obj:
                errors.append(f"Object {i} missing 'id' field")

    return len(errors) == 0, errors
