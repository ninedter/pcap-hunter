"""Tests for the dedicated MITRE ATT&CK workspace helpers."""

from __future__ import annotations

import pandas as pd

from app.threat_intel.attack_mapping import AttackMapping, TechniqueMatch
from app.ui.mitre_page import _coerce_mapping, build_attack_mapping, build_visibility_rows


def test_build_attack_mapping_uses_production_shaped_session_state():
    state = {
        "features": {
            "flows": [{"src": "10.0.0.1", "dst": "203.0.113.5", "count": 20, "bytes": 12_000_000}],
            "artifacts": {"ips": ["10.0.0.1", "203.0.113.5"], "ja3": []},
        },
        "beacon_df": pd.DataFrame([{"src": "10.0.0.1", "dst": "203.0.113.5", "score": 0.85}]),
        "dns_analysis": {"alerts": {"dga_count": 0, "tunneling_count": 0, "fast_flux_count": 0}},
        "tls_analysis": {"certificates": [], "alerts": {}},
        "yara_results": {"by_severity": {}, "results": []},
        "osint": {},
    }

    mapping = build_attack_mapping(state)

    assert isinstance(mapping, AttackMapping)
    assert mapping.techniques
    assert any(tech.technique_id == "T1071.001" for tech in mapping.techniques)


def test_build_attack_mapping_returns_none_before_analysis():
    assert build_attack_mapping({"features": None}) is None


def test_attack_mapping_round_trips_for_persisted_state():
    original = AttackMapping(
        techniques=[TechniqueMatch("T1071.001", "Web Protocols", "command-and-control", 0.8, ["HTTP"])],
        tactics_summary={"command-and-control": 1},
        kill_chain_phase="command-and-control",
        overall_severity="high",
    )

    restored = AttackMapping.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()


def test_coerce_mapping_restores_persisted_dictionary():
    restored = _coerce_mapping(
        {
            "techniques": [
                {
                    "technique_id": "T1571",
                    "technique_name": "Non-Standard Port",
                    "tactic": "command-and-control",
                    "confidence": 0.7,
                    "disposition": "confirmed",
                    "analyst_note": "Validated against flow evidence.",
                }
            ]
        }
    )

    assert isinstance(restored, AttackMapping)
    assert restored.techniques[0].disposition == "confirmed"
    assert restored.techniques[0].analyst_note == "Validated against flow evidence."


def test_visibility_rows_explicitly_mark_unavailable_detectors():
    rows = build_visibility_rows({"features": None, "zeek_tables": {}, "correlations": None})

    statuses = {row["Detector"]: row["Status"] for row in rows}
    assert statuses["Packet / flow telemetry"] == "unavailable"
    assert statuses["Zeek protocol telemetry"] == "unavailable"
    assert statuses["Cross-indicator correlation"] == "unavailable"
