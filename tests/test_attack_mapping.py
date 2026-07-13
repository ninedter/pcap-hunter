"""Tests for the ATT&CK mapping engine (app/threat_intel/attack_mapping.py).

The mapper was built but never instantiated at runtime until it was wired
into app/pipeline/runner.py — these tests use production-shape output from
the real analysis stages (app/pipeline/tls_certs.py, app/pipeline/dns_analysis.py,
app/pipeline/beacon.py) rather than "looks reasonable" dicts, since a shape
mismatch here previously escaped notice precisely because the mapper was dead
code (see the `_check_tls` fix in this same change).
"""

from __future__ import annotations

from app.threat_intel import ATTACKMapper


class TestCheckTLS:
    """Regression coverage for the tls_analysis shape consumed by _check_tls."""

    def test_self_signed_certificate_is_detected(self):
        """analyze_certificates() reports per-cert flags in `certificates`, not a
        list of {"type": ..., "cert": ...} alert objects — must not raise.
        """
        tls_analysis = {
            "total_certificates": 1,
            "certificates": [
                {
                    "subject_cn": "evil.example",
                    "is_self_signed": True,
                    "is_expired": False,
                }
            ],
            "alerts": {"self_signed_count": 1, "expired_count": 0, "high_risk_count": 0},
        }
        mapping = ATTACKMapper().map_analysis(tls_analysis=tls_analysis)
        ids = {t.technique_id for t in mapping.techniques}
        assert "T1587.003" in ids
        assert "T1573.002" in ids
        evidence = [e for t in mapping.techniques for e in t.evidence]
        assert any("evil.example" in e for e in evidence)

    def test_expired_certificate_is_detected(self):
        tls_analysis = {
            "total_certificates": 1,
            "certificates": [
                {
                    "subject_cn": "stale.example",
                    "is_self_signed": False,
                    "is_expired": True,
                }
            ],
            "alerts": {"self_signed_count": 0, "expired_count": 1, "high_risk_count": 0},
        }
        mapping = ATTACKMapper().map_analysis(tls_analysis=tls_analysis)
        ids = {t.technique_id for t in mapping.techniques}
        assert "T1573.002" in ids

    def test_clean_certificates_produce_no_techniques(self):
        tls_analysis = {
            "total_certificates": 1,
            "certificates": [
                {
                    "subject_cn": "clean.example",
                    "is_self_signed": False,
                    "is_expired": False,
                }
            ],
            "alerts": {"self_signed_count": 0, "expired_count": 0, "high_risk_count": 0},
        }
        mapping = ATTACKMapper().map_analysis(tls_analysis=tls_analysis)
        assert mapping.techniques == []

    def test_missing_certificates_key_does_not_raise(self):
        """Older/partial tls_analysis dicts without a certificates key are tolerated."""
        mapping = ATTACKMapper().map_analysis(tls_analysis={"alerts": {}})
        assert mapping.techniques == []


class TestMapAnalysisEndToEnd:
    """map_analysis() called the way app/pipeline/runner.py calls it (no yara/osint)."""

    def test_combined_production_shape_inputs_produce_a_mapping(self):
        features = {
            "flows": [{"dst": "1.2.3.4", "count": 5, "bytes": 20_000_000}],
            "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
        }
        dns_analysis = {"alerts": {"dga_count": 2, "tunneling_count": 0, "fast_flux_count": 0}}
        tls_analysis = {
            "certificates": [{"subject_cn": "c2.example", "is_self_signed": True, "is_expired": False}],
            "alerts": {"self_signed_count": 1, "expired_count": 0, "high_risk_count": 0},
        }
        beacon_results = [{"dst": "1.2.3.4", "score": 0.85}]

        mapping = ATTACKMapper().map_analysis(
            features=features,
            dns_analysis=dns_analysis,
            tls_analysis=tls_analysis,
            beacon_results=beacon_results,
        )
        ids = {t.technique_id for t in mapping.techniques}
        assert "T1071.001" in ids  # beaconing
        assert "T1587.003" in ids  # self-signed cert
        assert any(tid.startswith("T1568") for tid in ids)  # DGA
        assert mapping.overall_severity in {"low", "medium", "high", "critical"}
        d = mapping.to_dict()
        assert "techniques" in d and "tactics_summary" in d
