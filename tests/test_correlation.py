"""Tests for cross-indicator correlation engine."""

from __future__ import annotations

from app.analysis.correlation import (
    CorrelationResult,
    CorrelationSignal,
    _compute_composite,
    _get_verdict,
    correlate_indicators,
)


def test_get_verdict():
    assert _get_verdict(0.8) == "critical"
    assert _get_verdict(0.6) == "high"
    assert _get_verdict(0.4) == "medium"
    assert _get_verdict(0.1) == "low"
    assert _get_verdict(0.0) == "low"


def test_compute_composite_empty():
    assert _compute_composite([]) == 0.0


def test_compute_composite_single_signal():
    signals = [CorrelationSignal("beacon_score", 0.9, 0.9, "beacon")]
    score = _compute_composite(signals)
    assert score > 0
    assert score <= 1.0


def test_correlate_indicators_empty():
    results = correlate_indicators()
    assert results == []


def test_correlate_indicators_with_ip():
    features = {
        "artifacts": {"ips": ["8.8.8.8"], "domains": []},
        "flows": [],
    }
    osint = {
        "ips": {
            "8.8.8.8": {
                "greynoise": {"classification": "malicious"},
            }
        },
        "domains": {},
    }
    results = correlate_indicators(features=features, osint=osint)
    assert len(results) == 1
    assert results[0].indicator == "8.8.8.8"
    assert results[0].indicator_type == "ip"
    assert results[0].composite_score > 0
    assert any(s.name == "greynoise_malicious" for s in results[0].signals)


def test_correlate_indicators_with_domain():
    features = {
        "artifacts": {"ips": [], "domains": ["evil.com"]},
        "flows": [],
    }
    dns_analysis = {
        "dga_detections": [
            {"domain": "evil.com", "is_dga": True, "score": 0.8},
        ],
        "tunneling_detections": [],
    }
    results = correlate_indicators(features=features, dns_analysis=dns_analysis)
    assert len(results) == 1
    assert results[0].indicator == "evil.com"
    assert results[0].indicator_type == "domain"
    assert any(s.name == "dga_domain" for s in results[0].signals)


def test_correlation_result_to_dict():
    cr = CorrelationResult(
        indicator="1.2.3.4",
        indicator_type="ip",
        signals=[CorrelationSignal("beacon_score", 0.7, 0.7, "beacon")],
        composite_score=0.5,
        verdict="medium",
    )
    d = cr.to_dict()
    assert d["indicator"] == "1.2.3.4"
    assert d["type"] == "ip"
    assert d["signal_count"] == 1
    assert d["verdict"] == "medium"


def test_correlate_skips_private_ips():
    features = {
        "artifacts": {"ips": ["192.168.1.1", "10.0.0.1"], "domains": []},
        "flows": [],
    }
    results = correlate_indicators(features=features)
    assert len(results) == 0  # Private IPs filtered out


def _shodan_host(ports: list[int], vulns: list[str]) -> dict:
    """Production-shape Shodan host JSON (top-level keys mirror the real API)."""
    return {
        "ip_str": "45.33.32.156",
        "ports": ports,
        "vulns": vulns,
        "hostnames": ["server.example.net"],
        "org": "Example Hosting Ltd",
        "isp": "Example Hosting Ltd",
        "country_name": "Netherlands",
        "last_update": "2026-06-01T12:00:00.000000",
        "data": [{"port": p, "transport": "tcp", "product": "nginx"} for p in ports],
    }


def test_correlate_shodan_vulns_signal_contributes_to_score():
    features = {
        "artifacts": {"ips": ["45.33.32.156"], "domains": []},
        "flows": [],
    }
    osint = {
        "ips": {
            "45.33.32.156": {
                "shodan": _shodan_host(ports=[80, 443], vulns=["CVE-2023-44487", "CVE-2021-23017"]),
            }
        },
        "domains": {},
    }
    results = correlate_indicators(features=features, osint=osint)
    assert len(results) == 1
    sig = next(s for s in results[0].signals if s.name == "shodan_vulns")
    assert sig.value == "2 CVEs"
    assert sig.score == 0.5  # 0.3 + 0.1 * 2
    assert sig.source == "shodan"
    assert results[0].composite_score > 0


def test_correlate_shodan_vulns_score_capped_at_one():
    features = {"artifacts": {"ips": ["45.33.32.156"], "domains": []}, "flows": []}
    many_vulns = [f"CVE-2024-{1000 + i}" for i in range(20)]
    osint = {"ips": {"45.33.32.156": {"shodan": _shodan_host(ports=[443], vulns=many_vulns)}}, "domains": {}}
    results = correlate_indicators(features=features, osint=osint)
    sig = next(s for s in results[0].signals if s.name == "shodan_vulns")
    assert sig.score == 1.0


def test_correlate_shodan_exposure_signal_for_many_ports():
    features = {"artifacts": {"ips": ["45.33.32.156"], "domains": []}, "flows": []}
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 8080]
    osint = {"ips": {"45.33.32.156": {"shodan": _shodan_host(ports=ports, vulns=[])}}, "domains": {}}
    results = correlate_indicators(features=features, osint=osint)
    assert len(results) == 1
    sig = next(s for s in results[0].signals if s.name == "shodan_exposure")
    assert sig.value == "12 open ports"
    assert sig.score == 12 / 30
    assert sig.source == "shodan"


def test_correlate_shodan_exposure_score_capped():
    features = {"artifacts": {"ips": ["45.33.32.156"], "domains": []}, "flows": []}
    ports = list(range(1, 41))  # 40 open ports -> raw 40/30 > cap
    osint = {"ips": {"45.33.32.156": {"shodan": _shodan_host(ports=ports, vulns=[])}}, "domains": {}}
    results = correlate_indicators(features=features, osint=osint)
    sig = next(s for s in results[0].signals if s.name == "shodan_exposure")
    assert sig.score == 0.8


def test_correlate_shodan_few_ports_no_exposure_signal():
    features = {"artifacts": {"ips": ["45.33.32.156"], "domains": []}, "flows": []}
    osint = {"ips": {"45.33.32.156": {"shodan": _shodan_host(ports=[80, 443], vulns=[])}}, "domains": {}}
    results = correlate_indicators(features=features, osint=osint)
    # 2 ports and no vulns -> no shodan signals at all -> indicator dropped
    assert results == []


def test_correlate_shodan_error_dict_ignored():
    features = {"artifacts": {"ips": ["45.33.32.156"], "domains": []}, "flows": []}
    osint = {
        "ips": {
            "45.33.32.156": {
                "shodan": {"error": "No information available for that IP."},
                "greynoise": {"classification": "malicious"},
            }
        },
        "domains": {},
    }
    results = correlate_indicators(features=features, osint=osint)
    assert len(results) == 1
    assert not any(s.source == "shodan" for s in results[0].signals)
    assert any(s.name == "greynoise_malicious" for s in results[0].signals)


def test_correlate_shodan_transport_error_dict_ignored():
    # _j() returns {"_error": ...} for HTTP/network failures — must not crash or signal
    features = {"artifacts": {"ips": ["45.33.32.156"], "domains": []}, "flows": []}
    osint = {
        "ips": {
            "45.33.32.156": {
                "shodan": {"_error": "HTTP 401", "_url": "https://api.shodan.io/shodan/host/45.33.32.156"},
            }
        },
        "domains": {},
    }
    results = correlate_indicators(features=features, osint=osint)
    assert results == []
