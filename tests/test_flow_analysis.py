"""Tests for flow asymmetry and port anomaly detection."""

from __future__ import annotations

from app.analysis.flow_analysis import (
    FlowAsymmetryResult,
    PortAnomalyResult,
    detect_flow_asymmetry,
    detect_port_anomalies,
)


def test_detect_flow_asymmetry_empty():
    results = detect_flow_asymmetry([])
    assert results == []


def test_detect_flow_asymmetry_no_asymmetry():
    flows = [
        {"src": "10.0.0.1", "dst": "8.8.8.8", "count": 10, "pkt_lens": [100] * 10},
        {"src": "8.8.8.8", "dst": "10.0.0.1", "count": 10, "pkt_lens": [100] * 10},
    ]
    results = detect_flow_asymmetry(flows)
    # Total bytes too small (1000 bytes) to flag
    assert len(results) == 0


def test_detect_flow_asymmetry_detects_exfil():
    flows = [
        # Large outbound
        {"src": "10.0.0.1", "dst": "1.2.3.4", "count": 5000, "pkt_lens": [1000] * 5000},
        # Small inbound
        {"src": "1.2.3.4", "dst": "10.0.0.1", "count": 10, "pkt_lens": [100] * 10},
    ]
    results = detect_flow_asymmetry(flows)
    assert len(results) >= 1
    top = results[0]
    assert top.is_suspicious
    assert top.ratio > 10


def test_detect_port_anomalies_empty():
    results = detect_port_anomalies([])
    assert results == []


def test_detect_port_anomalies_c2_port():
    flows = [
        {"src": "10.0.0.1", "dst": "1.2.3.4", "sport": 12345, "dport": 4444, "proto": "tcp", "count": 50},
    ]
    results = detect_port_anomalies(flows)
    assert len(results) >= 1
    assert results[0].anomaly_type == "c2_port"
    assert results[0].port == 4444


def test_detect_port_anomalies_high_port_pair():
    flows = [
        {"src": "10.0.0.1", "dst": "1.2.3.4", "sport": 55000, "dport": 60000, "proto": "tcp", "count": 50},
    ]
    results = detect_port_anomalies(flows)
    assert any(r.anomaly_type == "high_port_pair" for r in results)


def test_detect_port_anomalies_tcp_on_dns():
    flows = [
        {"src": "10.0.0.1", "dst": "1.2.3.4", "sport": 12345, "dport": 53, "proto": "tcp", "count": 50},
    ]
    results = detect_port_anomalies(flows)
    assert any(r.anomaly_type == "non_standard" for r in results)


def test_flow_asymmetry_result_to_dict():
    r = FlowAsymmetryResult(
        src="10.0.0.1",
        dst="1.2.3.4",
        outbound_bytes=5000000,
        inbound_bytes=1000,
        ratio=5000.0,
        total_packets=100,
        score=0.8,
        is_suspicious=True,
        reason="extreme ratio",
    )
    d = r.to_dict()
    assert d["src"] == "10.0.0.1"
    assert d["score"] == 0.8
    assert d["is_suspicious"] is True


def test_port_anomaly_result_to_dict():
    r = PortAnomalyResult(
        src="10.0.0.1",
        dst="1.2.3.4",
        port=4444,
        proto="tcp",
        anomaly_type="c2_port",
        expected_service="n/a",
        score=0.7,
        reason="C2 port",
    )
    d = r.to_dict()
    assert d["port"] == 4444
    assert d["anomaly_type"] == "c2_port"
