"""Tests for capture-quality and detector-visibility metrics."""

from app.analysis.visibility import build_capture_metrics


def test_capture_metrics_preserve_true_flow_totals_and_sample_cap():
    metrics = build_capture_metrics(
        {
            "__total_pkts": 12,
            "features": {
                "flows": [
                    {
                        "src": "10.0.0.1",
                        "dst": "203.0.113.4",
                        "proto": "tcp",
                        "count": 10,
                        "bytes": 9000,
                        "first_ts": 100.0,
                        "last_ts": 110.0,
                        "pkt_times": [100.0, 110.0],
                    }
                ],
                "artifacts": {"ips": ["10.0.0.1", "203.0.113.4"], "domains": ["example.test"]},
            },
            "zeek_tables": {},
            "pipeline_warnings": ["zeek_no_logs"],
        }
    )

    assert metrics["packet_count"] == 12
    assert metrics["parsed_packet_count"] == 10
    assert metrics["parse_ratio"] == round(10 / 12, 4)
    assert metrics["total_bytes"] == 9000
    assert metrics["sampled_flow_count"] == 1
    assert metrics["duration_seconds"] == 10.0
    assert "zeek" in metrics["visibility_gaps"]
    assert metrics["limitations"]


def test_capture_metrics_mark_clean_empty_detectors_as_partial_not_absent():
    metrics = build_capture_metrics(
        {
            "features": {"flows": [], "artifacts": {"ips": [], "domains": []}},
            "zeek_tables": {"conn": []},
            "dns_analysis": {"total_records": 0},
            "tls_analysis": {"total_certificates": 0},
            "yara_results": {},
            "osint": {},
            "correlations": [],
        }
    )

    assert metrics["detectors"]["packet_flow"] == "available"
    assert metrics["detectors"]["zeek"] == "available"
    assert metrics["detectors"]["dns"] == "available"
    assert metrics["detectors"]["correlation"] == "available"


def test_capture_metrics_ignore_missing_or_malformed_timestamps():
    metrics = build_capture_metrics(
        {
            "features": {
                "flows": [
                    {"count": 1, "bytes": 20, "first_ts": None, "last_ts": None, "pkt_times": [None, "bad"]},
                    {"count": 2, "bytes": 40, "first_ts": 100.0, "last_ts": 105.0, "pkt_times": []},
                ],
                "artifacts": {},
            }
        }
    )

    assert metrics["first_seen"] == "1970-01-01T00:01:40+00:00"
    assert metrics["last_seen"] == "1970-01-01T00:01:45+00:00"
    assert metrics["duration_seconds"] == 5.0
