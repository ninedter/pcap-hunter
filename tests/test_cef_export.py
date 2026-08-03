"""Tests for CEF/syslog SIEM export module."""

from __future__ import annotations

from app.utils.cef_export import (
    CEFEvent,
    export_cef_text,
    format_syslog,
    generate_cef_events,
)


class TestCEFEvent:
    def test_basic_cef_format(self):
        event = CEFEvent(
            signature_id="TEST-001",
            name="Test Event",
            severity=5,
            extensions={"src": "1.2.3.4"},
        )
        cef = event.to_cef()
        assert cef.startswith("CEF:0|PCAPHunter|ThreatWorkbench|3.0.0|TEST-001|Test Event|5|")
        assert "src=1.2.3.4" in cef

    def test_pipe_escaping_in_name(self):
        event = CEFEvent(signature_id="T-1", name="Test|Pipe", severity=1)
        cef = event.to_cef()
        assert "Test\\|Pipe" in cef

    def test_extension_value_escaping(self):
        event = CEFEvent(
            signature_id="T-1",
            name="Test",
            severity=1,
            extensions={"cs1": "key=value"},
        )
        cef = event.to_cef()
        assert "cs1=key\\=value" in cef

    def test_empty_extensions(self):
        event = CEFEvent(signature_id="T-1", name="Test", severity=1)
        cef = event.to_cef()
        assert cef.endswith("|1|")


class TestFormatSyslog:
    def test_syslog_header(self):
        event = CEFEvent(signature_id="T-1", name="Test", severity=1)
        line = format_syslog(event, hostname="myhost")
        assert "myhost" in line
        assert "CEF:0" in line


class TestGenerateCEFFromCorrelations:
    def test_dict_correlations(self):
        correlations = [
            {"indicator": "1.2.3.4", "verdict": "high", "signals": ["beacon", "osint"], "score": 0.8},
            {"indicator": "5.6.7.8", "verdict": "low", "signals": [], "score": 0.2},
        ]
        events = generate_cef_events(correlations=correlations)
        assert len(events) == 2
        assert events[0].severity == 8  # high
        assert events[1].severity == 3  # low
        assert "1.2.3.4" in events[0].to_cef()

    def test_dataclass_correlations(self):
        from types import SimpleNamespace

        c = SimpleNamespace(indicator="evil.com", verdict="critical", signals=["dga"], score=0.95)
        events = generate_cef_events(correlations=[c])
        assert len(events) == 1
        assert events[0].severity == 10

    def test_empty_correlations(self):
        assert generate_cef_events(correlations=[]) == []
        assert generate_cef_events() == []


class TestGenerateCEFFromBeacons:
    def test_beacon_events(self):
        import pandas as pd

        df = pd.DataFrame(
            [
                {"src": "10.0.0.1", "dst": "1.2.3.4", "dport": 4444, "score": 0.7, "count": 100},
                {"src": "10.0.0.2", "dst": "5.6.7.8", "dport": 443, "score": 0.1, "count": 50},
            ]
        )
        events = generate_cef_events(beacon_df=df)
        # Only score >= 0.3 should be emitted
        assert len(events) == 1
        assert "1.2.3.4" in events[0].to_cef()

    def test_empty_beacon_df(self):
        import pandas as pd

        assert generate_cef_events(beacon_df=pd.DataFrame()) == []

    def test_none_beacon_df(self):
        assert generate_cef_events(beacon_df=None) == []


class TestGenerateCEFFromDNS:
    def test_dga_events(self):
        dns = {
            "dga_detections": [
                {"domain": "xkjf82kjd.com", "score": 4.5, "reason": "high entropy"},
            ],
            "tunneling_suspects": ["tunnel.evil.com"],
        }
        events = generate_cef_events(dns_analysis=dns)
        assert len(events) == 2
        # Check signature IDs
        sig_ids = {e.signature_id for e in events}
        assert "DNS-DGA-001" in sig_ids
        assert "DNS-TUNNEL-001" in sig_ids


class TestGenerateCEFFromIOCs:
    def test_scored_ioc_events(self):
        from types import SimpleNamespace

        iocs = [
            SimpleNamespace(value="1.2.3.4", ioc_type="ip", priority_score=0.9, priority_label="critical"),
            SimpleNamespace(value="safe.com", ioc_type="domain", priority_score=0.1, priority_label="low"),
        ]
        events = generate_cef_events(scored_iocs=iocs)
        # Only score >= 0.4 emitted
        assert len(events) == 1
        assert "1.2.3.4" in events[0].to_cef()

    def test_dict_iocs(self):
        iocs = [{"value": "evil.com", "type": "domain", "priority_score": 0.6, "priority_label": "medium"}]
        events = generate_cef_events(scored_iocs=iocs)
        assert len(events) == 1
        assert "evil.com" in events[0].to_cef()


class TestExportCEFText:
    def test_full_export(self):
        correlations = [{"indicator": "1.2.3.4", "verdict": "high", "signals": ["osint"], "score": 0.7}]
        text = export_cef_text(correlations=correlations)
        assert "CEF:0" in text
        assert "pcap-hunter" in text
        lines = text.strip().split("\n")
        assert len(lines) >= 1

    def test_empty_export(self):
        text = export_cef_text()
        assert text == ""
