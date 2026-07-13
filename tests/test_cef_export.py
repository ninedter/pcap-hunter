"""Tests for CEF/syslog SIEM export module."""

from __future__ import annotations

from app.utils.cef_export import (
    CEFEvent,
    export_cef_text,
    feed_rows_to_cef,
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
        assert cef.startswith("CEF:0|PCAPHunter|ThreatWorkbench|1.0|TEST-001|Test Event|5|")
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

    def test_extension_value_newline_escaping(self):
        """A newline/CR embedded in an attacker-influenced extension value must not
        be able to forge a second CEF/syslog line."""
        event = CEFEvent(
            signature_id="T-1",
            name="Test",
            severity=1,
            extensions={"cs1": "evil\nCEF:0|Fake|Fake|1.0|999|Forged Event|10|src=9.9.9.9\r"},
        )
        cef = event.to_cef()
        assert "\n" not in cef
        assert "\r" not in cef
        assert "cs1=evil\\nCEF:0|Fake|Fake|1.0|999|Forged Event|10|src\\=9.9.9.9\\r" in cef

    def test_name_newline_does_not_split_header(self):
        """A newline embedded in the name field must not split the CEF header
        into a second forged line."""
        event = CEFEvent(signature_id="T-1", name="Evil\nCEF:0|Fake|Fake|1.0|999|Forged|10|", severity=1)
        cef = event.to_cef()
        assert "\n" not in cef
        assert "\r" not in cef


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


class TestFeedRowsToCEF:
    """feed_rows_to_cef renders feed-query rows (score 25-100, no priority_score)
    directly — it must NOT apply the 0.4 priority-score gate used by
    _events_from_iocs, or a LOW-severity row (score 25) would be silently
    dropped from a feed pull."""

    def test_low_row_not_dropped(self):
        rows = [{"type": "ip", "value": "1.2.3.4", "score": 25, "severity": "low", "tags": []}]
        text = feed_rows_to_cef(rows)
        assert "CEF:0" in text
        assert "1.2.3.4" in text

    def test_one_event_per_row(self):
        rows = [
            {"type": "ip", "value": "1.1.1.1", "score": 25, "severity": "low", "tags": []},
            {"type": "ip", "value": "2.2.2.2", "score": 100, "severity": "critical", "tags": []},
        ]
        text = feed_rows_to_cef(rows)
        lines = [ln for ln in text.strip().splitlines() if ln]
        assert len(lines) == 2

    def test_severity_mapping_reuses_severity_map(self):
        rows = [{"type": "ip", "value": "9.9.9.9", "score": 100, "severity": "critical", "tags": []}]
        text = feed_rows_to_cef(rows)
        # _SEVERITY_MAP["critical"] == 10
        assert "|10|" in text

    def test_unknown_severity_defaults_sanely(self):
        rows = [{"type": "ip", "value": "8.8.8.8", "score": 50, "severity": "bogus", "tags": []}]
        text = feed_rows_to_cef(rows)
        assert "CEF:0" in text  # doesn't raise; renders with a fallback severity

    def test_escaping_of_special_chars_in_value_and_tags(self):
        rows = [
            {
                "type": "url",
                "value": "http://evil.example/a=b",
                "score": 50,
                "severity": "medium",
                "tags": ["tag=1", "back\\slash"],
            }
        ]
        text = feed_rows_to_cef(rows)
        assert "a\\=b" in text
        assert "tag\\=1" in text
        assert "back\\\\slash" in text

    def test_empty_rows(self):
        assert feed_rows_to_cef([]) == ""

    def test_hostname_in_syslog_header(self):
        rows = [{"type": "ip", "value": "1.2.3.4", "score": 75, "severity": "high", "tags": []}]
        text = feed_rows_to_cef(rows, hostname="feedhost")
        assert "feedhost" in text

    def test_hostile_value_with_embedded_newline_yields_one_line_per_event(self):
        """IOC values are attacker-influenced (derived from PCAP data). A value
        containing an embedded newline must not be able to inject a forged
        second CEF/syslog line into the SIEM feed."""
        rows = [
            {
                "type": "domain",
                "value": "evil.example\nCEF:0|Fake|Fake|1.0|999|Forged Event|10|src=9.9.9.9",
                "score": 100,
                "severity": "critical",
                "tags": [],
            },
            {"type": "ip", "value": "2.2.2.2", "score": 50, "severity": "medium", "tags": []},
        ]
        text = feed_rows_to_cef(rows)
        lines = [ln for ln in text.strip().splitlines() if ln]
        assert len(lines) == 2
