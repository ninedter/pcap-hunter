"""Narrator timeline times: read from the capture, UTC-aware, never invented."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.analysis.narrator import (
    NO_OBSERVED_TIME,
    AttackNarrator,
    TimelineEvent,
    parse_observed_time,
)
from app.pipeline.beacon import rank_beaconing
from app.pipeline.yara_scan import YARAMatch, YARAScanResult, _carve_context
from app.ui.charts import plot_attack_timeline

T0 = 1568538830.5  # 2019-09-15T09:13:50.5Z
T0_UTC = datetime(2019, 9, 15, 9, 13, 50, 500000, tzinfo=timezone.utc)


def _flow(start: float, sport: int, dst: str = "93.184.216.34") -> dict:
    """Flow in the shape ``parse_pcap_pyshark`` emits."""
    pkt_times = [start + i * 0.04 for i in range(6)]
    return {
        "src": "192.168.1.50",
        "dst": dst,
        "sport": str(sport),
        "dport": "443",
        "proto": "tcp",
        "count": 6,
        "bytes": 2435,
        "first_ts": pkt_times[0],
        "last_ts": pkt_times[-1],
        "pkt_times": pkt_times,
        "pkt_lens": [74, 66, 583, 1466, 180, 66],
        "mac_src": "aa:bb:cc:00:00:01",
        "mac_dst": "aa:bb:cc:00:00:02",
    }


def _yara_results(with_carve_context: bool) -> dict:
    """YARA stage output built from the real dataclasses (``scan_carved`` shape)."""
    match = YARAMatch(
        rule_name="Suspicious_Dropper",
        rule_tags=["malware"],
        meta={"author": "test"},
        strings=[(0, "$a", b"MZ")],
        file_path="/data/carved/case_ab12cd34/stream7_0123456789.bin",
        file_hash="0123456789" + "a" * 54,
    )
    hit = YARAScanResult(file_path=match.file_path, file_hash=match.file_hash, file_size=4096, matches=[match])
    clean = YARAScanResult(
        file_path="/data/carved/case_ab12cd34/stream9_ffffffffff.bin", file_hash="f" * 64, file_size=10
    )
    carve_item = {
        "time": f"{T0 + 300:.6f}",
        "tcp_stream": "7",
        "content_type": "application/octet-stream",
        "content_length": "4096",
        "sha256": match.file_hash,
        "path": match.file_path,
    }
    hit_entry = hit.to_dict()
    if with_carve_context:
        hit_entry.update(_carve_context(carve_item))
    return {
        "scanned": 2,
        "matched": 1,
        "errors": 0,
        "results": [clean.to_dict(), hit_entry],
        "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "clean": 1},
        "yara_available": True,
        "rule_count": 1,
    }


class TestParseObservedTime:
    def test_epoch_is_utc_aware(self):
        parsed = parse_observed_time(T0)
        assert parsed == T0_UTC
        assert parsed.utcoffset() == timedelta(0)

    def test_numeric_string_epoch(self):
        assert parse_observed_time(f"{T0:.6f}") == T0_UTC

    def test_iso_strings(self):
        assert parse_observed_time("2019-09-15T09:13:50.500000+00:00") == T0_UTC
        assert parse_observed_time("2019-09-15T09:13:50.500000Z") == T0_UTC
        assert parse_observed_time("2019-09-15T17:13:50.500000+08:00") == T0_UTC

    def test_naive_values_are_taken_as_utc(self):
        assert parse_observed_time(datetime(2019, 9, 15, 9, 13, 50, 500000)) == T0_UTC
        assert parse_observed_time("2019-09-15 09:13:50.500000") == T0_UTC

    def test_unusable_values(self):
        for value in (None, "", "-", "nan-ish", 0, 0.0, -5, float("nan"), True, [], {}):
            assert parse_observed_time(value) is None, value


class TestCaptureStart:
    def test_reads_first_ts_from_flows(self):
        narrator = AttackNarrator()
        flows = [_flow(T0 + 120, 50001), _flow(T0, 50000), _flow(T0 + 60, 50002)]
        start = narrator.capture_start({"flows": flows})
        assert start == datetime.fromtimestamp(T0, tz=timezone.utc)
        assert start.tzinfo is not None

    def test_none_when_flows_have_no_time(self):
        narrator = AttackNarrator()
        assert narrator.capture_start({"flows": [{"src": "10.0.0.1", "dst": "10.0.0.2"}]}) is None
        assert narrator.capture_start(None) is None
        assert narrator.capture_start({}) is None


class TestTimelineTimes:
    def test_beacon_event_uses_the_beacon_rows_first_ts(self):
        flows = [_flow(T0 + i * 60.0, 49152 + i) for i in range(25)]
        beacon_rows = rank_beaconing(flows, top_n=5).to_dict("records")
        timeline = AttackNarrator().create_timeline(features={"flows": flows}, beacon_results=beacon_rows)

        beacon_events = [e for e in timeline if e.event_type == "c2_beacon"]
        assert beacon_events
        event = beacon_events[0]
        assert event.time_observed is True
        assert event.timestamp == datetime.fromtimestamp(T0, tz=timezone.utc)
        assert event.timestamp.utcoffset() == timedelta(0)
        assert event.to_dict()["timestamp"].endswith("+00:00")

    def test_events_without_a_time_are_marked_not_fabricated(self):
        before = datetime.now(timezone.utc)
        timeline = AttackNarrator().create_timeline(
            features={"flows": [_flow(T0, 50000)]},
            beacon_results=[{"src": "192.168.1.50", "dst": "93.184.216.34", "dport": "443", "score": 0.9}],
            dns_analysis={"alerts": {"dga_count": 1, "tunneling_count": 1}, "dga_detections": [{"domain": "x.com"}]},
            yara_results=_yara_results(with_carve_context=False),
        )
        assert {e.event_type for e in timeline} == {"c2_beacon", "dga_detection", "dns_tunneling", "yara_match"}
        for event in timeline:
            assert event.time_observed is False
            assert event.timestamp == NO_OBSERVED_TIME
            assert event.to_dict()["timestamp"] == ""
            assert event.to_dict()["time_observed"] is False
        # Nothing was stamped with "now" or with capture-start + N minutes
        assert not any(isinstance(e.timestamp, datetime) and e.timestamp >= before for e in timeline)

    def test_no_event_gets_wall_clock_time_when_capture_has_no_times(self):
        timeline = AttackNarrator().create_timeline(
            beacon_results=[{"dst": "93.184.216.34", "score": 0.9}],
            base_timestamp=datetime(2030, 1, 1),  # deprecated argument must not leak into events
        )
        assert [e.timestamp for e in timeline] == [NO_OBSERVED_TIME]

    def test_yara_event_uses_carve_time_and_real_file_name(self):
        timeline = AttackNarrator().create_timeline(yara_results=_yara_results(with_carve_context=True))
        events = [e for e in timeline if e.event_type == "yara_match"]
        # The clean file in ``results`` is not an event
        assert len(events) == 1
        event = events[0]
        assert event.timestamp == datetime.fromtimestamp(T0 + 300, tz=timezone.utc)
        assert "stream7_0123456789.bin" in event.description
        assert "Suspicious_Dropper" in event.description
        assert "unknown" not in event.description
        assert event.severity == "critical"

    def test_dns_events_use_detection_first_seen(self):
        dns_analysis = {
            "alerts": {"dga_count": 2, "tunneling_count": 1},
            "dga_detections": [
                {"domain": "b.example", "is_dga": True, "first_seen": T0 + 50},
                {"domain": "a.example", "is_dga": True, "first_seen": T0 + 20},
            ],
            "tunneling_detections": [{"domain": "t.example", "is_tunneling": True, "first_seen": T0 + 90}],
        }
        timeline = {e.event_type: e for e in AttackNarrator().create_timeline(dns_analysis=dns_analysis)}
        assert timeline["dga_detection"].timestamp == datetime.fromtimestamp(T0 + 20, tz=timezone.utc)
        assert timeline["dns_tunneling"].timestamp == datetime.fromtimestamp(T0 + 90, tz=timezone.utc)
        assert timeline["dns_tunneling"].iocs == ["t.example"]

    def test_tls_counter_dict_does_not_raise(self):
        """``alerts`` from the TLS stage is a dict of counters; slicing it used to raise."""
        tls_analysis = {
            "total_certificates": 1,
            "alerts": {"self_signed_count": 1, "expired_count": 0, "high_risk_count": 0},
            "certificate_alerts": [
                {
                    "type": "self_signed",
                    "severity": "medium",
                    "cert": "c2.example.net",
                    "dst_ip": "93.184.216.34",
                    "dst_port": 443,
                    "timestamp": datetime.fromtimestamp(T0, tz=timezone.utc).isoformat(),
                }
            ],
        }
        timeline = AttackNarrator().create_timeline(tls_analysis=tls_analysis)
        assert len(timeline) == 1
        assert timeline[0].event_type == "tls_anomaly"
        assert timeline[0].dest_ip == "93.184.216.34"
        assert timeline[0].timestamp == datetime.fromtimestamp(T0, tz=timezone.utc)

        legacy_only = {"alerts": {"self_signed_count": 1, "expired_count": 0, "high_risk_count": 0}}
        assert AttackNarrator().create_timeline(tls_analysis=legacy_only) == []

    def test_default_timeline_event_is_observed(self):
        event = TimelineEvent(timestamp=T0_UTC, event_type="alert", description="d", severity="low")
        assert event.time_observed is True
        assert event.to_dict()["time_observed"] is True


class TestConsumersTolerateUnobservedTimes:
    def test_attack_timeline_chart_renders_mixed_and_untimed_events(self):
        timeline = AttackNarrator().create_timeline(
            beacon_results=[
                {"src": "192.168.1.50", "dst": "93.184.216.34", "dport": "443", "score": 0.9, "first_ts": T0},
                {"src": "192.168.1.50", "dst": "93.184.216.35", "dport": "443", "score": 0.7},
            ],
            dns_analysis={"alerts": {"dga_count": 1}, "dga_detections": [{"domain": "x.com"}]},
        )
        dicts = [e.to_dict() for e in timeline]
        assert sum(d["time_observed"] for d in dicts) == 1

        for events in (dicts, [d for d in dicts if not d["time_observed"]]):
            fig = plot_attack_timeline(events)
            assert sum(len(trace.x) for trace in fig.data) == len(events)

    def test_basic_narrative_and_prompt_ignore_timestamps(self):
        narrator = AttackNarrator()
        narrative = narrator.generate_narrative(
            beacon_results=[{"dst": "93.184.216.34", "dport": "443", "score": 0.9}],
            dns_analysis={
                "alerts": {"dga_count": 1, "tunneling_count": 0, "nxdomain_suspicious": True, "nxdomain_ratio": 0.42}
            },
        )
        assert "c2_beacon" in narrative

    def test_prompt_dns_alert_count_is_a_count(self):
        captured = {}

        def fake_llm(base_url, api_key, model, context, language):
            captured["prompt"] = context["prompt"]
            return "ok"

        AttackNarrator(fake_llm).generate_narrative(
            dns_analysis={
                "alerts": {
                    "dga_count": 2,
                    "tunneling_count": 1,
                    "fast_flux_count": 0,
                    "nxdomain_suspicious": True,
                    "nxdomain_ratio": 0.42,
                    "high_velocity_sources": 3,
                },
                "dga_detections": [{"domain": "x.com"}],
            },
            llm_config={"base_url": "http://localhost:1234/v1", "api_key": "k", "model": "m"},
        )
        assert "- DNS alerts: 3\n" in captured["prompt"]
