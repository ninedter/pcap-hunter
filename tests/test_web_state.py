import pytest

from app.database.models import Analysis, Case, CaseStatus, Job, JobStatus, Severity
from app.database.repository import CaseRepository
from app.web.state import _capture_summary, _map_flows, _sankey, build_workbench_state


@pytest.fixture(autouse=True)
def isolated_workbench_settings(tmp_path, monkeypatch):
    from app.utils.config_manager import ConfigManager

    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY_FILE", raising=False)
    manager = ConfigManager(tmp_path / "settings.json")
    monkeypatch.setattr("app.web.state.get_config_manager", lambda: manager)


def test_new_and_missing_analysis_timestamps_are_absolute_utc(tmp_path):
    import time
    from datetime import timedelta

    before = time.time()
    repo = CaseRepository(str(tmp_path / "cases.db"))
    repo.create_case(Case(id="timezone", title="UTC timestamp regression"))
    fresh = Analysis(id="new", case_id="timezone")
    repo.save_analysis(fresh)
    with repo._get_conn() as conn:
        conn.execute("UPDATE analyses SET analyzed_at=NULL WHERE id=?", (fresh.id,))
        conn.commit()
    recovered = repo.get_case("timezone").analyses[0]
    for analysis in (fresh, recovered, Analysis.from_dict({})):
        assert analysis.analyzed_at.utcoffset() == timedelta(0)
        assert before <= analysis.sort_timestamp <= time.time()


def test_legacy_and_agent_analysis_timestamps_can_share_the_workbench(tmp_path):
    from datetime import datetime, timedelta, timezone

    repo = CaseRepository(str(tmp_path / "cases.db"))
    repo.create_case(Case(id="mixed", title="Mixed timestamp formats"))
    repo.save_analysis(Analysis(id="legacy", case_id="mixed", analyzed_at=datetime(2026, 10, 28, 9)))
    repo.save_analysis(
        Analysis(
            id="agent", case_id="mixed", analyzed_at=datetime(2026, 10, 28, 18, tzinfo=timezone(timedelta(hours=8)))
        )
    )
    state = build_workbench_state(repo)
    assert state["active_analysis_id"] == "agent"
    assert max(repo.get_case("mixed").analyses, key=lambda a: a.sort_timestamp).id == "agent"


def test_empty_workbench_state_is_complete(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))

    state = build_workbench_state(repo)

    assert state["version"] == "3.0.0"
    assert state["analysis_complete"] is False
    assert state["dashboard"]["map_flows"] == []
    assert state["dashboard"]["raw_flows"] == []
    assert state["dashboard"]["capture_summary"] == {
        "packet_count": 0,
        "flow_count": 0,
        "endpoint_count": 0,
        "parsed_traffic_bytes": 0,
        "parsed_packet_count": 0,
        "capture_file_bytes": None,
        "first_seen": None,
        "last_seen": None,
        "duration_seconds": None,
        "byte_coverage": "unknown",
    }
    assert state["dashboard"]["protocol_distribution"] == []
    assert state["dashboard"]["endpoint_ranking"] == []
    assert state["dashboard"]["traffic_replay"] == {
        "events": [],
        "sampled_event_count": 0,
        "returned_event_count": 0,
        "max_events": 2_000,
        "truncated": False,
        "sampled_flow_count": 0,
        "total_flow_count": 0,
        "represented_packet_count": 0,
        "total_packet_count": 0,
        "first_seen": None,
        "last_seen": None,
        "coverage": "unavailable",
    }
    assert state["cases"] == []
    assert state["jobs"] == []


def test_workbench_maps_saved_analysis_to_prototype_views(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(
        id="case-001",
        title="Saved capture",
        status=CaseStatus.OPEN,
        severity=Severity.LOW,
        tags=["test"],
    )
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-001",
            case_id=case.id,
            pcap_path="/data/example.pcap",
            packet_count=3,
            features={
                "flows": [
                    {
                        "src": "192.168.1.10",
                        "dst": "192.168.1.20",
                        "proto": "tcp",
                        "dport": 443,
                        "count": 3,
                        "pkt_lens": [64, 128, 256],
                        "pkt_times": [1.0, 1.2, 1.8],
                    }
                ],
                "artifacts": {"domains": ["example.test"]},
            },
            report="Saved report",
            attack_mapping={"techniques": [], "overall_severity": "low"},
            session_artifacts={"pipeline_stages": ["Packet parsing"]},
        )
    )

    state = build_workbench_state(repo)

    assert state["analysis_complete"] is True
    assert state["active_case_id"] == case.id
    assert state["dashboard"]["packets"] == 3
    assert state["dashboard"]["flows"] == 1
    assert state["dashboard"]["raw_flows"][0]["protocol"] == "TCP/443"
    assert state["dashboard"]["report"] == "Saved report"
    assert state["cases"][0]["analysis_count"] == 1


def test_workbench_exposes_saved_reverse_dns_name_on_ip_evidence(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-rdns", title="PTR capture")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-rdns",
            case_id=case.id,
            pcap_path="/data/rdns.pcap",
            features={"artifacts": {"ips": ["8.8.8.8"]}},
            session_artifacts={"rdns_map": {"8.8.8.8": "dns.google"}},
        )
    )

    evidence = build_workbench_state(repo)["dashboard"]["evidence"]

    assert evidence[0]["value"] == "8.8.8.8"
    assert evidence[0]["hostname"] == "dns.google"


def test_workbench_serializes_live_stage_progress(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    repo.create_case(Case(id="case-001", title="Live run"))
    job_id = repo.create_job(Job(case_id="case-001", pcap_path="/data/live.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)
    repo.update_job_progress(job_id, "Parsing Packets", 2, 10, 45, "Reading packet 450 of 1000")

    job = build_workbench_state(repo)["jobs"][0]

    assert job["progress"] == 24
    assert job["completed_stages"] == 2
    assert job["stage_progress"] == 45
    assert job["stage_message"] == "Reading packet 450 of 1000"


def test_sankey_keeps_bidirectional_endpoints_in_separate_layers():
    graph = _sankey(
        [
            {"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "tcp", "dport": 443, "count": 5},
            {"src": "10.0.0.2", "dst": "10.0.0.1", "proto": "tcp", "dport": 443, "count": 4},
        ]
    )

    layers = {(node["layer"], node["name"]) for node in graph["nodes"]}
    assert ("source", "10.0.0.1") in layers
    assert ("destination", "10.0.0.1") in layers
    assert all(link["source"] != link["target"] for link in graph["links"])


def test_map_flows_preserve_continent_and_filter_slices(monkeypatch):
    monkeypatch.setattr(
        "app.web.state.GeoIP.lookup",
        lambda ip: {
            "ip": ip,
            "country": "Taiwan",
            "city": "Taipei",
            "continent": "Asia",
            "lat": 25.033,
            "lon": 121.5654,
        },
    )

    mapped = _map_flows(
        [
            {
                "src": "192.168.1.10",
                "dst": "8.8.8.8",
                "proto": "udp",
                "count": 4,
                "pkt_lens": [64, 64, 64, 64],
                "first_ts": 60,
            }
        ],
        {},
    )

    assert mapped[0]["continent"] == "Asia"
    assert mapped[0]["country"] == "Taiwan"
    assert mapped[0]["city"] == "Taipei"
    assert mapped[0]["byte_count"] == 256
    assert mapped[0]["traffic_slices"] == [{"protocol": "UDP", "time": "00:01", "packets": 4, "bytes": 256}]


def test_capture_statistics_prefer_scalar_bytes_and_keep_file_bytes_distinct(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-stats", title="Stats")
    repo.create_case(case)
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap-file")
    repo.save_analysis(
        Analysis(
            id="analysis-stats",
            case_id=case.id,
            pcap_path=str(capture),
            packet_count=5,
            capture_metrics={"packet_count": 5, "first_seen": "1970-01-01T00:00:05+00:00", "last_seen": 40},
            features={
                "flows": [
                    {
                        "src": "10.0.0.1",
                        "dst": "8.8.8.8",
                        "proto": "tcp",
                        "count": 3,
                        "bytes": 900,
                        "pkt_lens": [50],
                        "pkt_times": [20, 10, 30],
                    },
                    {
                        "src": "8.8.8.8",
                        "dst": "10.0.0.1",
                        "proto": "udp",
                        "count": 2,
                        "bytes": 100,
                        "pkt_times": [15, 25],
                    },
                ]
            },
        )
    )

    dashboard = build_workbench_state(repo)["dashboard"]

    assert dashboard["capture_summary"] == {
        "packet_count": 5,
        "flow_count": 2,
        "endpoint_count": 2,
        "parsed_traffic_bytes": 1000,
        "parsed_packet_count": 5,
        "capture_file_bytes": 9,
        "first_seen": 5.0,
        "last_seen": 40.0,
        "duration_seconds": 35.0,
        "byte_coverage": "complete",
    }
    assert dashboard["protocol_distribution"] == [
        {"name": "TCP", "bytes": 900, "packets": 3, "flow_count": 1, "percent": 90.0},
        {"name": "UDP", "bytes": 100, "packets": 2, "flow_count": 1, "percent": 10.0},
    ]
    assert dashboard["endpoint_ranking"][0] == {
        "ip": "10.0.0.1",
        "bytes": 1000,
        "packets": 5,
        "flow_count": 2,
        "sent_bytes": 900,
        "received_bytes": 100,
    }


def test_capture_stats_mark_packet_samples_partial_and_missing_file_null(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-partial", title="Partial")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-partial",
            case_id=case.id,
            pcap_path=str(tmp_path / "missing.pcap"),
            packet_count=3,
            features={"flows": [{"src": "not-an-ip", "dst": "10.0.0.1", "count": 3, "pkt_lens": [10, 20, 30]}]},
        )
    )

    summary = build_workbench_state(repo)["dashboard"]["capture_summary"]

    assert summary["parsed_traffic_bytes"] == 60
    assert summary["byte_coverage"] == "partial"
    assert summary["capture_file_bytes"] is None
    assert summary["endpoint_count"] == 1
    assert all(row["ip"] != "not-an-ip" for row in build_workbench_state(repo)["dashboard"]["endpoint_ranking"])


def test_capture_summary_rejects_non_files_and_requires_exact_known_packet_count(tmp_path):
    flow = {"src": "10.0.0.1", "dst": "8.8.8.8", "count": 3, "bytes": 100}

    empty_path = _capture_summary(Analysis(packet_count=0, pcap_path=""), [flow])
    directory_path = _capture_summary(Analysis(packet_count=3, pcap_path=str(tmp_path)), [flow])
    inconsistent_count = _capture_summary(Analysis(packet_count=2), [flow])

    assert empty_path["capture_file_bytes"] is None
    assert directory_path["capture_file_bytes"] is None
    assert empty_path["byte_coverage"] == "partial"
    assert inconsistent_count["byte_coverage"] == "partial"


def test_capture_summary_prefers_positive_analysis_packet_count_over_zero_metric():
    summary = _capture_summary(
        Analysis(packet_count=3, capture_metrics={"packet_count": 0}),
        [{"src": "10.0.0.1", "dst": "8.8.8.8", "count": 3, "bytes": 100}],
    )

    assert summary["packet_count"] == 3
    assert summary["byte_coverage"] == "complete"


def test_traffic_replay_sorts_samples_aligns_lengths_and_classifies_scopes(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-replay", title="Replay")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-replay",
            case_id=case.id,
            packet_count=5,
            features={
                "flows": [
                    {
                        "src": "10.0.0.1",
                        "dst": "8.8.8.8",
                        "proto": "tcp",
                        "count": 3,
                        "pkt_lens": [100, 200],
                        "pkt_times": [3, "bad", 1],
                    },
                    {
                        "src": "192.0.2.1",
                        "dst": "fc00::1",
                        "proto": "udp",
                        "count": 1,
                        "pkt_times": [2],
                    },
                    {"src": "::1", "dst": "fc00::2", "proto": "icmp", "count": 1, "pkt_times": [4]},
                ]
            },
        )
    )

    replay = build_workbench_state(repo)["dashboard"]["traffic_replay"]

    assert [event["timestamp"] for event in replay["events"]] == [1.0, 2.0, 3.0, 4.0]
    assert [event["sampled_length"] for event in replay["events"]] == [None, None, 100, None]
    assert replay["events"][0]["src_scope"] == "internal"
    assert replay["events"][0]["dst_scope"] == "external"
    assert replay["events"][1]["src_scope"] == "special"
    assert replay["events"][1]["dst_scope"] == "internal"
    assert replay["events"][3]["src_scope"] == "internal"
    assert replay["events"][3]["dst_scope"] == "internal"
    assert replay["coverage"] == "sampled"


def test_traffic_replay_downsamples_globally_and_keeps_late_event(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-cap", title="Replay cap")
    repo.create_case(case)
    times = list(range(2_001))
    repo.save_analysis(
        Analysis(
            id="analysis-cap",
            case_id=case.id,
            packet_count=len(times),
            features={"flows": [{"src": "ff02::1", "dst": "8.8.8.8", "count": len(times), "pkt_times": times}]},
        )
    )

    replay = build_workbench_state(repo)["dashboard"]["traffic_replay"]

    assert replay["sampled_event_count"] == 2_001
    assert replay["returned_event_count"] == 2_000
    assert replay["truncated"] is True
    assert replay["events"][0]["timestamp"] == 0.0
    assert replay["events"][-1]["timestamp"] == 2_000.0
    assert replay["events"][0]["src_scope"] == "special"


def test_traffic_replay_downsampling_retains_sparse_middle_and_late_events(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-skew", title="Skewed replay")
    repo.create_case(case)
    times = list(range(2_001)) + [500_000, 1_000_000]
    repo.save_analysis(
        Analysis(
            id="analysis-skew",
            case_id=case.id,
            packet_count=len(times),
            features={"flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "count": len(times), "pkt_times": times}]},
        )
    )

    replay_events = build_workbench_state(repo)["dashboard"]["traffic_replay"]["events"]
    returned_times = {event["timestamp"] for event in replay_events}

    assert 500_000.0 in returned_times
    assert 1_000_000.0 in returned_times


def test_traffic_replay_ignores_malformed_sample_shapes(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-malformed", title="Malformed samples")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-malformed",
            case_id=case.id,
            features={"flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "count": 2, "pkt_times": 5, "pkt_lens": {}}]},
        )
    )

    replay = build_workbench_state(repo)["dashboard"]["traffic_replay"]

    assert replay["events"] == []
    assert replay["coverage"] == "unavailable"


def test_traffic_replay_needs_full_capture_count_for_complete_coverage(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-replay-partial", title="Partial replay")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-replay-partial",
            case_id=case.id,
            packet_count=3,
            features={"flows": [{"src": "10.0.0.1", "dst": "8.8.8.8", "count": 2, "pkt_times": [1, 2]}]},
        )
    )

    replay = build_workbench_state(repo)["dashboard"]["traffic_replay"]

    assert replay["represented_packet_count"] == replay["sampled_event_count"] == 2
    assert replay["total_packet_count"] == 3
    assert replay["coverage"] == "sampled"


def test_traffic_replay_represents_only_flows_with_valid_timestamp_evidence(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-sampled-only", title="Sampled flows")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-sampled-only",
            case_id=case.id,
            packet_count=6,
            features={
                "flows": [
                    {"src": "10.0.0.1", "dst": "8.8.8.8", "count": 2, "pkt_times": [1, 2]},
                    {"src": "10.0.0.2", "dst": "8.8.4.4", "count": 3, "pkt_times": ["bad", None]},
                    {"src": "10.0.0.3", "dst": "1.1.1.1", "count": 1},
                ]
            },
        )
    )

    replay = build_workbench_state(repo)["dashboard"]["traffic_replay"]

    assert replay["represented_packet_count"] == 2
    assert replay["sampled_event_count"] == 2
    assert replay["sampled_flow_count"] == 1
    assert replay["total_flow_count"] == 3
    assert replay["total_packet_count"] == 6
    assert replay["coverage"] == "sampled"


def test_endpoint_statistics_canonicalize_equivalent_ipv6_spelling(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    case = Case(id="case-ipv6", title="IPv6")
    repo.create_case(case)
    repo.save_analysis(
        Analysis(
            id="analysis-ipv6",
            case_id=case.id,
            packet_count=2,
            features={
                "flows": [
                    {"src": "2001:db8:0:0:0:0:0:1", "dst": "8.8.8.8", "count": 1, "bytes": 10},
                    {"src": "2001:db8::1", "dst": "8.8.8.8", "count": 1, "bytes": 20},
                ]
            },
        )
    )

    dashboard = build_workbench_state(repo)["dashboard"]

    assert dashboard["capture_summary"]["endpoint_count"] == 2
    assert dashboard["endpoint_ranking"][0]["ip"] == "2001:db8::1"
    assert dashboard["endpoint_ranking"][0]["bytes"] == 30


def test_critical_ioc_after_preview_boundary_affects_full_dashboard_risk():
    from app.database.models import IOC, Analysis, IOCType, Severity
    from app.web.state import _dashboard_state

    analysis = Analysis(features={"flows": []})
    analysis.iocs = [IOC(ioc_type=IOCType.IP, value=f"192.0.2.{i}", severity=Severity.LOW) for i in range(100)]
    analysis.iocs.append(IOC(ioc_type=IOCType.DOMAIN, value="critical.invalid", severity=Severity.CRITICAL))
    result = _dashboard_state(analysis)
    assert result["alerts"] == 1 and result["risk"] == "HIGH"
    assert result["evidence_total"] == 101
    assert result["evidence"][0]["value"] == "critical.invalid"
