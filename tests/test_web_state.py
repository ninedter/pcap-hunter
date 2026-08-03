from app.database.models import Analysis, Case, CaseStatus, Job, JobStatus, Severity
from app.database.repository import CaseRepository
from app.web.state import _map_flows, _sankey, build_workbench_state


def test_empty_workbench_state_is_complete(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))

    state = build_workbench_state(repo)

    assert state["version"] == "3.0.0"
    assert state["analysis_complete"] is False
    assert state["dashboard"]["map_flows"] == []
    assert state["dashboard"]["raw_flows"] == []
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
