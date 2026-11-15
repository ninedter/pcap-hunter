"""Bootstrap cost and data-honesty checks for the workbench state builder."""

from __future__ import annotations

import gzip
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import app.database.repository as repository_mod
from app.database.models import IOC, Analysis, Case, IOCType, Severity
from app.database.repository import CaseRepository
from app.web.state import _map_flows, _traffic_rows, build_workbench_state


@pytest.fixture(autouse=True)
def isolated_workbench_settings(tmp_path, monkeypatch):
    from app.utils.config_manager import ConfigManager

    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY_FILE", raising=False)
    manager = ConfigManager(tmp_path / "settings.json")
    monkeypatch.setattr("app.web.state.get_config_manager", lambda: manager)
    repository_mod._flow_count_cache.clear()


def _flows(count: int, start: float = 1_780_000_000.0) -> list[dict]:
    return [
        {
            "src": "10.0.0.5",
            "dst": f"8.8.{index // 250}.{index % 250 + 1}",
            "proto": "TCP",
            "dport": 443,
            "count": 3,
            "bytes": 900,
            "first_ts": start + index * 30,
            "pkt_times": [start + index * 30, start + index * 30 + 1],
            "pkt_lens": [300, 600],
        }
        for index in range(count)
    ]


def _seed(repo: CaseRepository) -> None:
    """Several cases with production-shape analyses, notes, tags and mixed timestamp forms."""
    base = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
    for case_index in range(4):
        case_id = f"case{case_index}"
        repo.create_case(
            Case(
                id=case_id,
                title=f"capture-{case_index}.pcap",
                description=f"description {case_index}",
                severity=Severity.HIGH if case_index % 2 else Severity.LOW,
                tags=["zeta", "alpha", f"tag{case_index}"][: case_index + 1],
                created_at=datetime(2026, 9, 1, 8, case_index),
                updated_at=datetime(2026, 9, 1, 9, case_index),
            )
        )
        for analysis_index in range(case_index):  # case0 has no analysis
            flows = _flows(3 + case_index * 2 + analysis_index)
            analyzed_at = base + timedelta(hours=case_index, minutes=analysis_index)
            repo.save_analysis(
                Analysis(
                    id=f"an-{case_index}-{analysis_index}",
                    case_id=case_id,
                    pcap_path=f"/data/api_uploads/{case_id}_{analysis_index}.pcap",
                    packet_count=100 * (analysis_index + 1),
                    # One legacy naive row per case, the rest explicit UTC.
                    analyzed_at=analyzed_at.replace(tzinfo=None) if analysis_index == 0 else analyzed_at,
                    features={"flows": flows, "artifacts": {"ips": ["8.8.8.8"], "domains": ["example.org"]}},
                    osint={"ips": {"8.8.8.8": {"ptr": "dns.google"}}},
                    report=f"# Report {case_index}-{analysis_index}",
                    dns_analysis={"total_records": 5},
                    session_artifacts={"pipeline_stages": ["pyshark"], "zeek_tables": {"conn": [{"uid": "C1"}] * 50}},
                    iocs=[
                        IOC(ioc_type=IOCType.IP, value=f"8.8.{case_index}.{n}", severity=Severity.HIGH)
                        for n in range(analysis_index + 2)
                    ],
                )
            )
        for note_index in range(case_index % 3):
            repo.add_note(case_id, f"note {note_index} for {case_id}")


def _legacy_cases(repo: CaseRepository) -> list[dict]:
    """The pre-change ``_serialize_cases``: one full ``get_case`` per listed case."""
    rows = []
    for summary in repo.list_cases(limit=100):
        case = repo.get_case(summary.id)
        rows.append(
            {
                "id": case.id,
                "title": case.title,
                "description": case.description,
                "status": case.status.value,
                "severity": case.severity.value,
                "tags": case.tags,
                "created_at": case.created_at.isoformat(),
                "updated_at": case.updated_at.isoformat(),
                "analysis_count": len(case.analyses),
                "ioc_count": case.ioc_count,
                "note_count": len(case.notes),
                "analyses": [
                    {
                        "id": analysis.id,
                        "name": Path(analysis.pcap_path).name,
                        "packet_count": analysis.packet_count,
                        "flow_count": len((analysis.features or {}).get("flows") or []),
                        "ioc_count": len(analysis.iocs),
                        "analyzed_at": analysis.analyzed_at.isoformat(),
                    }
                    for analysis in case.analyses
                ],
                "notes": [note.to_dict() for note in case.notes],
            }
        )
    return rows


def _legacy_latest(repo: CaseRepository) -> tuple[Case | None, Analysis | None]:
    """The pre-change ``_latest_case_and_analysis``."""
    latest_case = latest_analysis = None
    for case_summary in repo.list_cases(limit=100):
        case = repo.get_case(case_summary.id)
        if latest_case is None:
            latest_case = case
        for analysis in case.analyses:
            if latest_analysis is None or analysis.sort_timestamp > latest_analysis.sort_timestamp:
                latest_case, latest_analysis = case, analysis
    return latest_case, latest_analysis


def test_bootstrap_cases_and_active_selection_match_the_previous_implementation(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    _seed(repo)
    expected_cases = _legacy_cases(repo)
    expected_case, expected_analysis = _legacy_latest(repo)

    state = build_workbench_state(repo)

    assert state["cases"] == expected_cases
    assert state["active_case_id"] == expected_case.id
    assert state["active_case_title"] == expected_case.title
    assert state["active_analysis_id"] == expected_analysis.id
    assert state["capture_count"] == len(expected_case.analyses)
    assert state["analysis_complete"] is True
    assert state["dashboard"]["flows"] == len(expected_analysis.features["flows"])
    assert state["dashboard"]["report"] == expected_analysis.report
    assert len(state["dashboard"]["evidence"]) == len(expected_analysis.iocs)
    # A second (cached) build is identical.
    assert build_workbench_state(repo)["cases"] == expected_cases


def test_selected_analysis_matches_the_previous_implementation(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    _seed(repo)
    selected = repo.get_analysis("an-2-0")
    expected_case = repo.get_case(selected.case_id)

    state = build_workbench_state(repo, analysis_id="an-2-0")

    assert state["active_analysis_id"] == "an-2-0"
    assert (state["active_case_id"], state["active_case_title"]) == (expected_case.id, expected_case.title)
    assert state["capture_count"] == len(expected_case.analyses)
    assert state["cases"] == _legacy_cases(repo)


def test_selected_analysis_outside_the_listed_cases_still_resolves_its_case(tmp_path, monkeypatch):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    _seed(repo)
    original = repo.list_cases
    monkeypatch.setattr(repo, "list_cases", lambda **kwargs: [c for c in original(**kwargs) if c.id != "case1"])

    state = build_workbench_state(repo, analysis_id="an-1-0")

    assert (state["active_case_id"], state["capture_count"]) == ("case1", 1)
    assert "case1" not in {row["id"] for row in state["cases"]}


def test_unknown_analysis_id_is_404(tmp_path):
    from fastapi import HTTPException

    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    with pytest.raises(HTTPException) as raised:
        build_workbench_state(repo, analysis_id="missing")
    assert raised.value.status_code == 404


def test_bootstrap_loads_each_case_once_and_decompresses_only_what_it_shows(tmp_path, monkeypatch):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    _seed(repo)
    analyses_total = 6  # 0 + 1 + 2 + 3
    blobs_per_full_analysis = 5  # features, osint, dns, session artifacts (+ none for unset columns) - measured below

    monkeypatch.setattr(repo, "get_case", lambda *a, **kw: pytest.fail("bootstrap must not load full cases"))
    full_loads: list[str] = []
    original_get_analysis = repo.get_analysis
    monkeypatch.setattr(
        repo, "get_analysis", lambda analysis_id: full_loads.append(analysis_id) or original_get_analysis(analysis_id)
    )
    calls: list[int] = []
    original_decompress = gzip.decompress
    monkeypatch.setattr(gzip, "decompress", lambda data: calls.append(len(data)) or original_decompress(data))

    build_workbench_state(repo)
    first = len(calls)
    assert full_loads == ["an-3-2"], "only the active analysis is loaded in full"
    # One features blob per listed analysis for its flow count, plus the active analysis's own blobs.
    assert analyses_total < first <= analyses_total + blobs_per_full_analysis

    calls.clear()
    build_workbench_state(repo)
    assert len(calls) == first - analyses_total, "flow counts are remembered; only the active analysis is re-read"


def test_flow_count_follows_a_resaved_analysis(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    repo.create_case(Case(id="c", title="t"))
    analysis = Analysis(id="a", case_id="c", pcap_path="x.pcap", features={"flows": _flows(3)})
    repo.save_analysis(analysis)
    assert build_workbench_state(repo)["cases"][0]["analyses"][0]["flow_count"] == 3

    analysis.features = {"flows": _flows(40)}
    repo.save_analysis(analysis)
    assert build_workbench_state(repo)["cases"][0]["analyses"][0]["flow_count"] == 40


def test_summaries_tolerate_missing_and_malformed_feature_blobs(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    repo.create_case(Case(id="c", title="t"))
    repo.save_analysis(Analysis(id="empty", case_id="c", pcap_path="x.pcap"))
    repo.save_analysis(Analysis(id="odd", case_id="c", pcap_path="y.pcap", features={"flows": _flows(2)}))
    repo.save_analysis(Analysis(id="list", case_id="c", pcap_path="z.pcap", features={"flows": _flows(2)}))
    with repo._get_conn() as conn:
        conn.execute("UPDATE analyses SET features_json=? WHERE id='empty'", (b"not gzip, not json",))
        conn.execute("UPDATE analyses SET features_json=? WHERE id='odd'", (gzip.compress(b'{"flows": 7}'),))
        conn.execute("UPDATE analyses SET features_json=? WHERE id='list'", (gzip.compress(b"[1, 2, 3]"),))
        conn.commit()

    ((_, summaries),) = repo.list_case_summaries()

    assert {summary.id: summary.flow_count for summary in summaries} == {"empty": 0, "odd": 0, "list": 0}
    assert repo.get_case_summary("missing") is None


# ── timeline buckets ─────────────────────────────────────────────────────────


def _flow_at(moment: datetime, dst: str = "8.8.8.8", proto: str = "TCP") -> dict:
    return {"src": "10.0.0.5", "dst": dst, "proto": proto, "count": 2, "bytes": 100, "first_ts": moment.timestamp()}


def test_single_day_timeline_keeps_short_labels_and_gains_ts():
    day = datetime(2026, 9, 1, tzinfo=timezone.utc)
    flows = [_flow_at(day.replace(hour=10, minute=5)), _flow_at(day.replace(hour=10, minute=5, second=40))]
    flows.append(_flow_at(day.replace(hour=9, minute=59)))

    assert _traffic_rows(flows) == [
        {"time": "09:59", "flows": 1, "ts": "2026-09-01T09:59:00Z"},
        {"time": "10:05", "flows": 2, "ts": "2026-09-01T10:05:00Z"},
    ]


def test_timeline_crossing_midnight_is_chronological_and_unambiguous():
    before = datetime(2026, 9, 1, 23, 59, tzinfo=timezone.utc)
    after = datetime(2026, 9, 2, 0, 1, tzinfo=timezone.utc)

    rows = _traffic_rows([_flow_at(after), _flow_at(before)])

    assert [row["ts"] for row in rows] == ["2026-09-01T23:59:00Z", "2026-09-02T00:01:00Z"]
    assert [row["time"] for row in rows] == ["2026-09-01 23:59", "2026-09-02 00:01"]


def test_same_clock_minute_on_different_days_is_not_merged():
    first = datetime(2026, 9, 1, 10, 5, tzinfo=timezone.utc)
    flows = [_flow_at(first), _flow_at(first + timedelta(days=1)), _flow_at(first + timedelta(days=2, seconds=20))]

    rows = _traffic_rows(flows)

    assert [row["flows"] for row in rows] == [1, 1, 1]
    assert len({row["time"] for row in rows}) == 3
    assert [row["time"] for row in rows] == sorted(row["time"] for row in rows)


def test_timeline_ignores_unusable_timestamps():
    good = _flow_at(datetime(2026, 9, 1, 10, 5, tzinfo=timezone.utc))
    bad = [{"first_ts": value, "src": "a", "dst": "b"} for value in ("x", float("nan"), float("inf"), 1e30, None)]
    assert [row["flows"] for row in _traffic_rows([good, *bad])] == [1]


def _filter_like_the_client(map_flows: list[dict], time: str) -> list[dict]:
    """dashboardFilters.js: keep destinations with a slice whose ``time`` equals the clicked bucket label."""
    return [flow for flow in map_flows if any(piece["time"] == time for piece in flow["traffic_slices"])]


def test_map_time_filter_labels_match_timeline_labels_across_days(monkeypatch):
    monkeypatch.setattr(
        "app.web.state.GeoIP.lookup",
        lambda ip: {"city": "X", "country": "Y", "continent": "Z", "lat": 1.0, "lon": 2.0},
    )
    day_one = datetime(2026, 9, 1, 10, 5, tzinfo=timezone.utc)
    flows = [
        _flow_at(day_one, dst="8.8.8.8"),
        _flow_at(day_one + timedelta(days=1), dst="1.1.1.1", proto="UDP"),
        _flow_at(day_one + timedelta(days=1, seconds=10), dst="8.8.8.8"),
    ]

    timeline = _traffic_rows(flows)
    mapped = _map_flows(flows, {})

    slice_labels = {piece["time"] for flow in mapped for piece in flow["traffic_slices"]}
    assert slice_labels == {row["time"] for row in timeline}
    day_one_label, day_two_label = (row["time"] for row in timeline)
    assert {flow["ip"] for flow in _filter_like_the_client(mapped, day_one_label)} == {"8.8.8.8"}
    assert {flow["ip"] for flow in _filter_like_the_client(mapped, day_two_label)} == {"8.8.8.8", "1.1.1.1"}
    google = next(flow for flow in mapped if flow["ip"] == "8.8.8.8")
    assert [piece["ts"] for piece in google["traffic_slices"]] == ["2026-09-01T10:05:00Z", "2026-09-02T10:05:00Z"]


# ── map verdict honesty ──────────────────────────────────────────────────────


def test_map_marks_unenriched_destinations_as_not_assessed(monkeypatch):
    monkeypatch.setattr(
        "app.web.state.GeoIP.lookup",
        lambda ip: {"city": "X", "country": "Y", "continent": "Z", "lat": 1.0, "lon": 2.0},
    )
    moment = datetime(2026, 9, 1, 10, 5, tzinfo=timezone.utc)
    flows = [_flow_at(moment, dst=ip) for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "4.4.4.4", "5.5.5.5")]
    osint = {
        "ips": {
            "1.1.1.1": {"ptr": "one.one.one.one", "city": "X", "country": "Y"},  # annotations only
            "9.9.9.9": {"abuseipdb": {"abuseConfidenceScore": 0}, "score": 0.1},  # assessed, benign
            "4.4.4.4": {"score": 0.9, "virustotal": {"malicious": 12}},  # assessed, bad
            "5.5.5.5": "malformed",
        }
    }

    by_ip = {flow["ip"]: flow for flow in _map_flows(flows, osint)}

    assert {ip: (f["status"], f["assessed"], f["assessment"]) for ip, f in by_ip.items()} == {
        "8.8.8.8": ("Expected", False, "Not assessed"),
        "1.1.1.1": ("Expected", False, "Not assessed"),
        "9.9.9.9": ("Expected", True, "Expected"),
        "4.4.4.4": ("Review", True, "Review"),
        "5.5.5.5": ("Expected", False, "Not assessed"),
    }
    # The client switches on the exact legacy strings; they must not change.
    assert {flow["status"] for flow in by_ip.values()} <= {"Expected", "Review"}
    assert by_ip["4.4.4.4"]["color"] == "#ffbd59" and by_ip["8.8.8.8"]["color"] == "#47a8ff"
