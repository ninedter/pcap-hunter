# tests/api/test_feed_query.py
"""Tests for IOC aggregation query layer."""

from __future__ import annotations

from datetime import datetime

from app.api.feed import IOCFilter, query_iocs
from app.database.models import IOC, Analysis, Case, CaseStatus, IOCType, Severity
from app.database.repository import CaseRepository


def _seed(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case = Case(id="case0001", title="t", tags=["soar:tines"])
    repo.create_case(case)
    analysis = Analysis(
        case_id=case.id,
        pcap_path="/tmp/x.pcap",
        pcap_hash="hash",
        analyzed_at=datetime(2026, 4, 27, 12, 0),
        iocs=[
            IOC(ioc_type=IOCType.IP, value="1.2.3.4", severity=Severity.HIGH),
            IOC(ioc_type=IOCType.DOMAIN, value="evil.example", severity=Severity.MEDIUM),
        ],
    )
    repo.save_analysis(analysis)
    return repo


def test_query_iocs_returns_all(tmp_path):
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter())
    assert len(rows) == 2
    values = {r["value"] for r in rows}
    assert values == {"1.2.3.4", "evil.example"}


def test_query_iocs_filters_by_type(tmp_path):
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter(types=["ip"]))
    assert all(r["type"] == "ip" for r in rows)


def test_query_iocs_filters_by_tag(tmp_path):
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter(tag="soar:tines"))
    assert len(rows) == 2
    rows = query_iocs(repo, IOCFilter(tag="nonexistent"))
    assert rows == []


def test_query_iocs_includes_case_ids_and_first_seen(tmp_path):
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter())
    for r in rows:
        assert "case0001" in r["case_ids"]
        assert r["first_seen"] is not None


def test_query_iocs_score_from_severity(tmp_path):
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter())
    scores = {r["value"]: r["score"] for r in rows}
    assert scores["1.2.3.4"] == 75  # HIGH
    assert scores["evil.example"] == 50  # MEDIUM


def test_query_iocs_min_score_filter(tmp_path):
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter(min_score=75))
    assert len(rows) == 1
    assert rows[0]["value"] == "1.2.3.4"


def test_min_score_filters_before_pagination(tmp_path):
    """Reproduces the 2026-06-11 live bug: 3 IOCs score >= 40, limit=2 must
    return 2 + a cursor-page of 1 — not a single row with no cursor."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="feedcase", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    analysis = Analysis(case_id="feedcase", pcap_path="x.pcap", features={"artifacts": {}})
    analysis.iocs = [
        IOC(ioc_type=IOCType.DOMAIN, value="low.example", severity=Severity.LOW),  # 25
        IOC(ioc_type=IOCType.DOMAIN, value="high.example", severity=Severity.HIGH),  # 75
        IOC(ioc_type=IOCType.HASH, value="c0" * 32, severity=Severity.MEDIUM),  # 50
        IOC(ioc_type=IOCType.IP, value="203.0.113.66", severity=Severity.CRITICAL),  # 100
    ]
    repo.save_analysis(analysis)

    page1 = query_iocs(repo, IOCFilter(min_score=40, limit=2, offset=0))
    assert len(page1) == 2
    page2 = query_iocs(repo, IOCFilter(min_score=40, limit=2, offset=2))
    assert len(page2) == 1
    assert all(r["score"] >= 40 for r in page1 + page2)
    values = {r["value"] for r in page1 + page2}
    assert values == {"high.example", "c0" * 32, "203.0.113.66"}


def test_duplicate_ioc_takes_max_severity_score(tmp_path):
    """The same indicator across analyses groups to one row with the max score."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="feedcas2", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    for sev in (Severity.CRITICAL, Severity.LOW):
        a = Analysis(case_id="feedcas2", pcap_path="x.pcap", features={"artifacts": {}})
        a.iocs = [IOC(ioc_type=IOCType.IP, value="198.51.100.7", severity=sev)]
        repo.save_analysis(a)

    rows = query_iocs(repo, IOCFilter())
    row = next(r for r in rows if r["value"] == "198.51.100.7")
    assert row["score"] == 100
    assert row["severity"] == "critical"


def test_query_iocs_derives_mitre_techniques(tmp_path):
    """mitre_techniques must be derived from the analysis's technique IDs, not hardcoded []."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="case9001", title="t"))
    analysis = Analysis(
        case_id="case9001",
        pcap_path="/tmp/x.pcap",
        mitre_techniques=["T1071.001"],
        iocs=[IOC(ioc_type=IOCType.IP, value="9.9.9.9", severity=Severity.HIGH)],
    )
    repo.save_analysis(analysis)

    rows = query_iocs(repo, IOCFilter())
    row = next(r for r in rows if r["value"] == "9.9.9.9")
    assert row["mitre_techniques"] == ["T1071.001"]


def test_query_iocs_no_techniques_returns_empty_list(tmp_path):
    """An analysis with no mapped techniques must yield [], not crash the LEFT JOIN."""
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter())
    for r in rows:
        assert r["mitre_techniques"] == []


def test_query_iocs_multi_technique_multi_tag_no_duplication(tmp_path):
    """Fan-out guard: the LEFT JOIN analysis_techniques multiplies result rows
    (one per technique), which could silently corrupt any non-DISTINCT aggregate.
    Seed multiple techniques AND multiple tags on the same IOC's analysis and
    confirm both tags and technique IDs come back deduped, not repeated."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="case9002", title="t", tags=["tag-a", "tag-b"]))
    analysis = Analysis(
        case_id="case9002",
        pcap_path="/tmp/y.pcap",
        mitre_techniques=["T1071.001", "T1059"],
        iocs=[IOC(ioc_type=IOCType.IP, value="8.8.8.8", severity=Severity.HIGH)],
    )
    repo.save_analysis(analysis)

    rows = query_iocs(repo, IOCFilter())
    row = next(r for r in rows if r["value"] == "8.8.8.8")
    assert row["mitre_techniques"] == ["T1059", "T1071.001"]  # sorted
    assert sorted(row["tags"]) == ["tag-a", "tag-b"]


def test_query_iocs_value_filter_exact_match(tmp_path):
    """An exact value filter returns only the matching IOC row."""
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter(value="1.2.3.4"))
    assert len(rows) == 1
    assert rows[0]["value"] == "1.2.3.4"
    assert rows[0]["score"] == 75
    assert rows[0]["severity"] == "high"


def test_query_iocs_value_filter_unknown_returns_empty(tmp_path):
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter(value="9.9.9.9"))
    assert rows == []


def test_query_iocs_value_filter_is_exact_not_substring(tmp_path):
    """value='1.2.3.4' must not also match '1.2.3.40' (substring false-positive)."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="case9004", title="t"))
    analysis = Analysis(
        case_id="case9004",
        pcap_path="/tmp/z.pcap",
        iocs=[
            IOC(ioc_type=IOCType.IP, value="1.2.3.4", severity=Severity.HIGH),
            IOC(ioc_type=IOCType.IP, value="1.2.3.40", severity=Severity.LOW),
        ],
    )
    repo.save_analysis(analysis)

    rows = query_iocs(repo, IOCFilter(value="1.2.3.4"))
    assert len(rows) == 1
    assert rows[0]["value"] == "1.2.3.4"


def test_query_iocs_value_filter_composes_with_type_filter(tmp_path):
    """value filter must AND with the existing type filter, not override it."""
    repo = _seed(tmp_path)
    rows = query_iocs(repo, IOCFilter(value="1.2.3.4", types=["domain"]))
    assert rows == []
    rows = query_iocs(repo, IOCFilter(value="1.2.3.4", types=["ip"]))
    assert len(rows) == 1
    assert rows[0]["value"] == "1.2.3.4"


def test_query_iocs_techniques_dont_affect_pagination(tmp_path):
    """LIMIT/OFFSET must still page over distinct (ioc_type, value) groups, not
    over the post-join fan-out rows, when techniques are present."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="case9003", title="t", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    analysis = Analysis(
        case_id="case9003",
        pcap_path="x.pcap",
        features={"artifacts": {}},
        mitre_techniques=["T1071.001", "T1059", "T1105"],
    )
    analysis.iocs = [
        IOC(ioc_type=IOCType.IP, value="203.0.113.10", severity=Severity.HIGH),
        IOC(ioc_type=IOCType.IP, value="203.0.113.11", severity=Severity.HIGH),
    ]
    repo.save_analysis(analysis)

    page1 = query_iocs(repo, IOCFilter(limit=1, offset=0))
    page2 = query_iocs(repo, IOCFilter(limit=1, offset=1))
    assert len(page1) == 1
    assert len(page2) == 1
    assert page1[0]["value"] != page2[0]["value"]
