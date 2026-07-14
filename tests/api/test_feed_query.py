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


def test_query_iocs_includes_persisted_mitre_techniques(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="mitrecase", title="t"))
    analysis = Analysis(
        case_id="mitrecase",
        pcap_path="x.pcap",
        attack_mapping={"techniques": [{"technique_id": "T1071.004"}, {"technique_id": "T1568.002"}]},
        iocs=[IOC(ioc_type=IOCType.DOMAIN, value="dns.example")],
    )
    repo.save_analysis(analysis)

    rows = query_iocs(repo, IOCFilter())

    assert rows[0]["mitre_techniques"] == ["T1071.004", "T1568.002"]


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
