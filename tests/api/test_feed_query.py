# tests/api/test_feed_query.py
"""Tests for IOC aggregation query layer."""

from __future__ import annotations

from datetime import datetime

from app.api.feed import IOCFilter, query_iocs
from app.database.models import IOC, Analysis, Case, IOCType, Severity
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
