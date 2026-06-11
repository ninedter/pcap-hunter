# tests/api/test_cases.py
"""Tests for GET/DELETE /api/v1/cases/{id} and /report.pdf endpoints."""

from __future__ import annotations

import os
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

# Import pdf_generator FIRST so its dyld path fix runs before weasyprint is touched (macOS).
from app.reports.pdf_generator import WEASYPRINT_AVAILABLE  # noqa: F401


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))

    from app.api.deps import get_queue, get_repo, get_settings

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()

    from app.api.app import create_app

    yield TestClient(create_app())

    get_settings.cache_clear()
    get_repo.cache_clear()
    get_queue.cache_clear()


def test_get_case_returns_dict(client):
    from app.api.deps import get_repo
    from app.database.models import Case

    case_id = get_repo().create_case(Case(title="x"))

    r = client.get(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == case_id
    assert body["title"] == "x"


def test_get_unknown_case_returns_404(client):
    r = client.get("/api/v1/cases/zzzz9999", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404


def test_report_pdf_returns_404_when_missing(client):
    from app.api.deps import get_repo
    from app.database.models import Case

    case_id = get_repo().create_case(Case(title="x"))

    r = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404


def test_delete_case_no_job(client):
    from app.api.deps import get_repo
    from app.database.models import Case

    case_id = get_repo().create_case(Case(title="x"))

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 204
    assert get_repo().get_case(case_id) is None


def test_delete_case_with_queued_job_cancels_it(client):
    from app.api.deps import get_repo
    from app.database.models import Case, Job

    repo = get_repo()
    case_id = repo.create_case(Case(title="x"))
    repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 204
    assert repo.get_case(case_id) is None


def test_delete_case_with_running_job_returns_409(client):
    from app.api.deps import get_repo
    from app.database.models import Case, Job, JobStatus

    repo = get_repo()
    case_id = repo.create_case(Case(title="x"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.RUNNING)

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "case_has_running_job"


def _seed_case_with_analysis(case_id: str) -> str:
    """Create a case with one persisted analysis (production-shape features)."""
    from app.api.deps import get_repo
    from app.database.models import Analysis, Case, CaseStatus, Severity

    repo = get_repo()
    repo.create_case(Case(id=case_id, title="pdf-case", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    analysis = Analysis(
        case_id=case_id,
        pcap_path="x.pcap",
        pcap_hash="ab" * 32,
        packet_count=20,
        features={
            "flows": [{"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "TCP", "count": 20}],
            "artifacts": {"ips": ["10.0.0.1", "10.0.0.2"], "domains": [], "urls": [], "hashes": [], "ja3": []},
            "beacon_records": [],
        },
    )
    analysis.iocs = repo.extract_iocs(analysis)
    repo.save_analysis(analysis)
    return case_id


@pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="weasyprint unavailable")
def test_report_pdf_generates_on_demand(client, tmp_path, monkeypatch):
    reports_dir = tmp_path / "reports"
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(reports_dir))
    case_id = _seed_case_with_analysis("pdfcase1")

    r = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert (reports_dir / f"{case_id}.pdf").exists(), "render must be cached to disk"

    # Second hit must serve the cached file — prove it by making any re-render explode.
    from app.reports.pdf_generator import PDFReportGenerator

    def _must_not_render(self, **kwargs):
        raise RuntimeError("must not re-render")

    monkeypatch.setattr(PDFReportGenerator, "generate", _must_not_render)
    r2 = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r2.status_code == 200


def test_report_pdf_404_when_no_analysis(client, tmp_path, monkeypatch):
    """A case with zero persisted analyses has nothing to render."""
    from app.api.deps import get_repo
    from app.database.models import Case, CaseStatus, Severity

    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(tmp_path / "reports"))
    get_repo().create_case(Case(id="pdfcase2", title="empty", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))

    r = client.get("/api/v1/cases/pdfcase2/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404
    assert r.json()["code"] == "report_no_analysis"


def test_report_pdf_503_when_renderer_unavailable(client, tmp_path, monkeypatch):
    """An unavailable weasyprint stack degrades to 503 problem+json, never a crash."""
    from app.reports.pdf_generator import PDFReportGenerator

    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(PDFReportGenerator, "is_available", property(lambda self: False))
    case_id = _seed_case_with_analysis("pdfcase3")

    r = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 503
    assert r.json()["code"] == "pdf_unavailable"


def test_report_pdf_500_when_render_fails(client, tmp_path, monkeypatch):
    """A renderer that produces no document degrades to 500 problem+json, never a crash."""
    from app.reports.pdf_generator import PDFReportGenerator

    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(PDFReportGenerator, "is_available", property(lambda self: True))
    monkeypatch.setattr(PDFReportGenerator, "generate", lambda self, **kw: None)
    case_id = _seed_case_with_analysis("pdfcase4")

    r = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 500
    assert r.json()["code"] == "pdf_render_failed"


@pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="weasyprint unavailable")
def test_report_pdf_regenerates_when_newer_analysis_lands(client, tmp_path, monkeypatch):
    """A newer analysis on the case must invalidate the cached pdf — no stale threat reports."""
    from app.api.deps import get_repo
    from app.database.models import Analysis

    reports_dir = tmp_path / "reports"
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(reports_dir))
    case_id = _seed_case_with_analysis("pdfcase5")

    r = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200, r.text
    pdf_file = reports_dir / f"{case_id}.pdf"

    # Age the cache so the incoming analysis is unambiguously newer than the file mtime.
    aged = time.time() - 3600
    os.utime(pdf_file, (aged, aged))

    # A second analysis lands on the same case (UI "add analysis to case" flow).
    repo = get_repo()
    second = Analysis(
        case_id=case_id,
        pcap_path="y.pcap",
        pcap_hash="cd" * 32,
        packet_count=40,
        features={
            "flows": [{"src": "10.0.0.3", "dst": "10.0.0.4", "proto": "TCP", "count": 40}],
            "artifacts": {"ips": ["10.0.0.3", "10.0.0.4"], "domains": [], "urls": [], "hashes": [], "ja3": []},
            "beacon_records": [],
        },
    )
    second.iocs = repo.extract_iocs(second)
    repo.save_analysis(second)

    r2 = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r2.status_code == 200, r2.text
    assert pdf_file.stat().st_mtime > aged, "stale cache must be regenerated when a newer analysis exists"


def test_report_pdf_tolerates_malformed_beacon_records(client, tmp_path, monkeypatch):
    """Corrupt persisted beacon_records degrade to no beacon table — never a route crash."""
    from app.api.deps import get_repo
    from app.database.models import Analysis, Case, CaseStatus, Severity
    from app.reports.pdf_generator import PDFReportGenerator

    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(tmp_path / "reports"))
    captured: dict = {}

    def _fake_generate(self, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(content=b"%PDF-1.4 fake")

    monkeypatch.setattr(PDFReportGenerator, "is_available", property(lambda self: True))
    monkeypatch.setattr(PDFReportGenerator, "generate", _fake_generate)

    repo = get_repo()
    repo.create_case(Case(id="pdfcase6", title="pdf-case", status=CaseStatus.IN_PROGRESS, severity=Severity.LOW))
    analysis = Analysis(
        case_id="pdfcase6",
        pcap_path="x.pcap",
        pcap_hash="ab" * 32,
        packet_count=20,
        features={
            "flows": [],
            "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []},
            "beacon_records": 17,  # corrupt: not a list of records
        },
    )
    repo.save_analysis(analysis)

    r = client.get("/api/v1/cases/pdfcase6/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200, r.text
    assert captured["beacon_df"] is None
