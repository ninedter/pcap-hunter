# tests/api/test_cases.py
"""Tests for GET/DELETE /api/v1/cases/{id} and /report.pdf endpoints."""

from __future__ import annotations

import os
import pathlib
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
    monkeypatch.setenv("PCAP_HUNTER_API_UPLOADS_DIR", str(tmp_path / "uploads"))

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
    assert r.content == b"", f"204 must have an empty body (RFC 7230); got {r.content!r}"
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


def test_delete_case_removes_files(client, tmp_path, monkeypatch):
    """DELETE must clean up the uploaded pcap, cached pdf, and per-run zeek/carve dirs."""
    from app import config as config_module

    uploads = pathlib.Path(os.environ["PCAP_HUNTER_API_UPLOADS_DIR"])
    reports = tmp_path / "reports"
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(reports))
    zeek_base = tmp_path / "zeek"
    carve_base = tmp_path / "carved"
    monkeypatch.setattr(config_module, "ZEEK_DIR", zeek_base)
    monkeypatch.setattr(config_module, "CARVE_DIR", carve_base)

    case_id = _seed_case_with_analysis("delfiles1")

    uploads.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    (uploads / f"{case_id}.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    (reports / f"{case_id}.pdf").write_bytes(b"%PDF-fake")
    # Per-run output dirs as the pipeline runner creates them: <sanitized-case>_<uuid8>
    (zeek_base / f"{case_id}_deadbeef").mkdir(parents=True)
    (zeek_base / f"{case_id}_deadbeef" / "conn.log").write_text("zeek log")
    (carve_base / f"{case_id}_deadbeef").mkdir(parents=True)
    # Another case's run dir must survive the cleanup glob.
    (zeek_base / "othercase_cafe0001").mkdir(parents=True)
    # A dir that shares the case_id as a prefix but WITHOUT the underscore separator
    # must also survive (guards against an over-greedy glob missing the "_" anchor).
    (zeek_base / f"{case_id}x_cafe0001").mkdir(parents=True)

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 204
    assert not (uploads / f"{case_id}.pcap").exists()
    assert not (reports / f"{case_id}.pdf").exists()
    assert not (zeek_base / f"{case_id}_deadbeef").exists()
    assert not (carve_base / f"{case_id}_deadbeef").exists()
    assert (zeek_base / "othercase_cafe0001").exists()
    assert (zeek_base / f"{case_id}x_cafe0001").exists(), "over-greedy glob must not delete dirs with extended prefix"


def test_delete_case_succeeds_when_no_artifacts_exist(client, tmp_path, monkeypatch):
    """File cleanup is best-effort: missing artifacts must never break the 204."""
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(tmp_path / "reports-nonexistent"))
    case_id = _seed_case_with_analysis("delfiles2")

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 204

    from app.api.deps import get_repo

    assert get_repo().get_case(case_id) is None


def test_delete_case_409_when_queued_job_starts_mid_delete(client, monkeypatch):
    """When cancel_queued_job returns False (job flipped queued→running between SELECT
    and CAS), DELETE must return 409 case_has_running_job and leave the case intact."""
    from app.api.deps import get_repo
    from app.database.models import Case, Job

    repo = get_repo()
    case_id = repo.create_case(Case(title="race-case"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))

    # Simulate the job flipping queued→running between our SELECT and the CAS cancel.
    monkeypatch.setattr("app.api.routers.cases.cancel_queued_job", lambda repo, jid: False)

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "case_has_running_job"
    assert body["job_id"] == job_id

    # Case must still exist — the analyst's data is preserved.
    r2 = client.get(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r2.status_code == 200


def test_delete_case_404_when_concurrent_delete_wins(client, tmp_path, monkeypatch):
    """When a concurrent DELETE removes the row between our existence check and our delete,
    repo.delete_case returns False but the case no longer exists — must return 404, not 500."""
    from app.database.repository import CaseRepository

    case_id = _seed_case_with_analysis("delrace1")

    # Patch delete_case to actually perform the deletion (simulating the concurrent winner)
    # but return False (as if it detected a race).
    real_delete = CaseRepository.delete_case

    def race_delete(self, cid):
        real_delete(self, cid)  # concurrent winner already removed it
        return False

    monkeypatch.setattr(CaseRepository, "delete_case", race_delete)

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 404
    body = r.json()
    assert body["code"] == "case_not_found"


def test_delete_case_500_and_no_file_removal_when_db_delete_fails(client, tmp_path, monkeypatch):
    """When repo.delete_case returns False (DB failure), the route must return 500
    and must NOT destroy the analyst's evidence files."""
    from app.database.repository import CaseRepository

    uploads = pathlib.Path(os.environ["PCAP_HUNTER_API_UPLOADS_DIR"])
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(tmp_path / "reports"))

    case_id = _seed_case_with_analysis("delfail1")

    uploads.mkdir(parents=True, exist_ok=True)
    pcap_file = uploads / f"{case_id}.pcap"
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    # Make the DB delete silently fail (e.g. locked DB → repository returns False).
    monkeypatch.setattr(CaseRepository, "delete_case", lambda self, cid: False)

    r = client.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 500
    body = r.json()
    assert body["code"] == "case_delete_failed"
    # Evidence files must be untouched — the analyst's pcap must still exist.
    assert pcap_file.exists(), "pcap must not be deleted when the DB delete fails"


def test_api_reports_dir_env_takes_precedence(client, tmp_path, monkeypatch):
    """PCAP_HUNTER_API_REPORTS_DIR must take precedence over the legacy PCAP_HUNTER_REPORTS_DIR.
    Pre-place a fake PDF in the API-prefixed dir; the route must serve it.
    The legacy dir must remain untouched."""
    api_reports = tmp_path / "api_reports"
    legacy_reports = tmp_path / "legacy_reports"
    api_reports.mkdir()
    legacy_reports.mkdir()

    monkeypatch.setenv("PCAP_HUNTER_API_REPORTS_DIR", str(api_reports))
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(legacy_reports))

    case_id = _seed_case_with_analysis("rptenv1")

    # Pre-place a fake (but valid-looking) cached PDF in the API-prefixed dir.
    # The route checks cache_fresh against analysis mtime; writing the file *after*
    # seeding the analysis means mtime(file) >= analyzed_at, so it serves the cache.
    fake_pdf = api_reports / f"{case_id}.pdf"
    fake_pdf.write_bytes(b"%PDF-1.4 fake-for-env-test")

    r = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers={"Authorization": "Bearer MAIN"})
    assert r.status_code == 200
    assert r.content.startswith(b"%PDF")

    # The legacy dir must be untouched — no PDF landed there.
    assert not (legacy_reports / f"{case_id}.pdf").exists(), (
        "PCAP_HUNTER_REPORTS_DIR must be ignored when PCAP_HUNTER_API_REPORTS_DIR is set"
    )
