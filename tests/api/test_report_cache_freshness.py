"""A report rewritten by the report-only LLM job must invalidate the cached PDF."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.database.models import Analysis, Case
from app.database.repository import CaseRepository


def test_report_stamp_moves_only_when_the_narrative_changes(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    repo.create_case(Case(id="c1", title="t"))
    analysis = Analysis(id="a1", case_id="c1", pcap_path="x.pcap", report="first")
    repo.save_analysis(analysis)
    assert repo.get_analysis("a1").report_updated_at is None, "first save: nothing was rewritten"

    repo.save_analysis(repo.get_analysis("a1"))  # same report, e.g. artifacts-only update
    assert repo.get_analysis("a1").report_updated_at is None

    rewritten = repo.get_analysis("a1")
    rewritten.report = "second"
    before = datetime.now(timezone.utc)
    repo.save_analysis(rewritten)
    stamped = repo.get_analysis("a1")
    assert stamped.analyzed_at == analysis.analyzed_at, "analyzed_at alone cannot reveal the rewrite"
    assert stamped.report_updated_at is not None and stamped.report_updated_at >= before
    assert stamped.to_dict()["report_updated_at"] == stamped.report_updated_at.isoformat()

    repo.save_analysis(repo.get_analysis("a1"))  # unchanged again: stamp is kept
    assert repo.get_analysis("a1").report_updated_at == stamped.report_updated_at
    assert repo.get_case("c1").analyses[0].report_updated_at == stamped.report_updated_at


def test_report_column_is_added_to_an_existing_database(tmp_path):
    import sqlite3

    db = tmp_path / "legacy.db"
    repo = CaseRepository(db_path=str(db))
    repo.create_case(Case(id="c1", title="t"))
    repo.save_analysis(Analysis(id="a1", case_id="c1", pcap_path="x.pcap", report="old"))
    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE analyses DROP COLUMN report_updated_at")
    conn.commit()
    conn.close()

    repo = CaseRepository(db_path=str(db))
    loaded = repo.get_analysis("a1")
    assert (loaded.report, loaded.report_updated_at) == ("old", None)
    loaded.report = "new"
    repo.save_analysis(loaded)
    assert repo.get_analysis("a1").report_updated_at is not None


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "MAIN")
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("PCAP_HUNTER_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.delenv("PCAP_HUNTER_API_REPORTS_DIR", raising=False)
    from app.api.deps import get_queue, get_repo, get_settings

    for getter in (get_settings, get_repo, get_queue):
        getter.cache_clear()
    from app.api.app import create_app

    yield TestClient(create_app())
    for getter in (get_settings, get_repo, get_queue):
        getter.cache_clear()


def test_report_only_llm_job_invalidates_the_cached_pdf(client, tmp_path, monkeypatch):
    """End to end through the real report-only job: stale PDF is re-rendered, then cached again."""
    import json

    import app.api.queue as queue_mod
    from app.api.deps import get_repo
    from app.database.models import Job, JobStatus
    from app.llm import providers as llm_providers
    from app.reports.pdf_generator import PDFReportGenerator

    repo = get_repo()
    repo.create_case(Case(id="pdfllm", title="t"))
    analysis_id = repo.save_analysis(
        Analysis(
            case_id="pdfllm",
            pcap_path="x.pcap",
            report="old narrative",
            features={"flows": [], "artifacts": {"ips": [], "domains": []}},
        )
    )
    analysis = repo.get_analysis(analysis_id)

    rendered: list[str] = []

    def fake_generate(self, report_md="", **kwargs):
        rendered.append(report_md)
        return SimpleNamespace(content=b"%PDF-" + report_md.encode())

    monkeypatch.setattr(PDFReportGenerator, "is_available", property(lambda self: True))
    monkeypatch.setattr(PDFReportGenerator, "generate", fake_generate)
    url = "/api/v1/cases/pdfllm/report.pdf"
    auth = {"Authorization": "Bearer MAIN"}

    assert client.get(url, headers=auth).content == b"%PDF-old narrative"
    assert client.get(url, headers=auth).content == b"%PDF-old narrative"
    assert rendered == ["old narrative"], "second request served from cache"
    pdf = tmp_path / "reports" / "pdfllm.pdf"
    assert pdf.stat().st_mtime >= analysis.sort_timestamp, "fresh by the analyzed_at rule alone"

    monkeypatch.setattr(
        queue_mod, "_load_llm_settings", lambda: ("lmstudio", "http://x/v1", "", "m", "en", 32000, False)
    )
    monkeypatch.setattr(llm_providers, "synthesize_report", lambda *a, **kw: "new narrative")
    options = {"_job_type": "llm_report", "_analysis_id": analysis_id, "llm_enabled": True}
    job_id = repo.create_job(Job(case_id="pdfllm", pcap_path="x.pcap", options_json=json.dumps(options)))
    queue_mod._worker_run(job_id, str(repo._db_path), "x.pcap", options)
    assert repo.get_job(job_id).status == JobStatus.DONE
    assert repo.get_analysis(analysis_id).analyzed_at == analysis.analyzed_at

    assert client.get(url, headers=auth).content == b"%PDF-new narrative"
    assert client.get(url, headers=auth).content == b"%PDF-new narrative"
    assert rendered == ["old narrative", "new narrative"], "re-rendered once, then cached again"


def test_full_scope_recovery_hint_points_at_real_v3_controls():
    from app.api.routers.admin import _LOCKOUT_WARNING
    from app.api.settings import FULL_SCOPE_RECOVERY_HINT

    assert "PCAP_HUNTER_API_KEY" in FULL_SCOPE_RECOVERY_HINT
    assert "POST /api/v1/admin/keys" in FULL_SCOPE_RECOVERY_HINT
    assert "Streamlit" not in FULL_SCOPE_RECOVERY_HINT
    assert FULL_SCOPE_RECOVERY_HINT in _LOCKOUT_WARNING
