# tests/api/test_gc.py
"""Tests for background garbage collection."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from app.api.feed import IOCFilter, query_iocs
from app.api.gc import gc_sweep
from app.api.settings import APISettings
from app.database.models import IOC, Analysis, Case, IOCType, Job, JobStatus, Severity
from app.database.repository import CaseRepository


def _settings(tmp_path) -> APISettings:
    return APISettings(
        main_key="x",
        feed_key=None,
        host="127.0.0.1",
        port=8000,
        workers=1,
        queue_depth=10,
        max_pcap_bytes=10**9,
        upload_timeout_seconds=60,
        pcap_ttl_days=1,
        artifact_ttl_days=2,
        job_ttl_days=3,
        require_https=False,
        cors_origins=[],
        webhook_timeout_seconds=10,
        webhook_max_retries=2,
    )


def test_gc_removes_old_pcap_files(tmp_path):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    old = uploads / "old.pcap"
    old.write_bytes(b"x" * 1000)
    fresh = uploads / "fresh.pcap"
    fresh.write_bytes(b"y" * 1000)

    # Backdate `old.pcap` by 10 days
    ten_days_ago = (datetime.now() - timedelta(days=10)).timestamp()
    os.utime(old, (ten_days_ago, ten_days_ago))

    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    settings = _settings(tmp_path)

    stats = gc_sweep(repo=repo, settings=settings, uploads_dir=uploads, artifacts_dir=tmp_path / "artifacts")
    assert stats["pcaps_deleted"] == 1
    assert not old.exists()
    assert fresh.exists()


def test_gc_deletes_old_job_rows(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="t"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    repo.update_job_status(job_id, JobStatus.DONE)

    # Backdate finished_at by 10 days
    conn = repo._get_conn()
    try:
        old = (datetime.now() - timedelta(days=10)).isoformat()
        conn.execute("UPDATE jobs SET finished_at=? WHERE id=?", (old, job_id))
        conn.commit()
    finally:
        conn.close()

    settings = _settings(tmp_path)
    stats = gc_sweep(
        repo=repo, settings=settings, uploads_dir=tmp_path / "uploads", artifacts_dir=tmp_path / "artifacts"
    )
    assert stats["jobs_deleted"] >= 1
    assert repo.get_job(job_id) is None


def test_gc_removes_old_run_dirs_keeps_fresh(tmp_path):
    """Carve output lives in per-run subdirs (data/carved/<run_id>/) — GC must
    remove expired top-level directories, not only loose files."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    old_dir = artifacts / "case1_deadbeef"
    old_dir.mkdir()
    (old_dir / "stream1_aaaa.bin").write_bytes(b"x" * 100)
    fresh_dir = artifacts / "case2_cafef00d"
    fresh_dir.mkdir()
    (fresh_dir / "stream2_bbbb.bin").write_bytes(b"y" * 100)

    # Backdate the old run dir past artifact_ttl_days (2 in _settings)
    ten_days_ago = (datetime.now() - timedelta(days=10)).timestamp()
    os.utime(old_dir, (ten_days_ago, ten_days_ago))

    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    settings = _settings(tmp_path)

    stats = gc_sweep(repo=repo, settings=settings, uploads_dir=tmp_path / "uploads", artifacts_dir=artifacts)
    assert stats["artifacts_deleted"] == 1
    assert not old_dir.exists()
    assert fresh_dir.exists()
    assert (fresh_dir / "stream2_bbbb.bin").exists()


def test_gc_keeps_fresh_files(tmp_path):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    fresh = uploads / "fresh.pcap"
    fresh.write_bytes(b"y" * 1000)

    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    settings = _settings(tmp_path)

    stats = gc_sweep(repo=repo, settings=settings, uploads_dir=uploads, artifacts_dir=tmp_path / "artifacts")
    assert stats["pcaps_deleted"] == 0
    assert fresh.exists()


def test_gc_handles_missing_directory(tmp_path):
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    settings = _settings(tmp_path)

    stats = gc_sweep(
        repo=repo,
        settings=settings,
        uploads_dir=tmp_path / "nonexistent",
        artifacts_dir=tmp_path / "also_nonexistent",
    )
    assert stats["pcaps_deleted"] == 0
    assert stats["artifacts_deleted"] == 0


# ---------------------------------------------------------------------------
# Task 5b: orphan reconcile sweep
# ---------------------------------------------------------------------------


def _seed_case_with_children(repo: CaseRepository, case_id: str) -> tuple[str, str]:
    """Seed a case with an analysis, IOC, note, tag link, and job (production shapes)."""
    repo.create_case(Case(id=case_id, title="t", tags=["soar:tines"]))
    analysis_id = repo.save_analysis(
        Analysis(
            case_id=case_id,
            pcap_path="/tmp/x.pcap",
            pcap_hash="hash",
            iocs=[IOC(ioc_type=IOCType.IP, value="203.0.113.7", severity=Severity.HIGH)],
        )
    )
    repo.add_note(case_id, "investigating", analysis_id=analysis_id)
    job_id = repo.create_job(Job(case_id=case_id, pcap_path="/tmp/x.pcap"))
    return analysis_id, job_id


def test_gc_reconciles_orphaned_case_children(tmp_path):
    """Pre-cascade delete_case removed only the cases row; GC must heal the leftovers."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    analysis_id, job_id = _seed_case_with_children(repo, "feed0001")

    # Simulate legacy damage: only the cases row goes away (the FK pragma is
    # off per connection, so children survive exactly as the old single-table
    # delete_case left them).
    conn = repo._get_conn()
    try:
        conn.execute("DELETE FROM cases WHERE id=?", ("feed0001",))
        conn.commit()
    finally:
        conn.close()
    assert [r["value"] for r in query_iocs(repo, IOCFilter())] == ["203.0.113.7"], "orphan poisons the feed"

    stats = gc_sweep(
        repo=repo, settings=_settings(tmp_path), uploads_dir=tmp_path / "uploads", artifacts_dir=tmp_path / "artifacts"
    )

    # analysis + ioc + analysis-note + case_tag + job
    assert stats["orphaned_rows_deleted"] == 5
    assert repo.get_analysis(analysis_id) is None
    assert repo.get_job(job_id) is None
    assert query_iocs(repo, IOCFilter()) == [], "the feed must stop serving orphaned IOCs"
    conn = repo._get_conn()
    try:
        for table in ("analyses", "iocs", "notes", "case_tags", "jobs"):
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert count == 0, f"orphaned {table} rows must be reconciled"
    finally:
        conn.close()


def test_gc_orphan_sweep_keeps_healthy_cases(tmp_path):
    """A live case with children must come through the sweep untouched."""
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    analysis_id, job_id = _seed_case_with_children(repo, "feed0002")

    stats = gc_sweep(
        repo=repo, settings=_settings(tmp_path), uploads_dir=tmp_path / "uploads", artifacts_dir=tmp_path / "artifacts"
    )

    assert stats["orphaned_rows_deleted"] == 0
    case = repo.get_case("feed0002")
    assert case is not None
    assert len(case.analyses) == 1
    assert len(case.notes) == 1
    assert case.tags == ["soar:tines"]
    assert repo.get_analysis(analysis_id) is not None
    assert repo.get_job(job_id) is not None
    assert [r["value"] for r in query_iocs(repo, IOCFilter())] == ["203.0.113.7"]


# ---------------------------------------------------------------------------
# Reports-dir GC sweep
# ---------------------------------------------------------------------------


def test_gc_sweeps_old_report_pdfs(tmp_path):
    """GC must delete expired cached PDFs (and .pdf.tmp from crashed renders)
    while leaving fresh ones alone; pdfs_deleted counter must reflect the count."""
    reports = tmp_path / "reports"
    reports.mkdir()

    old_pdf = reports / "case_abc123.pdf"
    old_pdf.write_bytes(b"%PDF-1.4 old")
    old_tmp = reports / "case_xyz789.pdf.tmp"
    old_tmp.write_bytes(b"partial render")
    fresh_pdf = reports / "case_def456.pdf"
    fresh_pdf.write_bytes(b"%PDF-1.4 fresh")

    # Backdate the old files past artifact_ttl_days (2 in _settings)
    ten_days_ago = (datetime.now() - timedelta(days=10)).timestamp()
    os.utime(old_pdf, (ten_days_ago, ten_days_ago))
    os.utime(old_tmp, (ten_days_ago, ten_days_ago))

    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    settings = _settings(tmp_path)

    stats = gc_sweep(
        repo=repo,
        settings=settings,
        uploads_dir=tmp_path / "uploads",
        artifacts_dir=tmp_path / "artifacts",
        reports_dir=reports,
    )

    assert stats["pdfs_deleted"] == 2
    assert not old_pdf.exists()
    assert not old_tmp.exists()
    assert fresh_pdf.exists()
