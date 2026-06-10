# tests/api/test_gc.py
"""Tests for background garbage collection."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from app.api.gc import gc_sweep
from app.api.settings import APISettings
from app.database.models import Case, Job, JobStatus
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
