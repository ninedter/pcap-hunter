"""Background garbage collection for retention policies."""

from __future__ import annotations

import logging
import os
import pathlib
import shutil
import time
from datetime import datetime, timedelta

from app.api.settings import APISettings
from app.database.repository import CaseRepository

logger = logging.getLogger(__name__)


def gc_sweep(
    repo: CaseRepository,
    settings: APISettings,
    uploads_dir: pathlib.Path,
    artifacts_dir: pathlib.Path,
    reports_dir: pathlib.Path | None = None,
) -> dict[str, int]:
    """Run one GC pass. Returns counters for telemetry."""
    if reports_dir is None:
        reports_dir = pathlib.Path(
            os.environ.get("PCAP_HUNTER_API_REPORTS_DIR") or os.environ.get("PCAP_HUNTER_REPORTS_DIR", "data/reports")
        )
    pcaps_deleted = _gc_files(uploads_dir, settings.pcap_ttl_days)
    artifacts_deleted = _gc_files(artifacts_dir, settings.artifact_ttl_days)
    # Cached PDFs are derived artifacts — reaping them is safe because the report
    # route regenerates on demand (cache-miss triggers a fresh render).
    pdfs_deleted = _gc_files(reports_dir, settings.artifact_ttl_days)
    jobs_deleted = _gc_old_jobs(repo, settings.job_ttl_days)
    orphaned_rows_deleted = _gc_orphaned_case_rows(repo)
    stats = {
        "pcaps_deleted": pcaps_deleted,
        "artifacts_deleted": artifacts_deleted,
        "pdfs_deleted": pdfs_deleted,
        "jobs_deleted": jobs_deleted,
        "orphaned_rows_deleted": orphaned_rows_deleted,
    }
    logger.info("gc_sweep complete: %s", stats)
    return stats


def _gc_files(dir_path: pathlib.Path, ttl_days: int) -> int:
    """Remove expired entries directly under ``dir_path``.

    Handles both loose files (legacy flat layout) and top-level per-run
    directories (carve output now lives in ``data/carved/<run_id>/``).
    Symlinks are skipped so GC never follows a link out of the data dir.
    """
    if not dir_path.exists():
        return 0
    cutoff = time.time() - (ttl_days * 86400)
    count = 0
    for entry in dir_path.iterdir():
        try:
            if entry.is_symlink():
                continue
            if entry.is_file() and entry.stat().st_mtime < cutoff:
                entry.unlink()
                count += 1
            elif entry.is_dir() and entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
                count += 1
        except OSError as exc:
            logger.warning("gc: failed to remove %s: %s", entry, exc)
    return count


def _gc_old_jobs(repo: CaseRepository, ttl_days: int) -> int:
    cutoff = (datetime.now() - timedelta(days=ttl_days)).isoformat()
    conn = repo._get_conn()
    try:
        cursor = conn.execute(
            "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < ?",
            (cutoff,),
        )
        conn.commit()
        return cursor.rowcount or 0
    finally:
        conn.close()


def _gc_orphaned_case_rows(repo: CaseRepository) -> int:
    """Remove rows whose case no longer exists.

    Heals damage from the pre-cascade ``delete_case``, which removed only the
    cases row — its analyses kept serving in the IOC feed forever (the feed
    joins iocs to analyses only). Covers analyses (plus their iocs and notes),
    case-level notes, case_tags, and jobs. ``notes.case_id`` and
    ``jobs.case_id`` are nullable, so those deletes guard with IS NOT NULL to
    leave case-less rows alone.

    Returns:
        Total number of orphaned rows deleted across all tables.
    """
    orphaned_analyses = "SELECT id FROM analyses WHERE case_id NOT IN (SELECT id FROM cases)"
    conn = repo._get_conn()
    try:
        deleted = 0
        # Children of orphaned analyses first, while the subquery still matches.
        deleted += conn.execute(f"DELETE FROM iocs WHERE analysis_id IN ({orphaned_analyses})").rowcount or 0
        deleted += conn.execute(f"DELETE FROM notes WHERE analysis_id IN ({orphaned_analyses})").rowcount or 0
        deleted += conn.execute("DELETE FROM analyses WHERE case_id NOT IN (SELECT id FROM cases)").rowcount or 0
        deleted += (
            conn.execute(
                "DELETE FROM notes WHERE case_id IS NOT NULL AND case_id NOT IN (SELECT id FROM cases)"
            ).rowcount
            or 0
        )
        deleted += conn.execute("DELETE FROM case_tags WHERE case_id NOT IN (SELECT id FROM cases)").rowcount or 0
        deleted += (
            conn.execute(
                "DELETE FROM jobs WHERE case_id IS NOT NULL AND case_id NOT IN (SELECT id FROM cases)"
            ).rowcount
            or 0
        )
        conn.commit()
        if deleted:
            logger.info("gc: reconciled %d orphaned case rows", deleted)
        return deleted
    finally:
        conn.close()
