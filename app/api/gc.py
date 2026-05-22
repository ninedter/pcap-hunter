"""Background garbage collection for retention policies."""

from __future__ import annotations

import logging
import pathlib
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
) -> dict[str, int]:
    """Run one GC pass. Returns counters for telemetry."""
    pcaps_deleted = _gc_files(uploads_dir, settings.pcap_ttl_days)
    artifacts_deleted = _gc_files(artifacts_dir, settings.artifact_ttl_days)
    jobs_deleted = _gc_old_jobs(repo, settings.job_ttl_days)
    stats = {
        "pcaps_deleted": pcaps_deleted,
        "artifacts_deleted": artifacts_deleted,
        "jobs_deleted": jobs_deleted,
    }
    logger.info("gc_sweep complete: %s", stats)
    return stats


def _gc_files(dir_path: pathlib.Path, ttl_days: int) -> int:
    if not dir_path.exists():
        return 0
    cutoff = time.time() - (ttl_days * 86400)
    count = 0
    for entry in dir_path.iterdir():
        try:
            if entry.is_file() and entry.stat().st_mtime < cutoff:
                entry.unlink()
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
