"""Job queue interface and in-process implementation."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from app.database.models import Job, JobStatus
from app.database.repository import CaseRepository

logger = logging.getLogger(__name__)

# Wire-format warning code added by the worker when analysis persistence fails.
WARNING_PERSISTENCE_FAILED = "analysis_persistence_failed"


@dataclass
class JobSubmission:
    """Inputs needed to enqueue a pipeline run."""

    case_id: str
    pcap_path: str
    options: dict[str, Any] = field(default_factory=dict)


class JobQueue(ABC):
    """Abstract job queue. Concrete impls: InProcessJobQueue (v1)."""

    @abstractmethod
    def enqueue(self, submission: JobSubmission) -> str:
        """Enqueue a job. Returns the generated job_id."""

    @abstractmethod
    def shutdown(self, wait: bool = True) -> None:
        """Cleanly stop accepting new jobs and optionally wait for in-flight to finish."""


class QueueFullError(Exception):
    """Raised when the queue's depth cap is exceeded."""


def _sha256_file(path: str) -> str:
    """Streaming SHA-256 of a file (used for Analysis.pcap_hash)."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _worker_run(job_id: str, db_path: str, pcap_path: str, options_dict: dict) -> None:
    """Top-level worker function (must be picklable for ProcessPoolExecutor)."""
    from app.database.models import JobStatus as JS
    from app.database.repository import CaseRepository as Repo
    from app.pipeline.progress import CallbackProgress, ProgressEvent
    from app.pipeline.runner import PipelineOptions, run_pipeline

    repo = Repo(db_path=db_path)
    repo.update_job_status(job_id, JS.RUNNING)

    def _on_event(event: ProgressEvent) -> None:
        if event.kind == "phase_start":
            j = repo.get_job(job_id)
            if j:
                repo.update_job_progress(job_id, event.title, j.progress_done, j.progress_total)
        elif event.kind == "phase_done":
            j = repo.get_job(job_id)
            if j:
                repo.update_job_progress(job_id, event.title, j.progress_done + 1, j.progress_total)

    progress = CallbackProgress(callback=_on_event, total_phases=10)
    options = PipelineOptions(**{k: v for k, v in options_dict.items() if k in PipelineOptions.__dataclass_fields__})

    try:
        job = repo.get_job(job_id)
        result = run_pipeline(
            pcap_path=pcap_path,
            case_id=job.case_id if job else "",
            options=options,
            progress=progress,
            heartbeat=lambda: repo.touch_job_heartbeat(job_id),
        )

        # Persist the analysis so the case completes and IOCs reach the feed
        # (mirrors app/ui/cases_tab.py:_quick_save_analysis). Persistence
        # failures must not lose the pipeline result -> warn, keep analysis_id None.
        from app.database.models import Analysis

        try:
            analysis = Analysis(
                case_id=job.case_id if job else "",
                pcap_path=pcap_path,
                pcap_hash=_sha256_file(pcap_path),
                packet_count=result.packet_count,
                features=result.features,
                dns_analysis=result.dns_analysis or None,
                tls_analysis=result.tls_analysis or None,
            )
            if result.beacon_df_records:
                analysis.features["beacon_records"] = result.beacon_df_records
            analysis.iocs = repo.extract_iocs(analysis)
            result.analysis_id = repo.save_analysis(analysis)
        except Exception:
            logger.exception("Job %s: analysis persistence failed", job_id)
            result.warnings.append(WARNING_PERSISTENCE_FAILED)

        result_blob = json.dumps(result.to_dict()).encode("utf-8")
        repo.update_job_status(job_id, JS.DONE, result_json=result_blob)
    except Exception as exc:
        logger.exception("Job %s failed: %s", job_id, exc)
        repo.update_job_status(
            job_id,
            JS.FAILED,
            error_code="pipeline_error",
            error_detail=str(exc)[:500],
        )


class InProcessJobQueue(JobQueue):
    """ProcessPoolExecutor-backed queue using SQLite for state."""

    def __init__(self, repo: CaseRepository, max_workers: int = 2, queue_depth: int = 100) -> None:
        self._repo = repo
        self._queue_depth = queue_depth
        self._executor = ProcessPoolExecutor(max_workers=max_workers)

    def enqueue(self, submission: JobSubmission) -> str:
        active = self._repo.count_active_jobs()
        if active >= self._queue_depth:
            raise QueueFullError(f"queue full ({active}/{self._queue_depth})")

        job = Job(
            case_id=submission.case_id,
            pcap_path=submission.pcap_path,
            options_json=json.dumps(submission.options),
        )
        job_id = self._repo.create_job(job)

        self._executor.submit(
            _worker_run,
            job_id,
            str(self._repo._db_path),
            submission.pcap_path,
            submission.options,
        )
        return job_id

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


def recover_stale_running_jobs(repo: CaseRepository, stale_after_seconds: int = 120) -> int:
    """Mark any RUNNING jobs with stale heartbeats as FAILED. Call at API startup."""
    stale = repo.find_stale_running_jobs(stale_after_seconds=stale_after_seconds)
    for job in stale:
        repo.update_job_status(
            job.id,
            JobStatus.FAILED,
            error_code="interrupted_restart",
            error_detail="API restarted with this job in flight; resubmit the PCAP to retry.",
        )
        logger.warning("Recovered stale running job %s -> failed", job.id)
    return len(stale)


def cancel_queued_job(repo: CaseRepository, job_id: str) -> bool:
    """Cancel a job that is still in QUEUED state. Returns True if cancelled."""
    job = repo.get_job(job_id)
    if not job or job.status != JobStatus.QUEUED:
        return False
    repo.update_job_status(job_id, JobStatus.CANCELLED)
    return True
