"""Durable Streamlit analysis jobs.

Long-running PCAP work must not execute inside Streamlit's script thread: the
browser's Stop control intentionally terminates that thread.  This module sends
the work to the existing process-backed queue, monitors SQLite state, and
restores persisted results into the UI when every job finishes.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import uuid
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

import streamlit as st

from app.api.queue import InProcessJobQueue, JobSubmission
from app.database.models import Case, CaseStatus, Job, JobStatus, Severity
from app.database.repository import CaseRepository
from app.ui.cases_tab import restore_analyses_to_session

logger = logging.getLogger(__name__)

BACKGROUND_RUN_KEY = "background_analysis_run"
BACKGROUND_ORIGIN = "streamlit"


@lru_cache(maxsize=1)
def get_background_repo() -> CaseRepository:
    """Return the process-wide repository used by Streamlit job monitoring."""
    return CaseRepository()


@lru_cache(maxsize=1)
def get_background_queue() -> InProcessJobQueue:
    """Create one worker pool for the Streamlit server, not one per rerun/session."""
    try:
        workers = max(1, int(os.getenv("PCAP_HUNTER_UI_WORKERS", "2")))
        depth = max(1, int(os.getenv("PCAP_HUNTER_UI_QUEUE_DEPTH", "100")))
    except ValueError:
        workers, depth = 2, 100
    return InProcessJobQueue(get_background_repo(), max_workers=workers, queue_depth=depth)


def _is_streamlit_job(job: Job) -> bool:
    return _job_options(job).get("_origin") == BACKGROUND_ORIGIN


def _job_options(job: Job) -> dict[str, Any]:
    try:
        options = json.loads(job.options_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return options if isinstance(options, dict) else {}


def submit_background_analysis(pcap_paths: list[str], options: dict[str, Any]) -> dict[str, Any]:
    """Create an autosaved case and enqueue one durable job per PCAP."""
    paths = [str(pathlib.Path(path)) for path in pcap_paths if path]
    if not paths:
        raise ValueError("At least one PCAP path is required.")

    repo = get_background_repo()
    queue = get_background_queue()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    if len(paths) == 1:
        title = f"{pathlib.Path(paths[0]).name} — {timestamp}"
    else:
        title = f"Batch analysis ({len(paths)} PCAPs) — {timestamp}"
    case = Case(
        title=title,
        description=(
            "Automatically saved background analysis. The job continues if the Streamlit page is stopped or reloaded."
        ),
        status=CaseStatus.IN_PROGRESS,
        severity=Severity.MEDIUM,
        tags=["autosaved", "background"],
    )
    case_id = repo.create_case(case)

    job_ids: list[str] = []
    durable_options = dict(options)
    run_id = uuid.uuid4().hex
    durable_options.update({"_origin": BACKGROUND_ORIGIN, "_run_id": run_id, "_batch_size": len(paths)})
    try:
        for index, path in enumerate(paths):
            per_file_options = dict(durable_options)
            per_file_options["_batch_index"] = index
            job_ids.append(queue.enqueue(JobSubmission(case_id=case_id, pcap_path=path, options=per_file_options)))
    except Exception:
        logger.exception("Could not enqueue the complete Streamlit background run")
        if not job_ids:
            repo.delete_case(case_id)
        raise

    return {
        "case_id": case_id,
        "job_ids": job_ids,
        "pcap_paths": paths,
        "loaded": False,
        "submitted_at": datetime.now().isoformat(),
        "run_id": run_id,
    }


def submit_background_report(analysis_ids: list[str]) -> dict[str, Any]:
    """Queue report-only regeneration for one or more persisted analyses."""
    repo = get_background_repo()
    queue = get_background_queue()
    analyses = [repo.get_analysis(analysis_id) for analysis_id in analysis_ids]
    if not analyses or any(analysis is None for analysis in analyses):
        raise ValueError("The saved analysis needed for report regeneration could not be found.")
    analyses = [analysis for analysis in analyses if analysis is not None]
    case_id = analyses[0].case_id
    if any(analysis.case_id != case_id for analysis in analyses):
        raise ValueError("A report batch must belong to one case.")

    run_id = uuid.uuid4().hex
    job_ids = []
    for index, analysis in enumerate(analyses):
        options = {
            "_origin": BACKGROUND_ORIGIN,
            "_run_id": run_id,
            "_job_type": "llm_report",
            "_analysis_id": analysis.id,
            "_batch_size": len(analyses),
            "_batch_index": index,
            "llm_enabled": True,
        }
        job_ids.append(
            queue.enqueue(JobSubmission(case_id=case_id, pcap_path=analysis.pcap_path or analysis.id, options=options))
        )
    case = repo.get_case(case_id)
    if case is not None:
        case.status = CaseStatus.IN_PROGRESS
        repo.update_case(case)
    return {
        "case_id": case_id,
        "job_ids": job_ids,
        "pcap_paths": [analysis.pcap_path for analysis in analyses],
        "loaded": False,
        "submitted_at": datetime.now().isoformat(),
        "run_id": run_id,
        "report_only": True,
    }


def find_recoverable_background_run(max_age_days: int = 7) -> dict[str, Any] | None:
    """Find the latest UI-owned run after a browser reload resets Session State."""
    repo = get_background_repo()
    jobs = [job for job in repo.list_jobs(limit=500) if _is_streamlit_job(job)]
    if not jobs:
        return None

    cutoff = datetime.now() - timedelta(days=max_age_days)
    recent = [job for job in jobs if (job.submitted_at or datetime.min) >= cutoff]
    if not recent:
        return None

    active = [job for job in recent if job.status in (JobStatus.QUEUED, JobStatus.RUNNING)]
    anchor = max(active or recent, key=lambda job: job.submitted_at or datetime.min)
    anchor_options = _job_options(anchor)
    run_id = anchor_options.get("_run_id")
    case_jobs = sorted(
        [
            job
            for job in recent
            if job.case_id == anchor.case_id and (not run_id or _job_options(job).get("_run_id") == run_id)
        ],
        key=lambda job: job.submitted_at or datetime.min,
    )
    return {
        "case_id": anchor.case_id,
        "job_ids": [job.id for job in case_jobs],
        "pcap_paths": [job.pcap_path for job in case_jobs],
        "loaded": False,
        "submitted_at": (anchor.submitted_at or datetime.now()).isoformat(),
        "recovered": True,
        "run_id": run_id,
        "report_only": anchor_options.get("_job_type") == "llm_report",
    }


def _load_completed_analyses(repo: CaseRepository, jobs: list[Job]):
    analyses = []
    for job in jobs:
        try:
            result = json.loads(job.result_json or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Job {job.id} completed without a readable result.") from exc
        analysis_id = result.get("analysis_id")
        if not analysis_id:
            raise RuntimeError(f"Job {job.id} completed but its analysis was not persisted.")
        analysis = repo.get_analysis(analysis_id)
        if analysis is None:
            raise RuntimeError(f"Persisted analysis {analysis_id} could not be found.")
        analyses.append(analysis)
    return analyses


def render_background_progress(run: dict[str, Any]) -> bool:
    """Render current job state and restore results; return True after first restore."""
    repo = get_background_repo()
    jobs = [repo.get_job(job_id) for job_id in run.get("job_ids", [])]
    if not jobs or any(job is None for job in jobs):
        st.error("The saved background job record could not be found. Check Cases for any completed evidence.")
        return False
    jobs = [job for job in jobs if job is not None]

    total_units = sum(max(job.progress_total, 1) for job in jobs)
    completed_units = sum(min(job.progress_done, max(job.progress_total, 1)) for job in jobs)
    percent = int(completed_units / total_units * 100) if total_units else 0
    st.progress(min(percent, 100), text=f"Background analysis: {percent}%")
    st.caption(
        "This analysis runs outside the Streamlit page. The upper-right Stop control only pauses this display; "
        "job progress remains in the case database and the final evidence is autosaved when processing completes."
    )

    for index, job in enumerate(jobs, start=1):
        filename = pathlib.Path(job.pcap_path).name
        stage = job.progress_stage or job.status.value.replace("_", " ").title()
        st.write(f"**{index}/{len(jobs)} — {filename}:** {stage} ({job.status.value})")

    failed = [job for job in jobs if job.status in (JobStatus.FAILED, JobStatus.CANCELLED)]
    if failed:
        for job in failed:
            detail = job.error_detail or job.error_code or job.status.value
            st.error(f"{pathlib.Path(job.pcap_path).name}: {detail}")
        st.info("Any analyses that completed before the failure remain available in Cases.")
        return False

    if not all(job.status == JobStatus.DONE for job in jobs):
        running = sum(job.status == JobStatus.RUNNING for job in jobs)
        queued = sum(job.status == JobStatus.QUEUED for job in jobs)
        st.info(f"Analysis is continuing safely in the background ({running} running, {queued} queued).")
        return False

    if run.get("loaded"):
        st.success("Analysis complete and restored. Review Dashboard, MITRE Analysis, LLM Analysis, and Raw Data.")
        return False

    try:
        analyses = _load_completed_analyses(repo, jobs)
        restore_analyses_to_session(analyses)
    except Exception as exc:
        logger.exception("Could not restore completed background analysis")
        st.error(f"The job completed, but the workbench could not restore its results: {exc}")
        st.info("The persisted evidence is still available in Cases.")
        return False

    case = repo.get_case(run["case_id"])
    if case is not None and case.status == CaseStatus.IN_PROGRESS:
        case.status = CaseStatus.OPEN
        repo.update_case(case)
    run["loaded"] = True
    st.session_state[BACKGROUND_RUN_KEY] = run
    st.success("Analysis complete. Results were autosaved and restored into the workbench.")
    return True
