"""GET /api/v1/jobs/{id} — job status, /result — fetch result."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.api.deps import get_repo, require_full_scope
from app.api.models import JobError, JobProgress, JobStatusResponse
from app.database.models import JobStatus

router = APIRouter(prefix="/api/v1/jobs", tags=["ingress"])


def _job_to_response(job) -> JobStatusResponse:
    pct = int(job.progress_done / max(job.progress_total, 1) * 100)
    return JobStatusResponse(
        job_id=job.id,
        case_id=job.case_id,
        status=job.status.value,
        progress=JobProgress(
            stage=job.progress_stage,
            stages_done=job.progress_done,
            stages_total=job.progress_total,
            percent=pct,
        ),
        submitted_at=job.submitted_at.isoformat() if job.submitted_at else None,
        started_at=job.started_at.isoformat() if job.started_at else None,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        error=JobError(code=job.error_code, detail=job.error_detail) if job.error_code else None,
    )


@router.get("/{job_id}", response_model=JobStatusResponse)
def get_job(job_id: str, _scope=Depends(require_full_scope), repo=Depends(get_repo)):
    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job_not_found")
    return _job_to_response(job)


@router.get("/{job_id}/result")
def get_job_result(job_id: str, _scope=Depends(require_full_scope), repo=Depends(get_repo)):
    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job_not_found")
    if job.status != JobStatus.DONE:
        raise HTTPException(
            status_code=409,
            detail={"code": "result_not_ready", "current_status": job.status.value},
        )
    if job.result_json is None:
        raise HTTPException(status_code=410, detail="result_expired")
    payload = json.loads(job.result_json)
    return Response(content=json.dumps(payload), media_type="application/json")
