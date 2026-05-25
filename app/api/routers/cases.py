"""GET /api/v1/cases/{id}, DELETE, /report.pdf"""

from __future__ import annotations

import os
import pathlib

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from app.api.deps import get_repo, require_full_scope
from app.api.queue import cancel_queued_job

router = APIRouter(prefix="/api/v1/cases", tags=["ingress"])


def _reports_dir() -> pathlib.Path:
    return pathlib.Path(os.environ.get("PCAP_HUNTER_REPORTS_DIR", "data/reports"))


@router.get("/{case_id}")
def get_case(case_id: str, _scope=Depends(require_full_scope), repo=Depends(get_repo)):
    case = repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")
    return JSONResponse(content=case.to_dict())


@router.get("/{case_id}/report.pdf")
def get_case_report(case_id: str, _scope=Depends(require_full_scope), repo=Depends(get_repo)):
    case = repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")

    pdf_path = _reports_dir() / f"{case_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="report_not_found")
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"case_{case_id}.pdf",
    )


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: str, _scope=Depends(require_full_scope), repo=Depends(get_repo)):
    case = repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")

    # Find any associated jobs
    conn = repo._get_conn()
    try:
        rows = conn.execute("SELECT id, status FROM jobs WHERE case_id=?", (case_id,)).fetchall()
    finally:
        conn.close()

    for row in rows:
        if row[1] == "running":
            raise HTTPException(
                status_code=409,
                detail={"code": "case_has_running_job", "job_id": row[0]},
            )
        if row[1] == "queued":
            cancel_queued_job(repo, row[0])

    repo.delete_case(case_id)
    return JSONResponse(status_code=204, content=None)
