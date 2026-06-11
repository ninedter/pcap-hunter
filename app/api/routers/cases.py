"""GET /api/v1/cases/{id}, DELETE, /report.pdf"""

from __future__ import annotations

import logging
import os
import pathlib
import tempfile

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from app.api.deps import get_repo, require_full_scope
from app.api.queue import cancel_queued_job

logger = logging.getLogger(__name__)

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

    latest = max(case.analyses, key=lambda a: a.analyzed_at) if case.analyses else None
    reports_dir = _reports_dir()
    pdf_path = reports_dir / f"{case_id}.pdf"
    cache_fresh = pdf_path.exists() and (latest is None or pdf_path.stat().st_mtime >= latest.analyzed_at.timestamp())
    if not cache_fresh:
        if latest is None:
            # No analysis to render. A pre-existing cached file (orphaned by
            # analysis deletion) still serves above via cache_fresh.
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "report_no_analysis",
                    "title": "Not Found",
                    "detail": "Case has no persisted analysis to render.",
                },
            )

        # Lazy import — keeps the weasyprint stack off the API boot path (cold path only).
        from app.reports.pdf_generator import PDFReportGenerator, ReportConfig

        generator = PDFReportGenerator(ReportConfig(title=f"PCAP Analysis Report — {case.title}"))
        if not generator.is_available:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "pdf_unavailable",
                    "title": "Service Unavailable",
                    "detail": "PDF rendering libraries (weasyprint/pango) are not installed on this host.",
                },
            )
        import pandas as pd

        beacon_records = (latest.features or {}).get("beacon_records") or []
        beacon_df = None
        if beacon_records:
            try:
                beacon_df = pd.DataFrame.from_records(beacon_records)
            except Exception as exc:
                logger.warning("Malformed beacon_records for case %s; omitting beacon table: %s", case_id, exc)
        report = generator.generate(
            report_md=latest.report or "",
            features=latest.features or {},
            osint=latest.osint or None,
            yara_results=latest.yara_results,
            dns_analysis=latest.dns_analysis,
            tls_analysis=latest.tls_analysis,
            beacon_df=beacon_df,
        )
        if report is None:
            raise HTTPException(
                status_code=500,
                detail={"code": "pdf_render_failed", "title": "Internal Server Error", "detail": "PDF render failed."},
            )
        reports_dir.mkdir(parents=True, exist_ok=True)
        # Atomic publish: write to a temp file then rename into place, so a
        # concurrent reader never sees a torn/truncated pdf.
        fd, tmp_name = tempfile.mkstemp(dir=reports_dir, suffix=".pdf.tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(report.content)
            os.replace(tmp_name, pdf_path)
        except BaseException:
            os.unlink(tmp_name)
            raise

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
