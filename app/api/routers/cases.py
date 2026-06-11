"""GET /api/v1/cases/{id}, DELETE, /report.pdf"""

from __future__ import annotations

import glob
import logging
import os
import pathlib
import re
import shutil
import tempfile

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response

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
            if not cancel_queued_job(repo, row[0]):
                # Lost the race: the job started between our SELECT and the CAS.
                raise HTTPException(
                    status_code=409,
                    detail={"code": "case_has_running_job", "job_id": row[0]},
                )

    if not repo.delete_case(case_id):
        raise HTTPException(
            status_code=500,
            detail={
                "code": "case_delete_failed",
                "title": "Internal Server Error",
                "detail": "Case deletion failed; no files were removed.",
            },
        )

    # Best-effort artifact cleanup: uploaded pcap, cached pdf, per-run output
    # dirs. The DB delete above is the source of truth — file errors must
    # never turn the 204 into a failure.
    try:
        uploads_dir = pathlib.Path(os.environ.get("PCAP_HUNTER_API_UPLOADS_DIR", "data/api_uploads"))
        (uploads_dir / f"{case_id}.pcap").unlink(missing_ok=True)
        (_reports_dir() / f"{case_id}.pdf").unlink(missing_ok=True)

        # Config constants resolved at call time (module-level import would work too).
        from app import config as C

        # Sanitization deliberately diverges from app.pipeline.runner._derive_run_id:
        # the router SKIPs empty sanitized ids rather than falling back to "run",
        # because globbing "run_*" would delete other cases' dirs.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", case_id)[:40].lstrip(".")
        if safe:
            for base in (C.ZEEK_DIR, C.CARVE_DIR):
                for d in glob.glob(str(base / f"{safe}_*")):
                    shutil.rmtree(d, ignore_errors=True)
    except Exception as exc:
        logger.warning("Artifact cleanup after deleting case %s failed: %s", case_id, exc)

    return Response(status_code=204)
