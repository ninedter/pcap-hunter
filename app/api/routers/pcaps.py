"""POST /api/v1/pcaps — submit a PCAP for analysis."""

from __future__ import annotations

import os
import pathlib
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_queue, get_repo, get_settings, require_full_scope
from app.api.models import JobLinks, PcapSubmissionForm, PcapSubmissionResponse
from app.api.queue import JobSubmission, QueueFullError
from app.api.validation import is_valid_pcap_magic
from app.database.models import Case, CaseStatus, Severity
from app.utils.network_utils import is_safe_webhook_url

router = APIRouter(prefix="/api/v1/pcaps", tags=["ingress"])

UPLOADS_DIR_DEFAULT = pathlib.Path("data/api_uploads")


def _uploads_dir() -> pathlib.Path:
    p = pathlib.Path(os.environ.get("PCAP_HUNTER_API_UPLOADS_DIR", str(UPLOADS_DIR_DEFAULT)))
    p.mkdir(parents=True, exist_ok=True)
    return p


@router.post("", status_code=202, response_model=PcapSubmissionResponse)
async def submit_pcap(
    pcap: UploadFile = File(...),
    name: str | None = Form(default=None),
    tags: str | None = Form(default=None),
    severity_hint: str | None = Form(default=None),
    osint_enabled: bool = Form(default=True),
    llm_enabled: bool = Form(default=True),
    pyshark_packet_limit: int | None = Form(default=None),
    webhook_url: str | None = Form(default=None),
    _scope=Depends(require_full_scope),
    repo=Depends(get_repo),
    queue=Depends(get_queue),
    settings=Depends(get_settings),
) -> PcapSubmissionResponse:
    # Fail fast, before any upload I/O: reject unsafe webhook targets up front.
    # is_safe_webhook_url resolves DNS (socket.getaddrinfo, blocking), so run
    # it off the event loop to avoid stalling other in-flight requests.
    if webhook_url and not await run_in_threadpool(is_safe_webhook_url, webhook_url):
        raise HTTPException(status_code=422, detail="invalid_webhook_url")

    case_id = uuid.uuid4().hex[:8]
    out_path = _uploads_dir() / f"{case_id}.pcap"

    # Stream to disk; check size + magic afterwards
    bytes_written = 0
    head = b""
    with out_path.open("wb") as f:
        while True:
            chunk = await pcap.read(1024 * 1024)
            if not chunk:
                break
            if not head:
                head = chunk[:8]
            bytes_written += len(chunk)
            if bytes_written > settings.max_pcap_bytes:
                f.close()
                out_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="pcap_too_large")
            f.write(chunk)

    if not is_valid_pcap_magic(head):
        out_path.unlink(missing_ok=True)
        raise HTTPException(status_code=415, detail="pcap_invalid_format")

    # Create case
    form = PcapSubmissionForm(
        name=name,
        tags=tags,
        severity_hint=severity_hint,
        osint_enabled=osint_enabled,
        llm_enabled=llm_enabled,
        pyshark_packet_limit=pyshark_packet_limit,
    )
    case = Case(
        id=case_id,
        title=form.name or pcap.filename or f"api-{case_id}",
        status=CaseStatus.IN_PROGRESS,
        severity=Severity.from_str(form.severity_hint or "medium"),
        tags=form.parsed_tags(),
    )
    repo.create_case(case)

    # Mark source as 'api'
    conn = repo._get_conn()
    try:
        conn.execute("UPDATE cases SET source='api' WHERE id=?", (case_id,))
        conn.commit()
    finally:
        conn.close()

    # Enqueue
    options = {
        "osint_enabled": osint_enabled,
        "llm_enabled": llm_enabled,
        "do_yara": True,
        "do_carve": True,
        "do_pyshark": True,
        "do_zeek": True,
        "pre_count": True,
        "pyshark_packet_limit": pyshark_packet_limit,
        "webhook_url": webhook_url,
    }
    try:
        job_id = queue.enqueue(
            JobSubmission(
                case_id=case_id,
                pcap_path=str(out_path),
                options=options,
            )
        )
    except QueueFullError:
        raise HTTPException(status_code=503, detail="queue_full", headers={"Retry-After": "60"})

    return PcapSubmissionResponse(
        job_id=job_id,
        case_id=case_id,
        status="queued",
        links=JobLinks(
            status=f"/api/v1/jobs/{job_id}",
            result=f"/api/v1/jobs/{job_id}/result",
            case=f"/api/v1/cases/{case_id}",
        ),
    )
