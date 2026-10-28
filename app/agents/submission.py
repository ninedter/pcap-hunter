"""Idempotent offline capture submission under persisted agent quotas."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid

from fastapi import Depends, File, HTTPException, Request, UploadFile

from app.agents.registry import AgentRegistry, canonical, digest, utcnow
from app.agents.routes import actor, idempotency_key, receipt, router
from app.api.deps import get_queue, get_repo, get_settings
from app.api.routers.pcaps import _uploads_dir
from app.api.validation import is_valid_pcap_magic

_upload_slot = asyncio.Semaphore(1)


@router.post("/agent/captures", status_code=202)
async def submit(request: Request, pcap: UploadFile = File(...), principal=Depends(actor), repo=Depends(get_repo)):
    AgentRegistry.require(principal, "captures:submit")
    if set(request.query_params):
        raise HTTPException(422, "agent_submissions_are_offline")
    key = idempotency_key(request)
    form = await request.form()
    if set(form) != {"pcap"} or len(form.getlist("pcap")) != 1:
        raise HTTPException(422, "agent_submissions_accept_capture_only")
    filename = _uploads_dir() / ("agent_" + uuid.uuid4().hex + ".pcap")
    maximum = min(get_settings().max_pcap_bytes, 100 * 1024 * 1024)
    hasher, head, size = hashlib.sha256(), b"", 0
    retained = False
    await _upload_slot.acquire()
    try:
        with filename.open("xb") as output:
            while chunk := await pcap.read(1024 * 1024):
                if not head:
                    head = chunk[:8]
                size += len(chunk)
                if size > maximum:
                    raise HTTPException(413, "pcap_too_large")
                hasher.update(chunk)
                output.write(chunk)
        if not is_valid_pcap_magic(head):
            raise HTTPException(415, "pcap_invalid_format")
        registry = AgentRegistry(repo)
        fingerprint = digest([hasher.hexdigest(), size])
        now = utcnow().isoformat()
        options = {
            "osint_enabled": False,
            "llm_enabled": False,
            "do_yara": True,
            "do_carve": True,
            "do_pyshark": True,
            "do_zeek": True,
            "pre_count": True,
            "pyshark_packet_limit": 200000,
            "_agent_id": principal["id"],
            "_max_wall_seconds": 600,
        }
        with registry.connection(write=True) as conn:
            result = registry.retry(conn, principal["id"], key, "capture", fingerprint)
            if result is None:
                used = conn.execute(
                    "SELECT count(*) FROM agent_retries WHERE actor=? AND operation='capture' AND at>=?",
                    (principal["id"], utcnow().strftime("%Y-%m-%d")),
                ).fetchone()[0]
                if used >= principal["daily_submissions"]:
                    raise HTTPException(429, "agent_submission_budget_exhausted")
                active = conn.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]
                if active >= get_settings().queue_depth:
                    raise HTTPException(503, "queue_full", headers={"Retry-After": "60"})
                case_id, job_id = uuid.uuid4().hex[:12], "j_" + uuid.uuid4().hex[:16]
                conn.execute(
                    "INSERT INTO cases(id,title,status,severity,source) VALUES (?,?,'in_progress','medium','agent')",
                    (case_id, "Agent capture " + case_id),
                )
                conn.execute(
                    "INSERT INTO jobs(id,case_id,pcap_path,options_json,status,submitted_at) "
                    "VALUES (?,?,?,?,'queued',?)",
                    (job_id, case_id, str(filename), canonical(options), now),
                )
                current = conn.execute(
                    "SELECT cases,revoked,expires_at FROM agent_keys WHERE id=?", (principal["id"],)
                ).fetchone()
                if current["revoked"] or current["expires_at"] <= utcnow().isoformat():
                    raise HTTPException(401, "invalid_agent_key")
                grants = sorted(set(json.loads(current["cases"])) | {case_id})
                conn.execute("UPDATE agent_keys SET cases=? WHERE id=?", (canonical(grants), principal["id"]))
                result = {
                    "case_id": case_id,
                    "job_id": job_id,
                    "status": "queued",
                    "offline": True,
                    "input_sha256": hasher.hexdigest(),
                    "input_bytes": size,
                }
                registry.remember(conn, principal["id"], key, "capture", fingerprint, result)
                retained = True
        # The persisted job is the receipt. A retry can dispatch a queued job
        # after an interruption; the worker's atomic start prevents double runs.
        job = repo.get_job(result["job_id"])
        if job and job.status.value == "queued":
            get_queue().dispatch(job.id)
        return receipt(request, result)
    finally:
        _upload_slot.release()
        if not retained:
            filename.unlink(missing_ok=True)
        await pcap.close()
