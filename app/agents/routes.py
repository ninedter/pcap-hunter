"""Authorized, case-scoped agent endpoints; no administration via agent keys."""

from __future__ import annotations

import json
import re
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.agents.evidence import EvidenceService, analysis_ref, safe_data
from app.agents.registry import AgentRegistry, canonical, digest
from app.api.deps import get_repo, require_full_scope
from app.api.routers.cases import build_case_report_response
from app.database.models import Case

router = APIRouter(prefix="/api/v1", tags=["agents"])
admin_router = APIRouter(prefix="/api/v1/admin/agents", tags=["agent administration"])
Permission = Literal["cases:read", "evidence:read", "jobs:read", "captures:submit", "notes:append", "reports:read"]


class CreateAgent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    permissions: list[Permission] = Field(
        default=["cases:read", "evidence:read", "jobs:read"], min_length=1, max_length=6
    )
    case_ids: list[str] = Field(default_factory=list, max_length=100)
    expires_in_days: int = Field(default=7, ge=1, le=90)
    requests_per_minute: int = Field(default=60, ge=1, le=600)
    daily_requests: int = Field(default=2000, ge=1, le=100000)
    daily_submissions: int = Field(default=5, ge=0, le=100)


def create_agent(body, repo):
    return AgentRegistry(repo).create(
        body.name,
        body.permissions,
        body.case_ids,
        days=body.expires_in_days,
        rpm=body.requests_per_minute,
        daily_requests=body.daily_requests,
        daily_submissions=body.daily_submissions,
    )


@admin_router.post("", status_code=201, dependencies=[Depends(require_full_scope)])
def admin_create(body: CreateAgent, repo=Depends(get_repo)):
    return create_agent(body, repo)


@admin_router.get("", dependencies=[Depends(require_full_scope)])
def admin_list(repo=Depends(get_repo)):
    return {"items": AgentRegistry(repo).list()}


@admin_router.delete("/{actor_id}", status_code=204, dependencies=[Depends(require_full_scope)])
def admin_revoke(actor_id: str, repo=Depends(get_repo)):
    AgentRegistry(repo).revoke(actor_id)


@admin_router.get("/{actor_id}/audit", dependencies=[Depends(require_full_scope)])
def admin_audit(actor_id: str, limit: int = Query(default=100, ge=1, le=500), repo=Depends(get_repo)):
    registry = AgentRegistry(repo)
    with registry.connection() as conn:
        return {
            "items": [
                dict(r)
                for r in conn.execute(
                    "SELECT id,actor,action,case_id,outcome,request_id,at FROM agent_audit "
                    "WHERE actor=? ORDER BY id DESC LIMIT ?",
                    (actor_id, limit),
                )
            ]
        }


def actor(request: Request, authorization: Annotated[str | None, Header()] = None, repo=Depends(get_repo)):
    return AgentRegistry(repo).authenticate(authorization, request)


def scoped_case(request, principal, case_id, permission, repo):
    AgentRegistry.require(principal, permission, case_id)
    request.state.agent_case = case_id
    with repo._get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "case_not_found")
    return Case.from_dict(dict(row))


def scoped_analysis(request, principal, analysis_id, permission, repo):
    AgentRegistry.require(principal, permission)
    analysis = analysis_ref(repo, analysis_id)
    if analysis is None:
        raise HTTPException(404, "analysis_not_found")
    AgentRegistry.require(principal, permission, analysis.case_id)
    request.state.agent_case = analysis.case_id
    return analysis


def receipt(request, payload):
    result = safe_data(payload) | {"request_id": getattr(request.state, "request_id", ""), "untrusted_data": True}
    if len(canonical(result).encode()) > 1024 * 1024:
        raise HTTPException(413, "agent_response_limit_exceeded")
    return result


@router.get("/agent/capabilities")
def capabilities(request: Request, principal=Depends(actor)):
    return receipt(
        request,
        {
            "permissions": principal["permissions"],
            "case_ids": principal["cases"],
            "expires_at": principal["expires_at"],
            "offline_submissions_only": True,
        },
    )


@router.get("/agent/cases")
def list_cases(request: Request, principal=Depends(actor), repo=Depends(get_repo)):
    AgentRegistry.require(principal, "cases:read")
    rows = []
    with repo._get_conn() as conn:
        for case_id in principal["cases"]:
            row = conn.execute(
                "SELECT id,title,status,(SELECT count(*) FROM analyses WHERE case_id=cases.id) "
                "AS analysis_count FROM cases WHERE id=?",
                (case_id,),
            ).fetchone()
            if row:
                rows.append(dict(row))
    return receipt(request, {"items": rows, "schema_version": "1"})


@router.get("/agent/cases/{case_id}")
def summary(case_id: str, request: Request, principal=Depends(actor), repo=Depends(get_repo)):
    case = scoped_case(request, principal, case_id, "cases:read", repo)
    with repo._get_conn() as conn:
        analysis_count = conn.execute("SELECT count(*) FROM analyses WHERE case_id=?", (case_id,)).fetchone()[0]
        notes = [
            dict(row)
            for row in conn.execute(
                "SELECT id,content FROM notes WHERE case_id=? ORDER BY id DESC LIMIT 20", (case_id,)
            )
        ]
    return receipt(
        request,
        {
            "id": case.id,
            "title": case.title,
            "status": case.status.value,
            "severity": case.severity.value,
            "analysis_count": analysis_count,
            "notes": notes,
        },
    )


@router.get("/cases/{case_id}/analyses")
def analyses(case_id: str, request: Request, principal=Depends(actor), repo=Depends(get_repo)):
    scoped_case(request, principal, case_id, "cases:read", repo)
    with repo._get_conn() as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                "SELECT id AS analysis_id,analyzed_at,packet_count,pcap_hash AS input_sha256 "
                "FROM analyses WHERE case_id=? ORDER BY analyzed_at DESC",
                (case_id,),
            )
        ]
    return receipt(request, {"items": rows, "schema_version": "1"})


@router.get("/analyses/{analysis_id}/manifest")
def manifest(
    analysis_id: str, request: Request, snapshot_id: str | None = None, principal=Depends(actor), repo=Depends(get_repo)
):
    analysis = scoped_analysis(request, principal, analysis_id, "evidence:read", repo)
    return receipt(request, EvidenceService(repo).manifest(analysis, snapshot_id))


class EvidenceQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=100, ge=1, le=200)
    cursor: str | None = Field(default=None, max_length=2048)
    snapshot_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    type: str | None = Field(default=None, max_length=32)
    value: str | None = Field(default=None, max_length=512)
    source: str | None = Field(default=None, max_length=512)
    destination: str | None = Field(default=None, max_length=512)
    protocol: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,32}$")
    start: str | None = Field(default=None, max_length=40)
    end: str | None = Field(default=None, max_length=40)


def query_records(analysis_id, request, principal, repo, kind, query):
    analysis = scoped_analysis(request, principal, analysis_id, "evidence:read", repo)
    params = query.model_dump(exclude_none=True)
    if len(request.query_params) != len(request.query_params.multi_items()):
        raise HTTPException(422, "duplicate_evidence_parameter")
    limit = params.pop("limit", "100")
    if not str(limit).isdigit():
        raise HTTPException(422, "invalid_evidence_limit")
    result = EvidenceService(repo).query(analysis, principal["id"], kind=kind, limit=int(limit), **params)
    return receipt(request, result)


@router.get("/analyses/{analysis_id}/evidence")
def evidence(
    analysis_id: str,
    request: Request,
    query: Annotated[EvidenceQuery, Query()],
    principal=Depends(actor),
    repo=Depends(get_repo),
):
    return query_records(analysis_id, request, principal, repo, "evidence", query)


@router.get("/analyses/{analysis_id}/flows")
def flows(
    analysis_id: str,
    request: Request,
    query: Annotated[EvidenceQuery, Query()],
    principal=Depends(actor),
    repo=Depends(get_repo),
):
    return query_records(analysis_id, request, principal, repo, "flows", query)


@router.get("/analyses/{analysis_id}/evidence/{evidence_id}")
def detail(
    analysis_id: str,
    evidence_id: str,
    request: Request,
    snapshot_id: str | None = None,
    principal=Depends(actor),
    repo=Depends(get_repo),
):
    analysis = scoped_analysis(request, principal, analysis_id, "evidence:read", repo)
    return receipt(request, EvidenceService(repo).record(analysis, evidence_id, snapshot_id))


@router.get("/analyses/{analysis_id}/indicator")
def indicator(
    analysis_id: str,
    request: Request,
    value: str = Query(min_length=1, max_length=512),
    snapshot_id: str | None = None,
    principal=Depends(actor),
    repo=Depends(get_repo),
):
    analysis = scoped_analysis(request, principal, analysis_id, "evidence:read", repo)
    service = EvidenceService(repo)
    manifest = service.manifest(analysis, snapshot_id)
    snapshot_id = manifest["snapshot_id"]
    return receipt(
        request,
        {
            "evidence": service.query(analysis, principal["id"], value=value, snapshot_id=snapshot_id),
            "source_flows": service.query(
                analysis, principal["id"], kind="flows", source=value, snapshot_id=snapshot_id
            ),
            "destination_flows": service.query(
                analysis, principal["id"], kind="flows", destination=value, snapshot_id=snapshot_id
            ),
            "coverage": manifest["coverage"],
            "snapshot_id": snapshot_id,
        },
    )


@router.get("/agent/jobs/{job_id}")
def job_status(job_id: str, request: Request, principal=Depends(actor), repo=Depends(get_repo)):
    job = repo.get_job(job_id)
    if job is None:
        raise HTTPException(404, "job_not_found")
    AgentRegistry.require(principal, "jobs:read", job.case_id)
    request.state.agent_case = job.case_id
    analysis_id = None
    if job.status.value == "done" and job.result_json:
        try:
            result = json.loads(job.result_json)
            candidate = analysis_ref(repo, result.get("analysis_id"))
            if candidate and candidate.case_id == job.case_id:
                analysis_id = candidate.id
        except (ValueError, TypeError, AttributeError):
            pass
    return receipt(
        request,
        {
            "job_id": job.id,
            "case_id": job.case_id,
            "status": job.status.value,
            "analysis_id": analysis_id,
            "stage": job.progress_stage,
            "error_code": job.error_code,
            "progress_done": job.progress_done,
            "progress_total": job.progress_total,
        },
    )


@router.get("/agent/cases/{case_id}/report.pdf")
def report(case_id: str, request: Request, principal=Depends(actor), repo=Depends(get_repo)):
    scoped_case(request, principal, case_id, "reports:read", repo)
    return build_case_report_response(case_id, repo)


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: str = Field(min_length=1, max_length=128)
    snapshot_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    content: str = Field(min_length=1, max_length=20000)
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


def idempotency_key(request):
    key = request.headers.get("Idempotency-Key", "")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", key):
        raise HTTPException(422, "idempotency_key_required")
    return key


@router.post("/agent/cases/{case_id}/drafts", status_code=201)
def append_draft(case_id: str, body: Draft, request: Request, principal=Depends(actor), repo=Depends(get_repo)):
    scoped_case(request, principal, case_id, "notes:append", repo)
    analysis = scoped_analysis(request, principal, body.analysis_id, "notes:append", repo)
    if analysis.case_id != case_id:
        raise HTTPException(422, "draft_analysis_case_mismatch")
    service = EvidenceService(repo)
    for record_id in body.evidence_ids:
        service.record(analysis, record_id, body.snapshot_id)
    key, registry = idempotency_key(request), service.registry
    fingerprint = digest([case_id, body.model_dump()])
    with registry.connection(write=True) as conn:
        existing = registry.retry(conn, principal["id"], key, "draft", fingerprint)
        if existing:
            return receipt(request, existing)
        content = "[Agent draft — requires analyst review]\n" + body.content + "\n\nEvidence references:\n"
        content += "\n".join(f"{body.analysis_id}/{body.snapshot_id}/{record}" for record in body.evidence_ids)
        cur = conn.execute(
            "INSERT INTO notes(case_id,analysis_id,content) VALUES (?,?,?)", (case_id, body.analysis_id, content)
        )
        result = {"id": cur.lastrowid, "status": "draft", "case_id": case_id}
        registry.remember(conn, principal["id"], key, "draft", fingerprint, result)
    return receipt(request, result)


@router.post("/agent/jobs/{job_id}/cancel")
def cancel(job_id: str, request: Request, principal=Depends(actor), repo=Depends(get_repo)):
    from app.agents.spool import atomic_json, input_root

    job = repo.get_job(job_id)
    if job is None:
        raise HTTPException(404, "job_not_found")
    AgentRegistry.require(principal, "captures:submit", job.case_id)
    if json.loads(job.options_json or "{}").get("_agent_id") != principal["id"]:
        raise HTTPException(403, "only_own_agent_jobs_can_be_cancelled")
    registry = AgentRegistry(repo)
    with registry.connection(write=True) as conn:
        status = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
        if status not in {"queued", "running", "cancelled"}:
            raise HTTPException(409, "job_is_finished")
        conn.execute("UPDATE jobs SET status='cancelled' WHERE id=? AND status IN ('queued','running')", (job_id,))
    folder = input_root() / job_id
    folder.mkdir(parents=True, exist_ok=True)
    atomic_json(folder / "cancel.json", {"cancelled": True})
    return receipt(request, {"job_id": job_id, "status": "cancelled"})
