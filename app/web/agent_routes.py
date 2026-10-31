"""Local analyst controls for explicit agent grants and evidence inspection."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.agents.evidence import EvidenceService, analysis_ref
from app.agents.registry import AgentRegistry
from app.agents.routes import CreateAgent, create_agent
from app.api.deps import get_repo

router = APIRouter(prefix="/api/ui", tags=["local agent settings"])


@router.get("/agents")
def agents(repo=Depends(get_repo)):
    return {"items": AgentRegistry(repo).list()}


@router.post("/agents", status_code=201)
def new_agent(body: CreateAgent, repo=Depends(get_repo)):
    registry = AgentRegistry(repo)
    result = create_agent(body, repo)
    registry.audit("local-analyst", "create_agent", None, 201, "local-ui")
    return result


@router.delete("/agents/{actor_id}", status_code=204)
def revoke_agent(actor_id: str, repo=Depends(get_repo)):
    registry = AgentRegistry(repo)
    registry.revoke(actor_id)
    registry.audit("local-analyst", "revoke_agent", None, 204, "local-ui")


@router.get("/analyses/{analysis_id}/evidence")
def evidence(analysis_id: str, request: Request, repo=Depends(get_repo)):
    analysis = analysis_ref(repo, analysis_id)
    if not analysis:
        raise HTTPException(404, "analysis_not_found")
    params = dict(request.query_params)
    kind = params.pop("kind", "evidence")
    limit = params.pop("limit", "100")
    if not limit.isdigit():
        raise HTTPException(422, "invalid_evidence_limit")
    return EvidenceService(repo).query(analysis, "local-analyst", kind=kind, limit=int(limit), **params)


@router.get("/analyses/{analysis_id}/evidence/{evidence_id}")
def detail(analysis_id: str, evidence_id: str, snapshot_id: str = Query(max_length=64), repo=Depends(get_repo)):
    analysis = analysis_ref(repo, analysis_id)
    if not analysis:
        raise HTTPException(404, "analysis_not_found")
    return EvidenceService(repo).record(analysis, evidence_id, snapshot_id)
