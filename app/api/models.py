"""Pydantic models for API request/response payloads."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field


class ProblemDetail(BaseModel):
    """RFC 7807 problem details."""

    type: str = "about:blank"
    title: str
    status: int
    detail: str = ""
    instance: str = ""
    code: str = ""
    request_id: str = ""


class JobLinks(BaseModel):
    status: str
    result: str
    case: str


class PcapSubmissionResponse(BaseModel):
    job_id: str
    case_id: str
    status: str
    links: JobLinks


class JobProgress(BaseModel):
    stage: str | None = None
    stages_done: int = 0
    stages_total: int = 10
    percent: int = 0


class JobError(BaseModel):
    code: str | None = None
    detail: str | None = None


class JobStatusResponse(BaseModel):
    job_id: str
    case_id: str
    status: str
    progress: JobProgress
    submitted_at: str | None
    started_at: str | None
    finished_at: str | None
    error: JobError | None


class IOCEntry(BaseModel):
    type: str
    value: str
    score: int = 0
    severity: str = "medium"
    tags: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    case_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class IOCFeedResponse(BaseModel):
    iocs: list[IOCEntry]
    count: int
    next_cursor: str | None = None


class PcapSubmissionForm(BaseModel):
    """Multipart form fields for POST /pcaps."""

    name: str | None = None
    tags: str | None = None  # JSON-encoded array
    severity_hint: str | None = None
    osint_enabled: bool = True
    llm_enabled: bool = True
    pyshark_packet_limit: int | None = None

    def parsed_tags(self) -> list[str]:
        if not self.tags:
            return []
        try:
            value = json.loads(self.tags)
        except json.JSONDecodeError:
            return [t.strip() for t in self.tags.split(",") if t.strip()]
        if isinstance(value, list):
            return [str(t) for t in value]
        return []
