"""GET /api/v1/iocs.{json,csv,stix} — egress feed for SIEM/log analysis platforms."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from email.utils import format_datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from app.api.deps import get_repo, require_feed_scope
from app.api.feed import IOCFilter, query_iocs

router = APIRouter(prefix="/api/v1", tags=["egress"])


def _build_filter(
    since: str | None,
    min_score: int,
    types: str | None,
    tag: str | None,
    case_id: str | None,
    limit: int,
    cursor: str | None,
) -> IOCFilter:
    type_list = [t.strip() for t in (types or "").split(",") if t.strip()]
    offset = 0
    if cursor:
        try:
            offset = int(cursor)
        except ValueError:
            offset = 0
    return IOCFilter(
        since=since,
        min_score=min_score,
        types=type_list,
        tag=tag,
        case_id=case_id,
        limit=min(limit, 10000),
        offset=offset,
    )


def _etag_for(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _last_modified(rows: list[dict]) -> str | None:
    timestamps = [r["last_seen"] for r in rows if r.get("last_seen")]
    return max(timestamps) if timestamps else None


def _http_date(iso_ts: str | None) -> str | None:
    """ISO-8601 (DB format) -> RFC 7231 IMF-fixdate; None if unparseable."""
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(iso_ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Rows are written by naive-local datetime.now() — interpret as local time.
        dt = dt.astimezone()
    return format_datetime(dt.astimezone(timezone.utc), usegmt=True)


def _conditional_response(request: Request, body: bytes, media_type: str, last_modified: str | None) -> Response:
    etag = _etag_for(body)
    inm = request.headers.get("If-None-Match")
    if inm and inm.strip('"') == etag:
        return Response(status_code=304, headers={"ETag": f'"{etag}"'})
    headers = {"ETag": f'"{etag}"', "Cache-Control": "private, max-age=60"}
    http_date = _http_date(last_modified)
    if http_date:
        headers["Last-Modified"] = http_date
    return Response(content=body, media_type=media_type, headers=headers)


# ── JSON feed ───────────────────────────────────────────────────────────────


@router.get("/iocs.json")
def iocs_json(
    request: Request,
    since: str | None = Query(default=None),
    min_score: int = Query(default=0, ge=0, le=100),
    type: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    case_id: str | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10000),
    cursor: str | None = Query(default=None),
    _scope=Depends(require_feed_scope),
    repo=Depends(get_repo),
):
    filt = _build_filter(since, min_score, type, tag, case_id, limit, cursor)
    rows = query_iocs(repo, filt)
    next_cursor = str(filt.offset + len(rows)) if len(rows) == filt.limit else None
    payload = {"iocs": rows, "count": len(rows), "next_cursor": next_cursor}
    body = json.dumps(payload).encode("utf-8")
    return _conditional_response(request, body, "application/json", _last_modified(rows))


# ── CSV feed ────────────────────────────────────────────────────────────────

CSV_HEADER = [
    "type",
    "value",
    "score",
    "severity",
    "tags",
    "first_seen",
    "last_seen",
    "case_ids",
    "mitre_techniques",
]


def _csv_safe(value: str) -> str:
    """Prefix values that would be interpreted as a formula by Excel/Sheets."""
    if value and value[0] in ("=", "+", "-", "@"):
        return "'" + value
    return value


@router.get("/iocs.csv")
def iocs_csv(
    request: Request,
    since: str | None = Query(default=None),
    min_score: int = Query(default=0, ge=0, le=100),
    type: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    case_id: str | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10000),
    cursor: str | None = Query(default=None),
    _scope=Depends(require_feed_scope),
    repo=Depends(get_repo),
):
    filt = _build_filter(since, min_score, type, tag, case_id, limit, cursor)
    rows = query_iocs(repo, filt)

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_HEADER)
    for r in rows:
        writer.writerow(
            [
                _csv_safe(r["type"]),
                _csv_safe(r["value"]),
                r["score"],
                r["severity"],
                _csv_safe(";".join(r["tags"])),
                r["first_seen"] or "",
                r["last_seen"] or "",
                _csv_safe(";".join(r["case_ids"])),
                _csv_safe(";".join(r["mitre_techniques"])),
            ]
        )
    body = out.getvalue().encode("utf-8")
    return _conditional_response(request, body, "text/csv", _last_modified(rows))


# ── STIX 2.1 feed ──────────────────────────────────────────────────────────


@router.get("/iocs.stix", operation_id="iocs_stix_dot")
@router.get("/iocs/stix", operation_id="iocs_stix_path")
def iocs_stix(
    request: Request,
    since: str | None = Query(default=None),
    min_score: int = Query(default=0, ge=0, le=100),
    type: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    case_id: str | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=10000),
    cursor: str | None = Query(default=None),
    _scope=Depends(require_feed_scope),
    repo=Depends(get_repo),
):
    filt = _build_filter(since, min_score, type, tag, case_id, limit, cursor)
    rows = query_iocs(repo, filt)

    bundle = _to_stix_bundle(rows)
    body = json.dumps(bundle).encode("utf-8")
    return _conditional_response(request, body, "application/json", _last_modified(rows))


def _to_stix_bundle(rows: list[dict]) -> dict:
    """Build a minimal STIX 2.1 bundle of indicator objects."""
    objects = []
    for r in rows:
        pattern = _row_to_stix_pattern(r)
        if not pattern:
            continue
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, r['value'])}",
                "created": r["first_seen"] or "1970-01-01T00:00:00Z",
                "modified": r["last_seen"] or r["first_seen"] or "1970-01-01T00:00:00Z",
                "pattern_type": "stix",
                "pattern": pattern,
                "valid_from": r["first_seen"] or "1970-01-01T00:00:00Z",
                "labels": ["malicious-activity"],
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def _row_to_stix_pattern(r: dict) -> str | None:
    t = r["type"]
    v = r["value"].replace("'", "\\'")
    if t == "ip":
        return f"[ipv4-addr:value = '{v}']"
    if t == "domain":
        return f"[domain-name:value = '{v}']"
    if t == "url":
        return f"[url:value = '{v}']"
    if t == "hash":
        return f"[file:hashes.'SHA-256' = '{v}']"
    return None
