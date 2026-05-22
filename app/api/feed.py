"""IOC feed aggregation queries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.database.repository import CaseRepository


@dataclass
class IOCFilter:
    """Filters for the IOC feed."""

    since: str | None = None  # ISO 8601
    min_score: int = 0
    types: list[str] = field(default_factory=list)
    tag: str | None = None
    case_id: str | None = None
    limit: int = 1000
    offset: int = 0


def query_iocs(repo: CaseRepository, filt: IOCFilter) -> list[dict[str, Any]]:
    """Aggregate IOCs across all cases with derived fields.

    Returns rows shaped like the API IOCEntry: type, value, score, severity,
    tags, first_seen, last_seen, case_ids, mitre_techniques.
    """
    sql = """
        SELECT i.ioc_type, i.value, i.severity,
               MIN(a.analyzed_at) AS first_seen,
               MAX(a.analyzed_at) AS last_seen,
               GROUP_CONCAT(DISTINCT a.case_id) AS case_ids,
               GROUP_CONCAT(DISTINCT t.name) AS tag_names
        FROM iocs i
        JOIN analyses a ON i.analysis_id = a.id
        LEFT JOIN case_tags ct ON ct.case_id = a.case_id
        LEFT JOIN tags t ON t.id = ct.tag_id
    """
    where: list[str] = []
    params: list[Any] = []

    if filt.types:
        placeholders = ",".join("?" * len(filt.types))
        where.append(f"i.ioc_type IN ({placeholders})")
        params.extend(filt.types)
    if filt.since:
        where.append("a.analyzed_at >= ?")
        params.append(filt.since)
    if filt.case_id:
        where.append("a.case_id = ?")
        params.append(filt.case_id)
    if filt.tag:
        where.append(
            "a.case_id IN (SELECT ct2.case_id FROM case_tags ct2 JOIN tags t2 ON t2.id = ct2.tag_id WHERE t2.name = ?)"
        )
        params.append(filt.tag)

    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " GROUP BY i.ioc_type, i.value ORDER BY MAX(a.analyzed_at) DESC"
    sql += " LIMIT ? OFFSET ?"
    params.extend([filt.limit, filt.offset])

    conn = repo._get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    out: list[dict[str, Any]] = []
    for row in rows:
        d = dict(row)
        out.append(
            {
                "type": d["ioc_type"],
                "value": d["value"],
                "severity": d["severity"] or "medium",
                "score": _severity_to_score(d["severity"]),
                "tags": [t for t in (d.get("tag_names") or "").split(",") if t],
                "first_seen": d["first_seen"],
                "last_seen": d["last_seen"],
                "case_ids": [c for c in (d.get("case_ids") or "").split(",") if c],
                "mitre_techniques": [],  # Future: derive from analysis features
            }
        )
    if filt.min_score:
        out = [r for r in out if r["score"] >= filt.min_score]
    return out


_SEV_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 100}


def _severity_to_score(severity: str | None) -> int:
    return _SEV_SCORE.get((severity or "medium").lower(), 50)
