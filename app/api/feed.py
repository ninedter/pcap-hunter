"""IOC feed aggregation queries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.database.repository import CaseRepository

# SQL expression that maps the worst severity across grouped rows to a numeric score.
# MAX ensures duplicates of the same indicator always surface the highest score.
_SCORE_CASE = (
    "MAX(CASE LOWER(COALESCE(i.severity, 'medium')) "
    "WHEN 'low' THEN 25 WHEN 'medium' THEN 50 WHEN 'high' THEN 75 "
    "WHEN 'critical' THEN 100 ELSE 50 END)"
)

# Reverse mapping: score → severity label used in the response payload.
_SCORE_SEV = {25: "low", 50: "medium", 75: "high", 100: "critical"}


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

    Scoring and min_score filtering happen in SQL so that LIMIT/OFFSET-based
    pagination is correct — post-filter Python filtering previously caused the
    page window to shrink silently, dropping rows the caller never saw.

    Returns rows shaped like the API IOCEntry: type, value, score, severity,
    tags, first_seen, last_seen, case_ids, mitre_techniques.
    """
    sql = f"""
        SELECT i.ioc_type, i.value,
               {_SCORE_CASE} AS score,
               MIN(a.analyzed_at) AS first_seen,
               MAX(a.analyzed_at) AS last_seen,
               GROUP_CONCAT(DISTINCT a.case_id) AS case_ids,
               GROUP_CONCAT(DISTINCT i.analysis_id) AS analysis_ids,
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
    sql += " GROUP BY i.ioc_type, i.value"
    if filt.min_score:
        sql += f" HAVING {_SCORE_CASE} >= ?"
        params.append(filt.min_score)
    sql += " ORDER BY MAX(a.analyzed_at) DESC, i.value LIMIT ? OFFSET ?"
    params.extend([filt.limit, filt.offset])

    conn = repo._get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
        analysis_ids = {
            analysis_id for row in rows for analysis_id in (row["analysis_ids"] or "").split(",") if analysis_id
        }
        mapping_by_analysis: dict[str, dict] = {}
        if analysis_ids:
            placeholders = ",".join("?" * len(analysis_ids))
            mapping_rows = conn.execute(
                f"SELECT id, attack_mapping_json FROM analyses WHERE id IN ({placeholders})",
                tuple(analysis_ids),
            ).fetchall()
            for mapping_row in mapping_rows:
                mapping = repo._decompress_json(mapping_row["attack_mapping_json"])
                if isinstance(mapping, dict):
                    mapping_by_analysis[mapping_row["id"]] = mapping
    finally:
        conn.close()

    out: list[dict[str, Any]] = []
    for row in rows:
        d = dict(row)
        score = int(d["score"] or 50)
        techniques = sorted(
            {
                str(technique.get("technique_id"))
                for analysis_id in (d.get("analysis_ids") or "").split(",")
                for technique in (mapping_by_analysis.get(analysis_id, {}).get("techniques") or [])
                if isinstance(technique, dict) and technique.get("technique_id")
            }
        )
        out.append(
            {
                "type": d["ioc_type"],
                "value": d["value"],
                "severity": _SCORE_SEV.get(score, "medium"),
                "score": score,
                "tags": [t for t in (d.get("tag_names") or "").split(",") if t],
                "first_seen": d["first_seen"],
                "last_seen": d["last_seen"],
                "case_ids": [c for c in (d.get("case_ids") or "").split(",") if c],
                "mitre_techniques": techniques,
            }
        )
    return out
