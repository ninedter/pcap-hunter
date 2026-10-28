"""Immutable analysis snapshots with complete, bounded, typed evidence queries."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import sqlite3
import time
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode

from fastapi import HTTPException

from app.agents.registry import AgentRegistry, canonical, digest, utcnow

_FLOW_FIELDS = ("src", "dst", "sport", "dport", "proto", "count", "bytes", "first_ts", "last_ts")
_ARTIFACT_TYPES = {"ips": "ip", "domains": "domain", "hashes": "hash", "ja3": "ja3", "urls": "url", "macs": "mac"}
_MAX_RESPONSE_BYTES = 1024 * 1024
_DETECTOR_PART_BYTES = 128 * 1024


def detector_parts(value, locator=""):
    """Keep large detector collections pageable without discarding their data.

    Locators use JSON Pointer escaping. Oversized text leaves carry ordered
    fragments so a client can reconstruct the original value.
    """
    if len(canonical(value).encode()) <= _DETECTOR_PART_BYTES:
        yield locator, value
    elif isinstance(value, dict):
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from detector_parts(child, locator + "/" + escaped)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from detector_parts(child, locator + "/" + str(index))
    elif isinstance(value, str):
        # At most 64 KiB UTF-8 per fragment, including non-ASCII text.
        width = 16384
        total = (len(value) + width - 1) // width
        for index in range(total):
            yield (
                locator,
                {"text_fragment": value[index * width : (index + 1) * width], "part": index + 1, "parts": total},
            )
    else:
        raise ValueError("unsupported oversized detector record")


def safe_data(value):
    """Remove server paths/configuration; retain evidence values as untrusted data."""
    if isinstance(value, dict):
        return {
            str(k): safe_data(v)
            for k, v in value.items()
            if str(k).lower()
            not in {"path", "pcap_path", "file_path", "zeek_log_paths", "api_key", "password", "secret"}
            and not str(k).startswith("cfg_")
        }
    if isinstance(value, (tuple, list)):
        return [safe_data(v) for v in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value if value is None or isinstance(value, (str, int, float, bool)) else str(value)


@dataclass(frozen=True)
class AnalysisRef:
    id: str
    case_id: str


def analysis_ref(repo, analysis_id):
    with repo._get_conn() as conn:
        row = conn.execute("SELECT id,case_id FROM analyses WHERE id=?", (analysis_id,)).fetchone()
    return AnalysisRef(row["id"], row["case_id"]) if row else None


class EvidenceService:
    def __init__(self, repo):
        self.repo = repo
        self.registry = AgentRegistry(repo)
        with self.registry.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS evidence_snapshots (
                    analysis_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, case_id TEXT NOT NULL,
                    manifest TEXT NOT NULL, created_at TEXT NOT NULL,
                    PRIMARY KEY(analysis_id,snapshot_id)
                );
                CREATE TABLE IF NOT EXISTS evidence_records (
                    analysis_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, kind TEXT NOT NULL,
                    position INTEGER NOT NULL, id TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
                    protocol TEXT, source TEXT, destination TEXT, record TEXT NOT NULL,
                    PRIMARY KEY(analysis_id,snapshot_id,kind,position), UNIQUE(analysis_id,snapshot_id,id)
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_filter
                    ON evidence_records(analysis_id,snapshot_id,kind,type,value);
                CREATE INDEX IF NOT EXISTS idx_evidence_flow
                    ON evidence_records(analysis_id,snapshot_id,kind,protocol,source,destination);
                CREATE TRIGGER IF NOT EXISTS snapshots_no_update BEFORE UPDATE ON evidence_snapshots
                    BEGIN SELECT RAISE(ABORT,'snapshot_is_immutable'); END;
                CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence_records
                    BEGIN SELECT RAISE(ABORT,'evidence_is_immutable'); END;
            """)
            if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='snapshots_no_delete_v2'").fetchone():
                # Permit only the trusted case-deletion transaction to purge
                # evidence, after removing its parent case. Normal snapshots
                # remain immutable, including across analysis revisions.
                conn.executescript("""
                    BEGIN IMMEDIATE;
                    DROP TRIGGER IF EXISTS snapshots_no_delete;
                    DROP TRIGGER IF EXISTS evidence_no_delete;
                    CREATE TRIGGER IF NOT EXISTS snapshots_no_delete_v2 BEFORE DELETE ON evidence_snapshots
                        WHEN EXISTS(SELECT 1 FROM cases WHERE id=OLD.case_id)
                        BEGIN SELECT RAISE(ABORT,'snapshot_is_immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS evidence_no_delete_v2 BEFORE DELETE ON evidence_records
                        WHEN EXISTS(SELECT 1 FROM evidence_snapshots s JOIN cases c ON c.id=s.case_id
                            WHERE s.analysis_id=OLD.analysis_id AND s.snapshot_id=OLD.snapshot_id)
                        BEGIN SELECT RAISE(ABORT,'evidence_is_immutable'); END;
                    COMMIT;
                """)

    def capture(self, analysis, *, provenance=None, connection=None):
        features = analysis.features or {}
        artifacts = analysis.session_artifacts or {}
        seen = set()
        evidence = []
        for ioc in analysis.iocs:
            row = {
                "type": ioc.ioc_type.value,
                "value": ioc.value,
                "context": ioc.context,
                "severity": ioc.severity.value,
            }
            evidence.append(row)
            seen.add((row["type"], row["value"]))
        for key, kind in _ARTIFACT_TYPES.items():
            for value in (features.get("artifacts") or {}).get(key) or []:
                if (kind, str(value)) not in seen:
                    evidence.append(
                        {
                            "type": kind,
                            "value": str(value),
                            "context": "Observed in saved capture",
                            "severity": "observed",
                        }
                    )
                    seen.add((kind, str(value)))
        detector_data = {
            "dns": analysis.dns_analysis,
            "tls": analysis.tls_analysis,
            "yara": analysis.yara_results,
            "beacon": artifacts.get("beacon_records") or features.get("beacon_records"),
            "attack_mapping": analysis.attack_mapping,
        }
        chunked_detectors = False
        for kind, data in detector_data.items():
            if data:
                for key, value in data.items() if isinstance(data, dict) else [("records", data)]:
                    value = safe_data(value)
                    chunked = len(canonical(value).encode()) > _DETECTOR_PART_BYTES
                    chunked_detectors |= chunked
                    for locator, part in detector_parts(value):
                        evidence.append(
                            {
                                "type": kind,
                                "value": str(key),
                                "context": {"locator": locator, "data": part} if chunked else part,
                                "severity": "observed",
                            }
                        )
        flows = [safe_data({key: flow.get(key) for key in _FLOW_FIELDS}) for flow in features.get("flows") or []]
        stages = list(artifacts.get("pipeline_stages") or [])
        warnings = list(artifacts.get("pipeline_warnings") or [])
        if chunked_detectors:
            warnings.append("detector_evidence_chunked_with_locators")
        provenance = provenance or {}
        # Legacy data has no trustworthy ingest-time tool/version receipt.
        coverage = {
            "saved_evidence": "complete",
            "packet_parse": "partial_or_unknown",
            "packet_count": analysis.packet_count,
            "flow_count": len(flows),
            "sampled_packets": any(f.get("pkt_times") for f in features.get("flows") or []),
            "pipeline_stages": stages,
            "parser_limit": provenance.get("options", {}).get("pyshark_packet_limit"),
            "provenance": "ingest_receipt" if provenance else "legacy_saved_analysis",
        }
        manifest = {
            "schema_version": "1",
            "analysis_id": analysis.id,
            "case_id": analysis.case_id,
            "input_sha256": analysis.pcap_hash or None,
            "analyzed_at": analysis.analyzed_at.isoformat(),
            "evidence_count": len(evidence),
            "flow_count": len(flows),
            "coverage": coverage,
            "warnings": warnings,
            "provenance": safe_data(provenance),
            "artifact_hashes": {key: digest(safe_data(data)) for key, data in detector_data.items() if data},
        }
        snapshot_id = digest({"manifest": manifest, "evidence": safe_data(evidence), "flows": flows})
        manifest["snapshot_id"] = snapshot_id
        with self.registry.connection(write=True) if connection is None else nullcontext(connection) as conn:
            if conn.execute(
                "SELECT 1 FROM evidence_snapshots WHERE analysis_id=? AND snapshot_id=?", (analysis.id, snapshot_id)
            ).fetchone():
                return manifest
            conn.execute(
                "INSERT INTO evidence_snapshots VALUES (?,?,?,?,?)",
                (analysis.id, snapshot_id, analysis.case_id, canonical(manifest), utcnow().isoformat()),
            )
            for kind, rows in (("evidence", evidence), ("flows", flows)):
                for position, raw in enumerate(rows):
                    row = safe_data(raw)
                    record_id = digest([analysis.id, snapshot_id, kind, position, row])[:32]
                    row |= {
                        "id": record_id,
                        "analysis_id": analysis.id,
                        "snapshot_id": snapshot_id,
                        "source_artifact_sha256": analysis.pcap_hash or None,
                        "investigate_url": "/investigate?"
                        + urlencode({"analysis_id": analysis.id, "evidence_id": record_id, "snapshot_id": snapshot_id}),
                    }
                    conn.execute(
                        "INSERT INTO evidence_records VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            analysis.id,
                            snapshot_id,
                            kind,
                            position,
                            record_id,
                            str(row.get("type", "flow")),
                            str(row.get("value", "")),
                            str(row.get("proto") or "").upper(),
                            str(row.get("src") or ""),
                            str(row.get("dst") or ""),
                            canonical(row),
                        ),
                    )
        return manifest

    def manifest(self, analysis, snapshot_id=None):
        with self.registry.connection() as conn:
            sql = "SELECT manifest FROM evidence_snapshots WHERE analysis_id=?"
            params = [analysis.id]
            if snapshot_id:
                sql += " AND snapshot_id=?"
                params.append(snapshot_id)
            row = conn.execute(sql + " ORDER BY created_at DESC,rowid DESC LIMIT 1", params).fetchone()
        if row:
            return json.loads(row[0])
        if snapshot_id is not None:
            return self._missing()
        return self.capture(self.repo.get_analysis(analysis.id))

    @staticmethod
    def _missing():
        raise HTTPException(404, "snapshot_not_found")

    def query(self, analysis, actor, *, kind="evidence", limit=100, cursor=None, snapshot_id=None, **filters):
        if kind not in {"evidence", "flows"} or not 1 <= limit <= 200:
            raise HTTPException(422, "invalid_evidence_query")
        columns = {
            "type": "type",
            "value": "value",
            "protocol": "protocol",
            "source": "source",
            "destination": "destination",
            "start": "json_extract(record, '$.first_ts')",
            "end": "json_extract(record, '$.first_ts')",
        }
        if set(filters) - set(columns):
            raise HTTPException(422, "unknown_evidence_filter")
        filters = {k: str(v) for k, v in filters.items() if v is not None and v != ""}
        if any(len(v) > 512 for v in filters.values()):
            raise HTTPException(422, "evidence_filter_too_long")
        if "protocol" in filters:
            filters["protocol"] = filters["protocol"].upper()
        for name in ("start", "end"):
            if name in filters:
                try:
                    parsed = datetime.fromisoformat(filters[name].replace("Z", "+00:00"))
                    if kind != "flows" or parsed.tzinfo is None:
                        raise ValueError
                    filters[name] = parsed.timestamp()
                except ValueError:
                    raise HTTPException(422, "UTC_or_offset_flow_time_required") from None
        if "start" in filters and "end" in filters and filters["start"] > filters["end"]:
            raise HTTPException(422, "invalid_flow_time_range")
        binding = digest([actor, analysis.id, kind, filters])
        offset = 0
        if cursor:
            try:
                if len(cursor) > 2048:
                    raise ValueError
                encoded, signature = cursor.split(".")
                expected = hmac.new(self.registry.cursor_key, encoded.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, signature):
                    raise ValueError
                data = json.loads(base64.urlsafe_b64decode(encoded))
                if data["binding"] != binding or type(data["offset"]) is not int or data["offset"] < 0:
                    raise ValueError
                if snapshot_id and snapshot_id != data["snapshot_id"]:
                    raise ValueError
                snapshot_id, offset = data["snapshot_id"], data["offset"]
            except (ValueError, KeyError, TypeError):
                raise HTTPException(422, "invalid_evidence_cursor") from None
        manifest = self.manifest(analysis, snapshot_id)
        clauses = ["analysis_id=?", "snapshot_id=?", "kind=?"]
        params = [analysis.id, manifest["snapshot_id"], kind]
        for name, value in filters.items():
            operator = ">=" if name == "start" else "<=" if name == "end" else "="
            clauses.append(columns[name] + operator + "?")
            params.append(value)
        where = " AND ".join(clauses)
        total, rows = self._page(where, params, limit, offset)
        items, size = [], 0
        for row in rows:
            size += len(row[0].encode())
            if size > _MAX_RESPONSE_BYTES:
                if not items:
                    raise HTTPException(413, "evidence_record_exceeds_response_limit")
                break
            items.append(json.loads(row[0]))
        next_cursor = None
        if offset + len(items) < total:
            encoded = base64.urlsafe_b64encode(
                canonical(
                    {"binding": binding, "snapshot_id": manifest["snapshot_id"], "offset": offset + len(items)}
                ).encode()
            ).decode()
            next_cursor = (
                encoded + "." + hmac.new(self.registry.cursor_key, encoded.encode(), hashlib.sha256).hexdigest()
            )
        return {
            "schema_version": "1",
            "analysis_id": analysis.id,
            "snapshot_id": manifest["snapshot_id"],
            "items": items,
            "returned_count": len(items),
            "total_matching": total,
            "next_cursor": next_cursor,
            "coverage": manifest["coverage"],
            "warnings": manifest["warnings"],
            "untrusted_data": True,
        }

    def _page(self, where, params, limit, offset):
        try:
            with self.registry.connection() as conn:
                deadline = time.monotonic() + 3
                conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
                total = conn.execute("SELECT count(*) FROM evidence_records WHERE " + where, params).fetchone()[0]
                rows = conn.execute(
                    "SELECT record FROM evidence_records WHERE " + where + " ORDER BY position LIMIT ? OFFSET ?",
                    params + [limit, offset],
                ).fetchall()
                return total, rows
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc):
                raise HTTPException(503, "evidence_query_time_budget_exceeded") from None
            raise

    def record(self, analysis, record_id, snapshot_id=None):
        manifest = self.manifest(analysis, snapshot_id)
        with self.registry.connection() as conn:
            row = conn.execute(
                "SELECT record FROM evidence_records WHERE analysis_id=? AND snapshot_id=? AND id=?",
                (analysis.id, manifest["snapshot_id"], record_id),
            ).fetchone()
        if not row:
            raise HTTPException(404, "evidence_not_found")
        if len(row[0].encode()) > _MAX_RESPONSE_BYTES:
            raise HTTPException(413, "evidence_record_exceeds_response_limit")
        return json.loads(row[0])
