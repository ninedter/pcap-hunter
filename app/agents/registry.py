"""Persisted agent grants, budgets, immutable audit records, and retries."""

from __future__ import annotations

import hashlib
import json
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

PERMISSIONS = frozenset({"cases:read", "evidence:read", "jobs:read", "captures:submit", "notes:append", "reports:read"})


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AgentRegistry:
    def __init__(self, repo):
        self.repo = repo
        with self.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agent_state (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS agent_keys (
                    id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                    permissions TEXT NOT NULL, cases TEXT NOT NULL, expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0, rpm INTEGER NOT NULL,
                    daily_requests INTEGER NOT NULL, daily_submissions INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_usage (
                    actor TEXT NOT NULL, bucket TEXT NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY(actor,bucket)
                );
                CREATE TABLE IF NOT EXISTS agent_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
                    case_id TEXT, outcome INTEGER NOT NULL, request_id TEXT NOT NULL, at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS agent_audit_no_update BEFORE UPDATE ON agent_audit
                    BEGIN SELECT RAISE(ABORT,'audit_is_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS agent_audit_no_delete BEFORE DELETE ON agent_audit
                    BEGIN SELECT RAISE(ABORT,'audit_is_append_only'); END;
                CREATE TABLE IF NOT EXISTS agent_retries (
                    actor TEXT NOT NULL, key TEXT NOT NULL, operation TEXT NOT NULL,
                    digest TEXT NOT NULL, response TEXT NOT NULL, at TEXT NOT NULL,
                    PRIMARY KEY(actor,key)
                );
                CREATE INDEX IF NOT EXISTS idx_agent_audit_actor ON agent_audit(actor,id);
            """)
            conn.execute("INSERT OR IGNORE INTO agent_state VALUES ('cursor_key',?)", (secrets.token_hex(32),))
            self.cursor_key = bytes.fromhex(
                conn.execute("SELECT value FROM agent_state WHERE name='cursor_key'").fetchone()[0]
            )

    @contextmanager
    def connection(self, write=False):
        conn = self.repo._get_conn()
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create(self, name, permissions, cases, *, days=7, rpm=60, daily_requests=2000, daily_submissions=5):
        if not permissions or not set(permissions) <= PERMISSIONS:
            raise HTTPException(422, "invalid_agent_permissions")
        cases = sorted(set(cases))
        with self.connection(write=True) as conn:
            for case_id in cases:
                if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                    raise HTTPException(422, "unknown_case_grant")
            raw = "pha_" + secrets.token_urlsafe(32)
            actor = "a_" + secrets.token_hex(12)
            expires = (utcnow() + timedelta(days=days)).isoformat()
            conn.execute(
                "INSERT INTO agent_keys VALUES (?,?,?,?,?,?,0,?,?,?,?)",
                (
                    actor,
                    hashlib.sha256(raw.encode()).hexdigest(),
                    name,
                    canonical(sorted(set(permissions))),
                    canonical(cases),
                    expires,
                    rpm,
                    daily_requests,
                    daily_submissions,
                    utcnow().isoformat(),
                ),
            )
        return {
            "id": actor,
            "key": raw,
            "name": name,
            "permissions": sorted(set(permissions)),
            "case_ids": cases,
            "expires_at": expires,
        }

    def list(self):
        with self.connection() as conn:
            return [
                {
                    k: row[k]
                    for k in ("id", "name", "expires_at", "revoked", "rpm", "daily_requests", "daily_submissions")
                }
                | {"permissions": json.loads(row["permissions"]), "case_ids": json.loads(row["cases"])}
                for row in conn.execute("SELECT * FROM agent_keys ORDER BY created_at DESC")
            ]

    def revoke(self, actor):
        with self.connection(write=True) as conn:
            if not conn.execute("UPDATE agent_keys SET revoked=1 WHERE id=?", (actor,)).rowcount:
                raise HTTPException(404, "agent_not_found")

    def authenticate(self, authorization, request):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "agent_auth_required", headers={"WWW-Authenticate": "Bearer"})
        token = authorization[7:].strip()
        if not token or len(token) > 256:
            raise HTTPException(401, "invalid_agent_key", headers={"WWW-Authenticate": "Bearer"})
        with self.connection(write=True) as conn:
            row = conn.execute(
                "SELECT * FROM agent_keys WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)
            ).fetchone()
            if row is None or row["revoked"] or datetime.fromisoformat(row["expires_at"]) <= utcnow():
                raise HTTPException(401, "invalid_agent_key", headers={"WWW-Authenticate": "Bearer"})
            request.state.agent_id = row["id"]
            now = utcnow()
            for bucket, maximum in (
                (now.strftime("minute:%Y%m%d%H%M"), row["rpm"]),
                (now.strftime("day:%Y%m%d"), row["daily_requests"]),
            ):
                used = conn.execute(
                    "SELECT count FROM agent_usage WHERE actor=? AND bucket=?", (row["id"], bucket)
                ).fetchone()
                if used and used[0] >= maximum:
                    raise HTTPException(429, "agent_request_budget_exhausted", headers={"Retry-After": "60"})
                conn.execute(
                    "INSERT INTO agent_usage VALUES (?,?,1) ON CONFLICT(actor,bucket) DO UPDATE SET count=count+1",
                    (row["id"], bucket),
                )
            return dict(row) | {"permissions": json.loads(row["permissions"]), "cases": json.loads(row["cases"])}

    @staticmethod
    def require(actor, permission, case_id=None):
        if permission not in actor["permissions"]:
            raise HTTPException(403, "agent_permission_denied")
        if case_id is not None and case_id not in actor["cases"]:
            raise HTTPException(404, "case_not_found")

    def audit(self, actor, action, case_id, outcome, request_id):
        with self.connection(write=True) as conn:
            conn.execute(
                "INSERT INTO agent_audit(actor,action,case_id,outcome,request_id,at) VALUES (?,?,?,?,?,?)",
                (actor, action[:200], case_id, outcome, request_id[:128], utcnow().isoformat()),
            )

    def retry(self, conn, actor, key, operation, fingerprint):
        row = conn.execute("SELECT * FROM agent_retries WHERE actor=? AND key=?", (actor, key)).fetchone()
        if row:
            if row["digest"] != fingerprint or row["operation"] != operation:
                raise HTTPException(409, "idempotency_key_conflict")
            return json.loads(row["response"])
        return None

    def remember(self, conn, actor, key, operation, fingerprint, response):
        conn.execute(
            "INSERT INTO agent_retries VALUES (?,?,?,?,?,?)",
            (actor, key, operation, fingerprint, canonical(response), utcnow().isoformat()),
        )
