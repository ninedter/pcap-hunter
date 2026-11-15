"""Per-request overhead, audit failure semantics and cancellation bookkeeping over HTTP."""

import asyncio
import logging
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.agents import middleware
from app.agents.evidence import EvidenceService
from app.agents.registry import AgentRegistry
from app.database.models import Analysis, Case
from app.database.repository import CaseRepository

READ = ["cases:read", "evidence:read", "jobs:read"]
PCAP = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")


class TracingRepository(CaseRepository):
    """Real repository that records every SQL statement its connections execute."""

    statements: list[str] = []

    def _get_conn(self):
        conn = super()._get_conn()
        conn.set_trace_callback(self.statements.append)
        return conn


def schema_statements(statements):
    return [sql for sql in statements if sql.lstrip().upper().startswith(("CREATE", "DROP", "INSERT OR IGNORE"))]


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "cases.db"))
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "test-admin")
    monkeypatch.setenv("PCAP_HUNTER_AGENT_SPOOL", str(tmp_path / "spool"))
    monkeypatch.setenv("PCAP_HUNTER_API_UPLOADS_DIR", str(tmp_path / "uploads"))
    from app.api import deps
    from app.api.deps import get_key_repo, get_queue, get_repo, get_settings

    for getter in (get_repo, get_queue, get_settings, get_key_repo):
        getter.cache_clear()
    monkeypatch.setattr(deps, "CaseRepository", TracingRepository)
    repo = get_repo()
    assert isinstance(repo, TracingRepository)
    repo.create_case(Case(id="case-a", title="Case A"))
    repo.save_analysis(Analysis(id="analysis-a", case_id="case-a", pcap_path="/private/capture.pcap"))
    registry = AgentRegistry(repo)
    from app.api.app import create_app

    with TestClient(create_app()) as client:
        yield client, repo, registry, tmp_path
    for getter in (get_repo, get_queue, get_settings, get_key_repo):
        if getter is get_queue and getter.cache_info().currsize:
            getter().shutdown()
        getter.cache_clear()


def headers(credential):
    return {"Authorization": "Bearer " + credential["key"]}


def test_requests_do_not_replay_schema_setup(environment):
    client, repo, registry, _ = environment
    key = registry.create("Reader", READ, ["case-a"], rpm=600)
    assert client.get("/api/v1/analyses/analysis-a/manifest", headers=headers(key)).status_code == 200
    TracingRepository.statements.clear()
    for _ in range(3):
        response = client.get("/api/v1/analyses/analysis-a/evidence", headers=headers(key))
        assert response.status_code == 200
    statements = list(TracingRepository.statements)
    assert schema_statements(statements) == []
    # The audit trail is still written once per request.
    assert sum("INSERT INTO agent_audit" in sql for sql in statements) == 3
    with registry.connection() as conn:
        assert conn.execute("SELECT count(*) FROM agent_audit WHERE actor=?", (key["id"],)).fetchone()[0] == 4


def test_schema_setup_runs_once_per_database_file_and_is_thread_safe(tmp_path):
    first = TracingRepository(str(tmp_path / "one.db"))
    TracingRepository.statements.clear()
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = set(pool.map(lambda _: AgentRegistry(first).cursor_key, range(32)))
        services = list(pool.map(lambda _: EvidenceService(first), range(32)))
    assert len(keys) == 1 and len(services) == 32
    creates = [sql for sql in TracingRepository.statements if "CREATE TABLE IF NOT EXISTS agent_keys" in sql]
    assert len(creates) == 1
    TracingRepository.statements.clear()
    AgentRegistry(first), EvidenceService(first)
    assert schema_statements(TracingRepository.statements) == []
    # A different database is still initialised, with its own signing key ...
    second = CaseRepository(str(tmp_path / "two.db"))
    assert AgentRegistry(second).cursor_key != AgentRegistry(first).cursor_key
    # ... and so is a database recreated at a path this process has already seen.
    for suffix in ("", "-wal", "-shm"):
        (tmp_path / ("one.db" + suffix)).unlink(missing_ok=True)
    recreated = CaseRepository(str(tmp_path / "one.db"))
    registry = AgentRegistry(recreated)
    EvidenceService(recreated)
    with registry.connection() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
    assert {"agent_keys", "agent_audit", "evidence_snapshots", "agent_cancelled_job_no_analysis"} <= tables


def test_audit_runs_off_the_event_loop(environment, monkeypatch):
    client, _, registry, _ = environment
    key = registry.create("Reader", READ, ["case-a"], rpm=600)
    seen = []
    original = middleware.write_audit

    def observed(*args):
        try:
            asyncio.get_running_loop()
            seen.append("event-loop")
        except RuntimeError:
            seen.append(threading.current_thread().name)
        return original(*args)

    monkeypatch.setattr(middleware, "write_audit", observed)
    assert client.get("/api/v1/agent/cases", headers=headers(key)).status_code == 200
    assert len(seen) == 1 and seen[0] != "event-loop"


def test_audit_failure_fails_closed_with_an_explicit_logged_error(environment, monkeypatch, caplog):
    client, _, registry, _ = environment
    key = registry.create("Reader", READ, ["case-a"], rpm=600)

    def locked(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(middleware, "write_audit", locked)
    with caplog.at_level(logging.ERROR, logger="app.agents.middleware"):
        response = client.get("/api/v1/analyses/analysis-a/evidence", headers=headers(key))
    assert response.status_code == 503
    assert response.json() == {"detail": "agent_audit_unavailable"}
    assert response.headers["cache-control"] == "no-store" and response.headers["retry-after"] == "5"
    assert "snapshot_id" not in response.text  # the evidence response was withheld
    assert any("Agent audit write failed" in record.getMessage() for record in caplog.records)
    assert key["key"] not in caplog.text
    # Requests that are not agent operations are untouched by the audit path.
    assert client.get("/api/v1/agent/cases").status_code == 401
    monkeypatch.undo()
    assert client.get("/api/v1/analyses/analysis-a/evidence", headers=headers(key)).status_code == 200


def test_audit_failure_on_a_write_is_recoverable_by_an_idempotent_retry(environment, monkeypatch):
    client, repo, registry, _ = environment
    key = registry.create("Submitter", READ + ["captures:submit"], [], rpm=600)
    auth = headers(key) | {"Idempotency-Key": "capture-audit-0001"}
    with monkeypatch.context() as patched:
        patched.setattr(middleware, "write_audit", lambda *args: (_ for _ in ()).throw(sqlite3.OperationalError("x")))
        refused = client.post("/api/v1/agent/captures", headers=auth, files={"pcap": ("test.pcap", PCAP)})
    assert refused.status_code == 503 and refused.json() == {"detail": "agent_audit_unavailable"}
    retried = client.post("/api/v1/agent/captures", headers=auth, files={"pcap": ("test.pcap", PCAP)})
    assert retried.status_code == 202
    with repo._get_conn() as conn:
        assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1  # one job, now audited
        audited = conn.execute(
            "SELECT count(*) FROM agent_audit WHERE actor=? AND action='POST /api/v1/agent/captures' AND outcome=202",
            (key["id"],),
        ).fetchone()[0]
    assert audited == 1


def test_cancel_records_a_finish_time_and_does_not_recreate_removed_input(environment):
    client, repo, registry, tmp_path = environment
    key = registry.create("Submitter", READ + ["captures:submit"], [], rpm=600)
    result = client.post(
        "/api/v1/agent/captures",
        headers=headers(key) | {"Idempotency-Key": "capture-cancel-0002"},
        files={"pcap": ("test.pcap", PCAP)},
    ).json()
    path = "/api/v1/agent/jobs/" + result["job_id"] + "/cancel"
    assert client.post(path, headers=headers(key)).json()["status"] == "cancelled"
    job = repo.get_job(result["job_id"])
    assert job.status.value == "cancelled" and job.finished_at is not None
    folder = tmp_path / "spool" / "inbox" / result["job_id"]
    assert (folder / "cancel.json").exists()
    # Job retention can now reap the row.
    from app.api.gc import _gc_old_jobs

    with repo._get_conn() as conn:
        conn.execute("UPDATE jobs SET finished_at='2000-01-01T00:00:00' WHERE id=?", (job.id,))
        conn.commit()
    from app.agents.spool import discard_input

    discard_input(job.id)
    assert client.post(path, headers=headers(key)).status_code == 200  # repeatable
    assert not folder.exists()
    assert _gc_old_jobs(repo, 1) == 1
