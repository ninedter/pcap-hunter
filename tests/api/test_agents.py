"""Agent authority, completeness, immutable citations, quotas and safe writes."""

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.agents.registry import AgentRegistry
from app.database.models import IOC, Analysis, Case, IOCType, Severity
from app.database.repository import CaseRepository

READ = ["cases:read", "evidence:read", "jobs:read"]


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PCAP_HUNTER_API_DB_PATH", str(tmp_path / "cases.db"))
    monkeypatch.setenv("PCAP_HUNTER_API_KEY", "test-admin")
    monkeypatch.setenv("PCAP_HUNTER_AGENT_SPOOL", str(tmp_path / "spool"))
    monkeypatch.setenv("PCAP_HUNTER_API_UPLOADS_DIR", str(tmp_path / "uploads"))
    from app.api.deps import get_key_repo, get_queue, get_repo, get_settings

    for getter in (get_repo, get_queue, get_settings, get_key_repo):
        getter.cache_clear()
    repo = CaseRepository(str(tmp_path / "cases.db"))
    repo.create_case(Case(id="case-a", title="Case A"))
    repo.create_case(Case(id="case-b", title="Case B"))
    analysis = Analysis(
        id="analysis-a",
        case_id="case-a",
        pcap_path="/private/capture.pcap",
        pcap_hash="f" * 64,
        packet_count=300,
        features={
            "flows": [
                {"src": "192.0.2.1", "dst": "198.51.100.2", "proto": "TCP", "count": 1, "first_ts": i}
                for i in range(251)
            ]
        },
    )
    analysis.iocs = [
        IOC(
            ioc_type=IOCType.IP,
            value=f"198.51.100.{i}",
            context="Observed",
            severity=Severity.CRITICAL if i == 100 else Severity.LOW,
        )
        for i in range(101)
    ]
    repo.save_analysis(analysis)
    repo.save_analysis(Analysis(id="analysis-b", case_id="case-b", pcap_path="/private/other.pcap"))
    registry = AgentRegistry(repo)
    credential = registry.create("Reader", READ, ["case-a"], rpm=600)
    from app.api.app import create_app

    with TestClient(create_app()) as client:
        yield client, repo, registry, credential
    for getter in (get_repo, get_queue, get_settings, get_key_repo):
        if getter is get_queue and getter.cache_info().currsize:
            getter().shutdown()
        getter.cache_clear()


def headers(credential):
    return {"Authorization": "Bearer " + credential["key"]}


def test_complete_pages_reach_evidence_after_100_and_flows_after_250(environment):
    client, _, _, key = environment
    url = "/api/v1/analyses/analysis-a/evidence"
    first = client.get(url, headers=headers(key), params={"limit": 100}).json()
    assert first["total_matching"] == 101 and first["returned_count"] == 100
    second = client.get(url, headers=headers(key), params={"cursor": first["next_cursor"]}).json()
    assert second["items"][0]["severity"] == "critical" and second["next_cursor"] is None
    assert first["coverage"]["packet_parse"] == "partial_or_unknown"
    url = "/api/v1/analyses/analysis-a/flows"
    first = client.get(url, headers=headers(key), params={"limit": 200}).json()
    second = client.get(url, headers=headers(key), params={"cursor": first["next_cursor"]}).json()
    assert first["total_matching"] == 251 and len(second["items"]) == 51
    assert "pcap_path" not in json.dumps(first) and "/private/" not in json.dumps(first)


def test_agent_cannot_cross_cases_or_use_legacy_admin_delete_settings(environment):
    client, _, _, key = environment
    for url in ("/api/v1/agent/cases/case-b", "/api/v1/analyses/analysis-b/manifest", "/api/v1/cases/case-b/analyses"):
        assert client.get(url, headers=headers(key)).status_code == 404
    assert client.get("/api/v1/admin/keys", headers=headers(key)).status_code == 401
    assert client.delete("/api/v1/cases/case-a", headers=headers(key)).status_code == 401
    assert client.post("/api/v1/admin/agents", headers=headers(key), json={"name": "escalate"}).status_code == 401
    assert client.get("/api/v1/agent/cases").status_code == 401


def test_signed_cursors_are_bound_to_principal_analysis_and_filters(environment):
    client, _, registry, key = environment
    url = "/api/v1/analyses/analysis-a/evidence"
    page = client.get(url, headers=headers(key), params={"limit": 1}).json()
    cursor = page["next_cursor"]
    other = registry.create("Other", READ, ["case-a"], rpm=600)
    assert client.get(url, headers=headers(other), params={"cursor": cursor}).status_code == 422
    assert client.get(url, headers=headers(key), params={"cursor": cursor, "type": "domain"}).status_code == 422
    assert client.get(url, headers=headers(key), params={"cursor": cursor[:-3] + "bad"}).status_code == 422
    assert client.get(url, headers=headers(key), params={"sql": "DELETE FROM cases"}).status_code == 422
    assert client.get(url, headers=headers(key), params={"value": "' OR 1=1 --"}).json()["total_matching"] == 0


def test_snapshot_is_immutable_and_cursor_does_not_drift(environment):
    client, repo, registry, key = environment
    url = "/api/v1/analyses/analysis-a/evidence"
    page = client.get(url, headers=headers(key), params={"limit": 100}).json()
    analysis = repo.get_analysis("analysis-a")
    analysis.iocs.append(IOC(ioc_type=IOCType.DOMAIN, value="example.invalid"))
    repo.save_analysis(analysis)
    old = client.get(url, headers=headers(key), params={"cursor": page["next_cursor"]}).json()
    current = client.get(url, headers=headers(key)).json()
    assert old["total_matching"] == 101 and current["total_matching"] == 102
    assert old["snapshot_id"] != current["snapshot_id"]
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        with registry.connection(write=True) as conn:
            conn.execute("DELETE FROM evidence_records")


def test_trusted_case_deletion_purges_only_its_saved_evidence(environment):
    client, repo, _, key = environment
    assert repo.delete_case("case-a")
    with repo._get_conn() as conn:
        assert conn.execute("SELECT count(*) FROM evidence_records WHERE analysis_id='analysis-a'").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM evidence_snapshots WHERE case_id='case-a'").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM evidence_snapshots WHERE case_id='case-b'").fetchone()[0] == 1
    assert client.get("/api/v1/analyses/analysis-a/evidence", headers=headers(key)).status_code == 404


def test_clear_all_purges_saved_evidence_and_stale_case_grants(environment):
    _, repo, registry, _ = environment
    assert repo.clear_all()
    with registry.connection() as conn:
        assert conn.execute("SELECT count(*) FROM evidence_records").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM evidence_snapshots").fetchone()[0] == 0
        assert conn.execute("SELECT cases FROM agent_keys").fetchone()[0] == "[]"


def test_large_detector_collections_remain_completely_pageable(environment):
    client, repo, _, key = environment
    analysis = repo.get_analysis("analysis-a")
    records = [{"domain": f"host-{index}.invalid", "detail": "x" * 1500} for index in range(800)]
    analysis.dns_analysis = {"high_risk_domains": records, "large_text": "字" * 400000}
    repo.save_analysis(analysis)
    rows, cursor = [], None
    while True:
        params = {"type": "dns", "limit": 200}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/api/v1/analyses/analysis-a/evidence", params=params, headers=headers(key))
        assert response.status_code == 200
        page = response.json()
        rows.extend(page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(rows) == page["total_matching"]
    assert [row["context"]["data"] for row in rows if row["value"] == "high_risk_domains"] == records
    fragments = [row["context"]["data"] for row in rows if row["value"] == "large_text"]
    assert "".join(part["text_fragment"] for part in fragments) == analysis.dns_analysis["large_text"]
    assert "detector_evidence_chunked_with_locators" in page["warnings"]


def test_analysis_and_evidence_persistence_are_atomic(environment, monkeypatch):
    from app.agents.evidence import EvidenceService

    _, repo, registry, _ = environment
    before = repo.get_analysis("analysis-a")
    with registry.connection() as conn:
        snapshots = conn.execute("SELECT count(*) FROM evidence_snapshots").fetchone()[0]
    original = EvidenceService.capture

    def capture_then_fail(self, analysis, **kwargs):
        original(self, analysis, **kwargs)
        raise RuntimeError("simulated snapshot persistence failure")

    monkeypatch.setattr(EvidenceService, "capture", capture_then_fail)
    before.packet_count += 1
    before.iocs.append(IOC(ioc_type=IOCType.DOMAIN, value="rollback.invalid"))
    with pytest.raises(RuntimeError, match="snapshot persistence"):
        repo.save_analysis(before)
    with pytest.raises(RuntimeError, match="snapshot persistence"):
        repo.save_analysis(Analysis(id="must-not-exist", case_id="case-a"))
    assert repo.get_analysis("must-not-exist") is None
    after = repo.get_analysis("analysis-a")
    assert after.packet_count == before.packet_count - 1
    assert not any(ioc.value == "rollback.invalid" for ioc in after.iocs)
    with registry.connection() as conn:
        assert conn.execute("SELECT count(*) FROM evidence_snapshots").fetchone()[0] == snapshots


def test_drafts_require_permission_valid_citations_and_idempotency(environment):
    client, repo, registry, key = environment
    page = client.get("/api/v1/analyses/analysis-a/evidence", headers=headers(key)).json()
    payload = {
        "analysis_id": "analysis-a",
        "snapshot_id": page["snapshot_id"],
        "content": "A hypothesis requiring review.",
        "evidence_ids": [page["items"][0]["id"]],
    }
    url = "/api/v1/agent/cases/case-a/drafts"
    assert client.post(url, headers=headers(key), json=payload).status_code == 403
    writer = registry.create("Writer", READ + ["notes:append"], ["case-a"], rpm=600)
    auth = headers(writer) | {"Idempotency-Key": "draft-probe-0001"}
    first = client.post(url, headers=auth, json=payload)
    second = client.post(url, headers=auth, json=payload)
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert len(repo.get_case("case-a").notes) == 1
    assert repo.get_case("case-a").status.value == "open"
    assert "requires analyst review" in repo.get_case("case-a").notes[0].content
    assert client.post(url, headers=auth, json=payload | {"content": "changed"}).status_code == 409
    assert (
        client.post(
            url,
            headers=headers(writer) | {"Idempotency-Key": "draft-probe-0002"},
            json=payload | {"evidence_ids": ["fake"]},
        ).status_code
        == 404
    )


def test_revocation_expiry_and_persisted_request_budget(environment):
    client, _, registry, key = environment
    registry.revoke(key["id"])
    assert client.get("/api/v1/agent/capabilities", headers=headers(key)).status_code == 401
    expired = registry.create("Expired", READ, ["case-a"])
    with registry.connection(write=True) as conn:
        conn.execute("UPDATE agent_keys SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (expired["id"],))
    assert client.get("/api/v1/agent/capabilities", headers=headers(expired)).status_code == 401
    bounded = registry.create("Budget", READ, ["case-a"], daily_requests=1)
    assert client.get("/api/v1/agent/capabilities", headers=headers(bounded)).status_code == 200
    assert client.get("/api/v1/agent/capabilities", headers=headers(bounded)).status_code == 429


def test_capture_submission_is_offline_idempotent_and_case_bound(environment):
    client, repo, registry, _ = environment
    key = registry.create("Submitter", READ + ["captures:submit"], [], rpm=600, daily_submissions=1)
    pcap = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    auth = headers(key) | {"Idempotency-Key": "capture-probe-0001"}
    first = client.post("/api/v1/agent/captures", headers=auth, files={"pcap": ("test.pcap", pcap)})
    assert first.status_code == 202, first.text
    second = client.post("/api/v1/agent/captures", headers=auth, files={"pcap": ("test.pcap", pcap)})
    assert second.json()["job_id"] == first.json()["job_id"]
    result = first.json()
    options = json.loads(repo.get_job(result["job_id"]).options_json)
    assert options["llm_enabled"] is False and options["osint_enabled"] is False
    assert client.get("/api/v1/agent/cases/" + result["case_id"], headers=headers(key)).status_code == 200
    assert (
        client.post(
            "/api/v1/agent/captures",
            headers=auth | {"Idempotency-Key": "capture-probe-0002"},
            files={"pcap": ("test.pcap", pcap)},
        ).status_code
        == 429
    )
    assert (
        client.post(
            "/api/v1/agent/captures", headers=auth, files={"pcap": ("test.pcap", pcap)}, data={"osint_enabled": "true"}
        ).status_code
        == 422
    )


def test_audit_is_append_only_and_contains_no_tokens_or_payloads(environment):
    client, _, registry, key = environment
    client.get("/api/v1/agent/cases/case-b", headers=headers(key))
    with registry.connection() as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM agent_audit WHERE actor=?", (key["id"],))]
    assert rows[-1]["outcome"] == 404
    assert key["key"] not in json.dumps(rows)
    with pytest.raises(sqlite3.IntegrityError, match="append_only"):
        with registry.connection(write=True) as conn:
            conn.execute("UPDATE agent_audit SET outcome=200")


def test_large_json_is_rejected_before_deserialization(environment):
    client, _, _, key = environment
    response = client.post(
        "/api/v1/agent/cases/case-a/drafts",
        headers=headers(key) | {"Content-Type": "application/json"},
        content=b" " * 70000,
    )
    assert response.status_code == 413


def test_flow_time_filters_require_an_explicit_timezone(environment):
    client, _, _, key = environment
    url = "/api/v1/analyses/analysis-a/flows"
    page = client.get(url, headers=headers(key), params={"start": "1970-01-01T00:04:10Z"}).json()
    assert page["total_matching"] == 1
    assert client.get(url, headers=headers(key), params={"start": "1970-01-01T00:00:00"}).status_code == 422
    assert client.get(url, headers=headers(key), params={"limit": 201}).status_code == 422


def test_agents_can_cancel_only_their_own_capture_job(environment):
    client, repo, registry, _ = environment
    key = registry.create("Submitter", READ + ["captures:submit"], [], rpm=600)
    pcap = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    result = client.post(
        "/api/v1/agent/captures",
        headers=headers(key) | {"Idempotency-Key": "capture-cancel-0001"},
        files={"pcap": ("test.pcap", pcap)},
    ).json()
    other = registry.create("Other", READ + ["captures:submit"], [result["case_id"]], rpm=600)
    path = "/api/v1/agent/jobs/" + result["job_id"] + "/cancel"
    assert client.post(path, headers=headers(other)).status_code == 403
    assert client.post(path, headers=headers(key)).status_code == 200
    assert repo.get_job(result["job_id"]).status.value == "cancelled"
    assert repo.get_case(result["case_id"]) is not None
