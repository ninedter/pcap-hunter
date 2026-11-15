"""Settings save validation, credential/host binding, and JSON body guards for the workbench API."""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from app.database.repository import CaseRepository
from app.web import app as web_app

JSON = {"Content-Type": "application/json"}


@pytest.fixture
def manager(tmp_path, monkeypatch):
    from app.utils.config_manager import ConfigManager

    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY", raising=False)
    monkeypatch.delenv("PCAP_HUNTER_CONFIG_KEY_FILE", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("LMSTUDIO_BASE_URL", raising=False)
    manager = ConfigManager(tmp_path / "settings.json")
    monkeypatch.setattr(web_app, "get_config_manager", lambda: manager)
    monkeypatch.setattr("app.web.state.get_config_manager", lambda: manager)
    return manager


@pytest.fixture
def client(manager, tmp_path, monkeypatch):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    monkeypatch.setattr(web_app, "get_repo", lambda: repo)
    with TestClient(web_app.create_app(), base_url="http://localhost") as test_client:
        test_client.repo = repo
        yield test_client


def _seed(manager, **values):
    config = manager.load()
    config.update(values)
    manager.save({key: value for key, value in config.items() if key in web_app.CONFIG_KEYS})


# ── types and ranges ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("key", "value", "fragment"),
    [
        ("cfg_pyshark_limit", {"nested": 1}, "whole number"),
        ("cfg_pyshark_limit", "200000", "whole number"),
        ("cfg_pyshark_limit", 1.5, "whole number"),
        ("cfg_pyshark_limit", True, "whole number"),
        ("cfg_pyshark_limit", -1, "between"),
        ("cfg_osint_top_ips", 1001, "between"),
        ("cfg_llm_context_window", 5, "between"),
        ("cfg_home_lat", 91, "between"),
        ("cfg_home_lon", "121.5", "number"),
        ("cfg_osint_cache_enabled", "yes", "true or false"),
        ("cfg_llm_unlimited_context", 1, "true or false"),
        ("cfg_llm_provider", "evilcorp", "one of"),
        ("cfg_llm_model", ["a"], "text"),
        ("cfg_yara_rules_dir", "x" * 5000, "at most"),
        ("cfg_zeek_bin", "zeek\n--evil", "control characters"),
        ("cfg_vt_key", {"k": "v"}, "text"),
        ("cfg_openai_base_url", "file:///etc/passwd", "http(s)"),
        ("cfg_openai_base_url", "https://user:pw@api.example/v1", "http(s)"),
        ("cfg_llm_endpoint", "http://169.254.169.254/v1", "http(s)"),
        ("cfg_llm_endpoint", "https://api.example/v1?x=1", "http(s)"),
    ],
)
def test_invalid_setting_is_rejected_with_a_per_field_message(client, manager, key, value, fragment):
    before = manager.load()

    response = client.put("/api/ui/settings", json={key: value, "cfg_llm_language": "Traditional Chinese"})

    assert response.status_code == 422
    body = response.json()
    assert isinstance(body["detail"], str) and key in body["detail"], "the client shows detail when it is a string"
    assert [error["field"] for error in body["errors"]] == [key]
    assert fragment in body["errors"][0]["message"]
    assert manager.load() == before, "a rejected save changes nothing, including the valid fields"


def test_valid_settings_are_saved_and_normalised(client, manager):
    response = client.put(
        "/api/ui/settings",
        json={
            "cfg_pyshark_limit": 50000.0,
            "cfg_osint_top_ips": 0,
            "cfg_llm_context_window": 64000,
            "cfg_home_lat": 25,
            "cfg_home_lon": 121.5,
            "cfg_osint_cache_enabled": True,
            "cfg_llm_provider": "openai",
            "cfg_openai_base_url": " https://api.openai.com/v1 ",
            "cfg_vt_key": "  vt-secret  ",
            "cfg_not_a_real_key": {"ignored": True},
            "configured_providers": {"cfg_vt_key": False},
        },
    )

    assert response.status_code == 200
    assert response.json() == {"saved": True}
    saved = manager.load()
    assert saved["cfg_pyshark_limit"] == 50000 and isinstance(saved["cfg_pyshark_limit"], int)
    assert saved["cfg_home_lat"] == 25.0 and isinstance(saved["cfg_home_lat"], float)
    assert (saved["cfg_osint_top_ips"], saved["cfg_osint_cache_enabled"]) == (0, True)
    assert saved["cfg_openai_base_url"] == "https://api.openai.com/v1"
    assert saved["cfg_vt_key"] == "vt-secret"
    assert "cfg_not_a_real_key" not in saved and "configured_providers" not in saved


def test_null_and_blank_secret_leave_stored_values_unchanged(client, manager):
    _seed(manager, cfg_pyshark_limit=1234, cfg_vt_key="vt-secret")

    response = client.put("/api/ui/settings", json={"cfg_pyshark_limit": None, "cfg_vt_key": "", "cfg_otx_key": None})

    assert response.status_code == 200
    saved = manager.load()
    assert (saved["cfg_pyshark_limit"], saved["cfg_vt_key"]) == (1234, "vt-secret")


def test_unchanged_legacy_value_echoed_by_the_form_does_not_block_other_edits(client, manager):
    """The form re-sends its whole draft; a stored out-of-range value must not block saving."""
    _seed(manager, cfg_llm_context_window=4000)

    response = client.put("/api/ui/settings", json={"cfg_llm_context_window": 4000, "cfg_llm_language": "Deutsch"})

    assert response.status_code == 200
    assert manager.load()["cfg_llm_language"] == "Deutsch"


# ── stored keys are bound to the host they were saved for ────────────────────


def test_moving_openai_base_url_without_a_new_key_clears_the_stored_key(client, manager):
    _seed(manager, cfg_openai_base_url="https://api.openai.com/v1", cfg_openai_cloud_key="sk-cloud", cfg_vt_key="vt")

    response = client.put("/api/ui/settings", json={"cfg_openai_base_url": "https://attacker.example/v1"})

    assert response.status_code == 200
    body = response.json()
    assert body["saved"] is True and body["cleared_keys"] == ["cfg_openai_cloud_key"]
    assert "different host" in body["notice"]
    saved = manager.load()
    assert saved["cfg_openai_base_url"] == "https://attacker.example/v1"
    assert saved["cfg_openai_cloud_key"] == "", "the worker must have nothing to send to the new host"
    assert saved["cfg_vt_key"] == "vt"
    assert client.get("/api/ui/settings").json()["configured_providers"]["cfg_openai_cloud_key"] is False


def test_moving_from_the_implicit_default_openai_host_also_clears(client, manager):
    _seed(manager, cfg_openai_cloud_key="sk-cloud")  # blank base URL = api.openai.com

    response = client.put("/api/ui/settings", json={"cfg_openai_base_url": "https://proxy.example/v1"})

    assert response.json()["cleared_keys"] == ["cfg_openai_cloud_key"]
    assert manager.load()["cfg_openai_cloud_key"] == ""


def test_lm_studio_endpoint_move_clears_its_key(client, manager):
    _seed(manager, cfg_llm_endpoint="http://localhost:1234/v1", cfg_openai_key="lm-secret")

    response = client.put("/api/ui/settings", json={"cfg_llm_endpoint": "http://localhost:9999/v1"})

    assert response.json()["cleared_keys"] == ["cfg_openai_key"]
    assert manager.load()["cfg_openai_key"] == ""


@pytest.mark.parametrize("new_url", ["http://api.openai.com/v1", "https://api.openai.com:8443/v1"])
def test_scheme_or_port_change_counts_as_a_different_destination(client, manager, new_url):
    _seed(manager, cfg_openai_base_url="https://api.openai.com/v1", cfg_openai_cloud_key="sk-cloud")

    response = client.put("/api/ui/settings", json={"cfg_openai_base_url": new_url})

    assert response.json()["cleared_keys"] == ["cfg_openai_cloud_key"]


def test_new_key_in_the_same_request_is_kept_for_the_new_host(client, manager):
    _seed(manager, cfg_openai_base_url="https://api.openai.com/v1", cfg_openai_cloud_key="sk-old")

    response = client.put(
        "/api/ui/settings",
        json={"cfg_openai_base_url": "https://gateway.example/v1", "cfg_openai_cloud_key": "sk-new"},
    )

    assert response.json() == {"saved": True}
    assert manager.load()["cfg_openai_cloud_key"] == "sk-new"


@pytest.mark.parametrize(
    "new_url", ["https://api.openai.com/v1", "https://api.openai.com/v1/", "https://API.OPENAI.COM:443/v2", ""]
)
def test_same_origin_edits_keep_the_stored_key(client, manager, new_url):
    _seed(manager, cfg_openai_base_url="https://api.openai.com/v1", cfg_openai_cloud_key="sk-cloud")

    response = client.put("/api/ui/settings", json={"cfg_openai_base_url": new_url, "cfg_llm_language": "Deutsch"})

    assert response.json() == {"saved": True}
    assert manager.load()["cfg_openai_cloud_key"] == "sk-cloud"


def test_full_draft_resave_as_the_react_form_sends_it_changes_nothing(client, manager):
    """The settings form PUTs public config back verbatim; that must be a no-op for stored keys."""
    _seed(
        manager,
        cfg_openai_base_url="https://gateway.example/v1",
        cfg_openai_cloud_key="sk-cloud",
        cfg_llm_endpoint="http://host.docker.internal:1234/v1",
        cfg_openai_key="lm-secret",
        cfg_anthropic_key="sk-ant",
    )
    draft = client.get("/api/ui/settings").json()
    assert "cfg_openai_cloud_key" not in draft

    response = client.put("/api/ui/settings", json=draft)

    assert response.json() == {"saved": True}
    saved = manager.load()
    assert (saved["cfg_openai_cloud_key"], saved["cfg_openai_key"], saved["cfg_anthropic_key"]) == (
        "sk-cloud",
        "lm-secret",
        "sk-ant",
    )


def test_concurrent_saves_do_not_lose_each_others_fields(client, manager):
    barrier = threading.Barrier(2)
    original_load = manager.load

    def slow_load():
        config = original_load()
        try:
            barrier.wait(timeout=0.3)  # without one lock both requests would load before either saved
        except threading.BrokenBarrierError:
            pass
        return config

    manager.load = slow_load
    results: list[int] = []

    def put(payload):
        results.append(client.put("/api/ui/settings", json=payload).status_code)

    threads = [
        threading.Thread(target=put, args=({"cfg_llm_language": "Deutsch"},)),
        threading.Thread(target=put, args=({"cfg_zeek_bin": "/opt/zeek/bin/zeek"},)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    manager.load = original_load

    assert results == [200, 200]
    saved = manager.load()
    assert (saved["cfg_llm_language"], saved["cfg_zeek_bin"]) == ("Deutsch", "/opt/zeek/bin/zeek")


# ── GET settings / jobs ──────────────────────────────────────────────────────


def test_get_settings_returns_public_config_without_building_the_workbench(client, manager, monkeypatch):
    _seed(manager, cfg_vt_key="vt-secret", cfg_llm_language="Deutsch")
    monkeypatch.setattr(web_app, "build_workbench_state", lambda *a, **kw: pytest.fail("bootstrap must not run"))
    monkeypatch.setattr(client.repo, "list_cases", lambda *a, **kw: pytest.fail("settings needs no database read"))

    body = client.get("/api/ui/settings").json()

    assert body["cfg_llm_language"] == "Deutsch"
    assert "cfg_vt_key" not in body and "vt-secret" not in str(body)
    assert body["configured_providers"]["cfg_vt_key"] is True


def test_jobs_endpoint_matches_the_bootstrap_job_shape(client, monkeypatch):
    import json

    from app.database.models import Case, Job

    repo = client.repo
    repo.create_case(Case(id="c1", title="capture-one.pcap"))
    repo.create_case(Case(id="c2", title="Batch analysis"))
    first = repo.create_job(Job(case_id="c1", pcap_path="/data/api_uploads/c1_1.pcap"))
    repo.create_job(Job(case_id="c2", pcap_path="/data/x.pcap", options_json=json.dumps({"display_name": "named"})))
    repo.start_job_if_queued(first)
    repo.update_job_stage(first, "Zeek", 40, "Parsing logs")

    bootstrap_jobs = client.get("/api/ui/bootstrap").json()["jobs"]
    monkeypatch.setattr(web_app, "build_workbench_state", lambda *a, **kw: pytest.fail("bootstrap must not run"))
    response = client.get("/api/ui/jobs")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"jobs": bootstrap_jobs}
    assert {job["name"] for job in bootstrap_jobs} == {"capture-one.pcap", "named"}
    assert {"id", "case_id", "status", "stage", "progress", "stage_progress", "error"} <= set(bootstrap_jobs[0])


# ── malformed / non-object JSON never reaches a 500 ──────────────────────────

_JSON_ROUTES = [
    ("POST", "/api/ui/cases"),
    ("POST", "/api/ui/cases/c1/notes"),
    ("POST", "/api/ui/paths"),
    ("PUT", "/api/ui/settings"),
]


@pytest.mark.parametrize(("method", "path"), _JSON_ROUTES)
@pytest.mark.parametrize("body", ['{"title": ', "not json", "\xff\xfe".encode("latin-1"), b""])
def test_malformed_json_is_400(client, method, path, body):
    from app.database.models import Case

    client.repo.create_case(Case(id="c1", title="t"))
    response = client.request(method, path, content=body, headers=JSON)
    assert response.status_code == 400, response.text
    assert response.json() == {"detail": "invalid_json"}


@pytest.mark.parametrize(("method", "path"), _JSON_ROUTES)
@pytest.mark.parametrize("body", ["[]", '"text"', "null", "42", "true"])
def test_non_object_json_is_422(client, method, path, body):
    from app.database.models import Case

    client.repo.create_case(Case(id="c1", title="t"))
    response = client.request(method, path, content=body, headers=JSON)
    assert response.status_code == 422, response.text
    assert isinstance(response.json()["detail"], str)


@pytest.mark.parametrize(
    "payload",
    [{"tags": "abc"}, {"tags": 7}, {"tags": [{"a": 1}]}, {"title": ["x"]}, {"severity": 3}, {"description": {}}],
)
def test_case_create_rejects_wrong_field_types(client, payload):
    response = client.post("/api/ui/cases", json=payload)
    assert response.status_code == 422
    assert client.repo.list_cases() == []


def test_case_and_note_create_still_work(client):
    created = client.post("/api/ui/cases", json={"title": " Intrusion ", "severity": "high", "tags": ["a", " ", 7]})
    assert created.status_code == 201
    case = client.repo.get_case(created.json()["id"])
    assert (case.title, case.severity.value, sorted(case.tags)) == ("Intrusion", "high", ["7", "a"])
    assert client.post("/api/ui/cases", json={}).status_code == 201

    note = client.post(f"/api/ui/cases/{case.id}/notes", json={"content": " first note "})
    assert note.status_code == 200 and note.json()["content"] == "first note"
    assert client.post(f"/api/ui/cases/{case.id}/notes", json={"content": 5}).status_code == 422
    assert client.post(f"/api/ui/cases/{case.id}/notes", json={"content": "  "}).status_code == 422


@pytest.mark.parametrize("payload", [{"paths": [1]}, {"paths": [["a"]]}, {"paths": "x.pcap"}, {"paths": []}, {}])
def test_path_submission_rejects_wrong_shapes(client, payload):
    assert client.post("/api/ui/paths", json=payload).status_code == 422


# ── environment-supplied keys are bound to the deployment's own origin ───────


def test_cleared_stored_key_is_not_replaced_by_the_environment_key(client, manager, monkeypatch):
    from app.api import queue as queue_mod

    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr("app.utils.config_manager.get_config_manager", lambda: manager)
    _seed(manager, cfg_llm_provider="openai", cfg_openai_cloud_key="sk-cloud")
    assert queue_mod._load_llm_settings()[2] == "sk-cloud"

    response = client.put("/api/ui/settings", json={"cfg_openai_base_url": "https://attacker.example/v1"})

    assert response.json()["cleared_keys"] == ["cfg_openai_cloud_key"]
    provider, base_url, api_key = queue_mod._load_llm_settings()[:3]
    assert (provider, base_url, api_key) == ("openai", "https://attacker.example/v1", "")


def test_environment_key_alone_is_not_sent_after_the_base_url_moves(client, manager, monkeypatch):
    """No stored key at all: the save guard has nothing to clear, so the worker must hold the line."""
    from app.api import queue as queue_mod

    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr("app.utils.config_manager.get_config_manager", lambda: manager)
    _seed(manager, cfg_llm_provider="openai")
    assert queue_mod._load_llm_settings()[2] == "sk-env"  # default origin: used

    assert (
        client.put("/api/ui/settings", json={"cfg_openai_base_url": "https://attacker.example/v1"}).status_code == 200
    )

    assert queue_mod._load_llm_settings()[2] == ""
