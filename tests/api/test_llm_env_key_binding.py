"""An environment-supplied LLM key is only ever sent to the origin it was provisioned for."""

from __future__ import annotations

import logging

import pytest

import app.api.queue as queue_mod
from app import config as C
from app.api.queue import (
    LMSTUDIO_PLACEHOLDER_KEY,
    WARNING_LLM_ENV_KEY_WITHHELD,
    _load_llm_settings,
    _run_llm_stage,
    resolve_llm_api_key,
)
from app.database.models import Case, Job
from app.database.repository import CaseRepository
from app.pipeline.runner import PipelineResult

ENV_NAMES = (
    "LLM_PROVIDER",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_MODEL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_MODEL",
    "LMSTUDIO_API_KEY",
    "LMSTUDIO_BASE_URL",
    "LMSTUDIO_MODEL",
)


class _Saved:
    def __init__(self, values: dict) -> None:
        self.values = values

    def load(self) -> dict:
        return dict(self.values)


@pytest.fixture
def settings(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(C, "LM_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setattr(C, "LM_API_KEY", "lm-studio")

    def configure(**saved) -> None:
        monkeypatch.setattr("app.utils.config_manager.get_config_manager", lambda: _Saved(saved))

    configure()
    return configure


def test_openai_env_key_is_used_for_the_default_origin(settings, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    settings(cfg_llm_provider="openai")
    assert _load_llm_settings()[:3] == ("openai", "", "sk-env")

    settings(cfg_llm_provider="openai", cfg_openai_base_url="https://API.openai.com:443/v1/")
    assert _load_llm_settings()[2] == "sk-env"  # the same origin, written differently


def test_openai_env_key_is_not_sent_to_a_changed_origin(settings, monkeypatch, caplog):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    settings(cfg_llm_provider="openai", cfg_openai_base_url="https://attacker.example/v1")

    with caplog.at_level(logging.WARNING, logger="app.api.queue"):
        provider, base_url, api_key = _load_llm_settings()[:3]

    assert (provider, base_url, api_key) == ("openai", "https://attacker.example/v1", "")
    assert "sk-env" not in caplog.text and "environment API key was not used" in caplog.text
    for other in ("http://api.openai.com/v1", "https://api.openai.com:8443/v1", "https://api.openai.com.evil.test/v1"):
        assert resolve_llm_api_key("openai", other, None) == ("", WARNING_LLM_ENV_KEY_WITHHELD)


def test_openai_env_key_follows_the_environment_configured_origin(settings, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-gateway")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gateway.internal/v1")
    settings(cfg_llm_provider="openai")
    assert _load_llm_settings()[1:3] == ("https://gateway.internal/v1", "sk-gateway")
    # The gateway's key is not for api.openai.com either.
    assert resolve_llm_api_key("openai", "https://api.openai.com/v1", None) == ("", WARNING_LLM_ENV_KEY_WITHHELD)


def test_stored_key_is_used_as_saved_and_never_replaced_by_the_environment(settings, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    settings(cfg_llm_provider="openai", cfg_openai_base_url="https://proxy.example/v1", cfg_openai_cloud_key="sk-proxy")
    assert _load_llm_settings()[2] == "sk-proxy"
    assert resolve_llm_api_key("openai", "https://proxy.example/v1", "sk-proxy") == ("sk-proxy", None)


def test_lmstudio_env_key_binding_and_keyless_local_use(settings, monkeypatch):
    settings(cfg_llm_provider="lmstudio", cfg_llm_endpoint="http://192.168.1.9:1234/v1")
    # No secret anywhere: the non-secret placeholder keeps a keyless LAN server working.
    assert _load_llm_settings()[:3] == ("lmstudio", "http://192.168.1.9:1234/v1", LMSTUDIO_PLACEHOLDER_KEY)
    assert resolve_llm_api_key("lmstudio", "http://192.168.1.9:1234/v1", None) == (LMSTUDIO_PLACEHOLDER_KEY, None)

    monkeypatch.setenv("LMSTUDIO_API_KEY", "lm-env-secret")
    assert _load_llm_settings()[2] == LMSTUDIO_PLACEHOLDER_KEY  # withheld from the changed host
    assert resolve_llm_api_key("lmstudio", "http://192.168.1.9:1234/v1", None)[1] == WARNING_LLM_ENV_KEY_WITHHELD
    settings(cfg_llm_provider="lmstudio")
    assert _load_llm_settings()[1:3] == ("http://localhost:1234/v1", "lm-env-secret")


def test_anthropic_env_key_is_always_eligible(settings, monkeypatch):
    # Anthropic has no configurable base URL in this application.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env")
    settings(cfg_llm_provider="anthropic")
    assert _load_llm_settings()[:3] == ("anthropic", "", "sk-ant-env")


def test_worker_records_a_warning_code_and_makes_no_llm_call(settings, monkeypatch, tmp_path, caplog):
    import app.llm.providers as provider_mod

    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    settings(cfg_llm_provider="openai", cfg_openai_base_url="https://attacker.example/v1", cfg_openai_model="m")
    monkeypatch.setattr(provider_mod, "synthesize_report", lambda *a, **k: pytest.fail("no key may be sent"))
    repo = CaseRepository(db_path=str(tmp_path / "t.db"))
    case_id = repo.create_case(Case(title="t"))
    job_id = repo.create_job(Job(case_id=case_id, pcap_path=str(tmp_path / "x.pcap"), options_json="{}"))
    result = PipelineResult(
        case_id=case_id,
        packet_count=1,
        features={"flows": [], "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []}},
    )

    with caplog.at_level(logging.WARNING, logger="app.api.queue"):
        _run_llm_stage(result, {"llm_enabled": True}, job_id, repo, {"ips": {}, "domains": {}, "ja3": {}}, None)

    assert WARNING_LLM_ENV_KEY_WITHHELD in result.warnings
    assert queue_mod.WARNING_LLM_NOT_CONFIGURED in result.warnings
    assert "sk-env" not in caplog.text
