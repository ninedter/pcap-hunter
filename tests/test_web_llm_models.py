"""LLM model-picker API tests.  All provider SDK calls are mocked."""

from types import SimpleNamespace
from unittest.mock import ANY, MagicMock

from fastapi.testclient import TestClient

from app.database.repository import CaseRepository
from app.web import app as web_app


class _Config:
    def __init__(self, values):
        self.values = values

    def load(self):
        return self.values


def _client(monkeypatch, tmp_path, config=None):
    repo = CaseRepository(db_path=str(tmp_path / "cases.db"))
    # Discovery may fall back to an environment key; tests set one explicitly after this.
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LMSTUDIO_API_KEY", "OPENAI_BASE_URL", "LMSTUDIO_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(web_app, "get_repo", lambda: repo)
    monkeypatch.setattr(web_app, "get_config_manager", lambda: _Config(config or {}))
    return TestClient(web_app.create_app(), base_url="http://localhost")


def test_model_discovery_uses_draft_openai_values_and_returns_sorted_models(monkeypatch, tmp_path):
    client = _client(
        monkeypatch,
        tmp_path,
        {"cfg_openai_base_url": "https://saved.invalid/v1", "cfg_openai_cloud_key": "saved-key"},
    )
    discover = MagicMock(return_value=["zeta", "alpha", "zeta"])
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    response = client.post(
        "/api/ui/llm/models",
        json={"provider": "openai", "base_url": "https://draft.example/v1", "api_key": "draft-key"},
    )

    assert response.status_code == 200
    assert response.json() == {"models": ["alpha", "zeta"], "message": "OpenAI returned 2 models."}
    discover.assert_called_once_with("openai", base_url="https://draft.example/v1", api_key="draft-key")


def test_model_discovery_offloads_provider_call_and_normalizes_result(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    calls = []

    async def threadpool(func, *args, **kwargs):
        calls.append((func, args, kwargs))
        return ["zeta", "alpha", "zeta"]

    monkeypatch.setattr(web_app, "run_in_threadpool", threadpool)

    response = client.post(
        "/api/ui/llm/models",
        json={"provider": "openai", "api_key": "draft-key"},
    )

    assert response.status_code == 200
    assert response.json()["models"] == ["alpha", "zeta"]
    assert calls == [
        (
            web_app._discover_llm_models,
            ("openai",),
            {"base_url": "https://api.openai.com/v1", "api_key": "draft-key"},
        )
    ]


def test_model_discovery_uses_saved_lmstudio_values_when_draft_is_empty(monkeypatch, tmp_path):
    client = _client(
        monkeypatch,
        tmp_path,
        {"cfg_llm_endpoint": "http://localhost:1234/v1", "cfg_openai_key": "saved-local-key"},
    )
    discover = MagicMock(return_value=["local-model"])
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    response = client.post(
        "/api/ui/llm/models",
        json={"provider": "lmstudio", "base_url": "", "api_key": ""},
    )

    assert response.status_code == 200
    discover.assert_called_once_with("lmstudio", base_url="http://localhost:1234/v1", api_key="saved-local-key")


def test_openai_uses_official_default_url_when_no_override_is_configured(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, {"cfg_openai_base_url": "", "cfg_openai_cloud_key": "saved-key"})
    discover = MagicMock(return_value=[])
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    response = client.post("/api/ui/llm/models", json={"provider": "openai"})

    assert response.status_code == 200
    assert response.json() == {"models": [], "message": "OpenAI returned no models."}
    discover.assert_called_once_with("openai", base_url="https://api.openai.com/v1", api_key="saved-key")


def test_cloud_providers_require_a_real_api_key_before_sdk_calls(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    discover = MagicMock()
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    openai = client.post("/api/ui/llm/models", json={"provider": "openai"})
    anthropic = client.post("/api/ui/llm/models", json={"provider": "anthropic"})

    assert openai.status_code == 422
    assert openai.json()["detail"] == "openai_api_key_required"
    assert anthropic.status_code == 422
    assert anthropic.json()["detail"] == "anthropic_api_key_required"
    discover.assert_not_called()


def test_model_discovery_rejects_unknown_provider(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)

    response = client.post("/api/ui/llm/models", json={"provider": "other"})

    assert response.status_code == 422
    assert response.json()["detail"] == "unsupported_llm_provider"


def test_model_discovery_rejects_malformed_or_credential_bearing_url(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    discover = MagicMock()
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    response = client.post(
        "/api/ui/llm/models",
        json={"provider": "openai", "base_url": "https://secret:token@example.test/v1"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "invalid_model_api_url"
    assert "token" not in response.text
    discover.assert_not_called()


def test_model_discovery_rejects_non_http_and_missing_hostname_urls(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    discover = MagicMock()
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    for url in ("ftp://models.example/v1", "https:///v1", "https://   /v1"):
        response = client.post("/api/ui/llm/models", json={"provider": "openai", "base_url": url})
        assert response.status_code == 422
        assert response.json()["detail"] == "invalid_model_api_url"

    discover.assert_not_called()


def test_model_discovery_failure_is_generic_and_never_echoes_secrets(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    secret = "super-secret-value"

    def fail(*args, **kwargs):
        raise RuntimeError(f"provider rejected {secret}")

    monkeypatch.setattr(web_app, "_discover_llm_models", fail)
    response = client.post(
        "/api/ui/llm/models",
        json={"provider": "openai", "api_key": secret},
    )

    assert response.status_code == 502
    assert response.json() == {
        "models": [],
        "message": "Could not retrieve models. Check the provider settings and try again.",
    }
    assert secret not in response.text


def test_model_ids_are_bounded_deduplicated_and_deterministic():
    models = [SimpleNamespace(id=f"model-{index:03d}") for index in range(120)]
    models.extend([SimpleNamespace(id="model-001"), SimpleNamespace(id="")])

    ids = web_app._model_ids(models)

    assert ids == [f"model-{index:03d}" for index in range(100)]


def test_model_ids_stop_consuming_after_the_response_bound():
    def limited_items():
        for index in range(web_app._LLM_MODEL_LIMIT):
            yield SimpleNamespace(id=f"model-{index:03d}")
        raise AssertionError("model iterator was read beyond the response bound")

    ids = web_app._model_ids(limited_items())

    assert len(ids) == web_app._LLM_MODEL_LIMIT


def test_openai_compatible_discovery_lists_models_with_lmstudio_docker_normalization(monkeypatch):
    from app.llm import client as llm_client

    sdk_client = MagicMock()
    sdk_client.models.list.return_value = [SimpleNamespace(id="local-model")]
    openai = MagicMock(return_value=sdk_client)
    monkeypatch.setattr(llm_client, "OpenAI", openai)
    monkeypatch.setenv("PCAP_HUNTER_DOCKER_HOST_FALLBACK", "true")

    result = web_app._discover_llm_models("lmstudio", base_url="http://192.168.1.9:1234", api_key="local-key")

    assert result == ["local-model"]
    openai.assert_called_once_with(
        base_url="http://host.docker.internal:1234/v1",
        api_key="local-key",
        timeout=web_app.C.LLM_PROBE_TIMEOUT_SECONDS,
        http_client=ANY,
    )
    sdk_client.models.list.assert_called_once_with()


def test_openai_discovery_never_substitutes_the_lmstudio_dummy_key(monkeypatch):
    from app.llm import client as llm_client

    sdk_client = MagicMock()
    sdk_client.models.list.return_value = []
    openai = MagicMock(return_value=sdk_client)
    monkeypatch.setattr(llm_client, "OpenAI", openai)

    web_app._discover_llm_models("openai", base_url="https://api.openai.com/v1", api_key="")

    assert openai.call_args.kwargs["api_key"] == ""


def test_anthropic_endpoint_uses_draft_key_then_saved_key(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, {"cfg_anthropic_key": "saved-anthropic-key"})
    discover = MagicMock(return_value=["claude-test"])
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    response = client.post("/api/ui/llm/models", json={"provider": "anthropic", "api_key": "draft-anthropic-key"})

    assert response.status_code == 200
    discover.assert_called_once_with("anthropic", base_url="", api_key="draft-anthropic-key")

    discover.reset_mock()
    response = client.post("/api/ui/llm/models", json={"provider": "anthropic", "api_key": ""})

    assert response.status_code == 200
    discover.assert_called_once_with("anthropic", base_url="", api_key="saved-anthropic-key")


def test_anthropic_discovery_uses_official_models_list_api(monkeypatch):
    import sys

    models = MagicMock()
    models.list.return_value = SimpleNamespace(data=[SimpleNamespace(id="claude-test")])
    sdk_client = SimpleNamespace(models=models, close=MagicMock())
    anthropic = SimpleNamespace(Anthropic=MagicMock(return_value=sdk_client))
    monkeypatch.setitem(sys.modules, "anthropic", anthropic)

    result = web_app._discover_llm_models("anthropic", base_url="", api_key="anthropic-key")

    assert result == ["claude-test"]
    anthropic.Anthropic.assert_called_once_with(
        api_key="anthropic-key",
        base_url="https://api.anthropic.com",
        http_client=ANY,
        timeout=web_app.C.LLM_PROBE_TIMEOUT_SECONDS,
    )
    models.list.assert_called_once_with(limit=web_app._LLM_MODEL_LIMIT)


def test_new_endpoint_never_receives_a_saved_cloud_key(monkeypatch, tmp_path):
    client = _client(
        monkeypatch, tmp_path, {"cfg_openai_base_url": "https://api.openai.com/v1", "cfg_openai_cloud_key": "saved-key"}
    )
    discover = MagicMock()
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)
    result = client.post("/api/ui/llm/models", json={"provider": "openai", "base_url": "https://other.invalid/v1"})
    assert result.status_code == 422
    discover.assert_not_called()


def test_new_lmstudio_endpoint_uses_no_saved_credential(monkeypatch, tmp_path):
    client = _client(
        monkeypatch, tmp_path, {"cfg_llm_endpoint": "http://localhost:1234/v1", "cfg_openai_key": "saved-key"}
    )
    discover = MagicMock(return_value=[])
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)
    result = client.post("/api/ui/llm/models", json={"provider": "lmstudio", "base_url": "http://localhost:1235/v1"})
    assert result.status_code == 200
    assert discover.call_args.kwargs["api_key"] == ""


def test_model_discovery_uses_the_environment_key_only_for_its_own_origin(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    discover = MagicMock(return_value=[])
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    assert client.post("/api/ui/llm/models", json={"provider": "openai"}).status_code == 200
    discover.assert_called_once_with("openai", base_url="https://api.openai.com/v1", api_key="sk-env")

    discover.reset_mock()
    moved = client.post("/api/ui/llm/models", json={"provider": "openai", "base_url": "https://other.example/v1"})
    assert moved.status_code == 422 and moved.json()["detail"] == "openai_api_key_required"
    discover.assert_not_called()


def test_lmstudio_discovery_withholds_the_environment_key_from_another_host(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("LMSTUDIO_API_KEY", "lm-env-secret")
    monkeypatch.setenv("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
    discover = MagicMock(return_value=[])
    monkeypatch.setattr(web_app, "_discover_llm_models", discover)

    client.post("/api/ui/llm/models", json={"provider": "lmstudio", "base_url": "http://localhost:1234/v1"})
    assert discover.call_args.kwargs["api_key"] == "lm-env-secret"
    client.post("/api/ui/llm/models", json={"provider": "lmstudio", "base_url": "http://192.168.1.9:1234/v1"})
    assert discover.call_args.kwargs["api_key"] == ""  # keyless local use still works


ACCEPTED_MODEL_HOSTS = [
    "http://localhost:1234/v1",
    "http://127.0.0.1:1234/v1",
    "http://[::1]:1234/v1",
    "http://host.docker.internal:1234/v1",
    "http://192.168.1.9:1234/v1",
    "http://10.0.0.5/v1",
    "http://172.16.4.4:8080/v1",
    "http://[::ffff:192.168.1.9]:1234/v1",
    "http://[fd00::1]:1234/v1",
    "https://api.openai.com/v1",
    "https://8.8.8.8/v1",
    "https://3com.example/v1",
    "https://0x.example/v1",
    "https://123.example.com/v1",
]
REJECTED_MODEL_HOSTS = [
    "http://169.254.169.254/latest",
    "http://[fe80::1]/v1",
    "http://0.0.0.0/v1",
    "http://[::]/v1",
    "http://224.0.0.1/v1",
    "http://[::ffff:169.254.169.254]/",
    "http://[::ffff:a9fe:a9fe]/",
    "http://[::ffff:0.0.0.0]/",
    "http://2852039166/",
    "http://0xa9fea9fe/",
    "http://0XA9FEA9FE/",
    "http://025177524776/",
    "http://169.254.43518/",
    "http://169.16689662/",
    "http://0251.0376.0251.0376/",
    "http://0xa9.0xfe.0xa9.0xfe/",
    "http://169.254.169.254./",
    "http://127.1/",
    "http://0/",
    "http://1.2.3.4.5/",
]


def test_model_base_url_host_table():
    import pytest
    from fastapi import HTTPException

    for url in ACCEPTED_MODEL_HOSTS:
        assert web_app._validated_model_base_url(url) == url, url
    for url in REJECTED_MODEL_HOSTS:
        with pytest.raises(HTTPException) as caught:
            web_app._validated_model_base_url(url)
        assert (caught.value.status_code, caught.value.detail) == (422, "invalid_model_api_url"), url
