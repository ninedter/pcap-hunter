"""Tests for the LLM Integration section of the Config tab (app/ui/config_ui.py).

Regression coverage for provider-scoped model pickers:
- "Fetch Models" under the OpenAI provider must populate a picker in the
  OpenAI section (and the chosen model must land in ``cfg_openai_model``).
- Models fetched for one provider must never appear in another provider's
  picker (the original bug: a shared ``available_models`` session key let
  OpenAI's fetched models show up in the LM Studio selectbox).

Uses Streamlit's AppTest harness; ``fetch_models`` is patched so no network
calls are made.
"""

from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from app.llm import providers as llm_providers

FAKE_OPENAI_MODELS = ["gpt-4.1", "gpt-4.1-mini", "o4-mini"]
FAKE_LM_MODELS = ["qwen2.5-7b-instruct", "llama-3.1-8b-instruct"]


def _llm_integration_app():
    from app.ui.config_ui import _render_llm_integration

    _render_llm_integration()


def _make_app() -> AppTest:
    return AppTest.from_function(_llm_integration_app, default_timeout=30)


def _select_provider(at: AppTest, provider: str) -> None:
    at.radio(key="widget_llm_provider").set_value(provider).run()


def _fetch_button(at: AppTest):
    buttons = [b for b in at.button if b.label == "Fetch Models"]
    assert len(buttons) == 1, f"expected exactly one Fetch Models button, found {len(buttons)}"
    return buttons[0]


def _pickers_with_options(at: AppTest, options: list[str]) -> list:
    return [sb for sb in at.selectbox if list(sb.options) == options]


class TestOpenAIModelPicker:
    def test_fetch_populates_openai_picker(self):
        at = _make_app()
        at.run()
        _select_provider(at, llm_providers.PROVIDER_OPENAI)

        with patch("app.ui.config_ui.fetch_models", return_value=list(FAKE_OPENAI_MODELS)):
            _fetch_button(at).click().run()

        pickers = _pickers_with_options(at, FAKE_OPENAI_MODELS)
        assert pickers, "OpenAI section must render a model picker listing the fetched models"
        assert at.session_state["cfg_openai_model"] == FAKE_OPENAI_MODELS[0]

    def test_fetched_model_can_be_picked(self):
        at = _make_app()
        at.run()
        _select_provider(at, llm_providers.PROVIDER_OPENAI)

        with patch("app.ui.config_ui.fetch_models", return_value=list(FAKE_OPENAI_MODELS)):
            _fetch_button(at).click().run()

        pickers = _pickers_with_options(at, FAKE_OPENAI_MODELS)
        assert pickers, "OpenAI section must render a model picker listing the fetched models"
        pickers[0].select("o4-mini").run()
        assert at.session_state["cfg_openai_model"] == "o4-mini"

    def test_fetch_preselects_saved_model_when_in_list(self):
        at = _make_app()
        at.session_state["cfg_openai_model"] = "o4-mini"
        at.run()
        _select_provider(at, llm_providers.PROVIDER_OPENAI)

        with patch("app.ui.config_ui.fetch_models", return_value=list(FAKE_OPENAI_MODELS)):
            _fetch_button(at).click().run()

        pickers = _pickers_with_options(at, FAKE_OPENAI_MODELS)
        assert pickers, "OpenAI section must render a model picker listing the fetched models"
        assert pickers[0].value == "o4-mini"
        assert at.session_state["cfg_openai_model"] == "o4-mini"

    def test_without_fetch_falls_back_to_text_input(self):
        at = _make_app()
        at.run()
        _select_provider(at, llm_providers.PROVIDER_OPENAI)

        model_inputs = [ti for ti in at.text_input if ti.label == "Model"]
        assert model_inputs, "OpenAI section should offer a free-text model field before any fetch"


class TestProviderModelIsolation:
    def test_openai_fetch_does_not_leak_into_lmstudio_picker(self):
        at = _make_app()
        at.run()
        _select_provider(at, llm_providers.PROVIDER_OPENAI)

        with patch("app.ui.config_ui.fetch_models", return_value=list(FAKE_OPENAI_MODELS)):
            _fetch_button(at).click().run()

        _select_provider(at, llm_providers.PROVIDER_LMSTUDIO)
        leaked = [sb for sb in at.selectbox if set(FAKE_OPENAI_MODELS) & set(sb.options)]
        assert not leaked, "OpenAI models leaked into the LM Studio model picker"
        model_inputs = [ti for ti in at.text_input if ti.label == "Model name"]
        assert model_inputs, "LM Studio should fall back to its free-text model field when it has no fetched models"

    def test_lmstudio_fetch_does_not_leak_into_openai_picker(self):
        at = _make_app()
        at.run()
        _select_provider(at, llm_providers.PROVIDER_LMSTUDIO)

        with patch("app.ui.config_ui.fetch_models", return_value=list(FAKE_LM_MODELS)):
            _fetch_button(at).click().run()

        _select_provider(at, llm_providers.PROVIDER_OPENAI)
        leaked = [sb for sb in at.selectbox if set(FAKE_LM_MODELS) & set(sb.options)]
        assert not leaked, "LM Studio models leaked into the OpenAI model picker"
        model_inputs = [ti for ti in at.text_input if ti.label == "Model"]
        assert model_inputs, "OpenAI should fall back to its free-text model field when it has no fetched models"


class TestLMStudioModelPicker:
    def test_fetch_populates_lmstudio_picker(self):
        at = _make_app()
        at.run()
        _select_provider(at, llm_providers.PROVIDER_LMSTUDIO)

        with patch("app.ui.config_ui.fetch_models", return_value=list(FAKE_LM_MODELS)):
            _fetch_button(at).click().run()

        pickers = _pickers_with_options(at, FAKE_LM_MODELS)
        assert pickers, "LM Studio section must render a model picker listing the fetched models"
        assert at.session_state["cfg_lm_model"] == FAKE_LM_MODELS[0]
