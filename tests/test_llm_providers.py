"""Tests for the multi-provider LLM dispatch (app/llm/providers.py).

All backends are mocked — no test touches the network. The ``anthropic`` and
``openai`` SDKs are stubbed in ``sys.modules`` before importing the module under
test (the real packages may not be installed in CI), with real exception
subclasses so the error-handling branches can be exercised.
"""

import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


# --- Stub anthropic SDK with real exception classes ------------------------
class _FakeAnthropicError(Exception):
    pass


class _FakeAuthError(_FakeAnthropicError):
    pass


class _FakeRateLimitError(_FakeAnthropicError):
    pass


class _FakeAPIStatusError(_FakeAnthropicError):
    pass


_fake_anthropic = MagicMock()
_fake_anthropic.AuthenticationError = _FakeAuthError
_fake_anthropic.RateLimitError = _FakeRateLimitError
_fake_anthropic.APIStatusError = _FakeAPIStatusError
_fake_anthropic.APIError = _FakeAnthropicError
sys.modules["anthropic"] = _fake_anthropic

# openai is also stubbed (client.py imports it at module load)
sys.modules.setdefault("openai", MagicMock())

from app.llm import providers as P  # noqa: E402
from app.llm.context_window import estimate_messages  # noqa: E402


def _text_block(text: str):
    return SimpleNamespace(type="text", text=text)


def _min_context() -> dict:
    return {"features": {}, "osint": {}, "zeek": {}, "packet_count": 7}


class TestProviderConstants(unittest.TestCase):
    def test_provider_ids_and_tuple(self):
        self.assertEqual(P.PROVIDER_LMSTUDIO, "lmstudio")
        self.assertEqual(P.PROVIDER_OPENAI, "openai")
        self.assertEqual(P.PROVIDER_ANTHROPIC, "anthropic")
        self.assertEqual(P.PROVIDERS, ("lmstudio", "openai", "anthropic"))

    def test_anthropic_models_default_first(self):
        self.assertEqual(P.ANTHROPIC_MODELS[0], "claude-opus-4-8")
        self.assertIn("claude-sonnet-4-6", P.ANTHROPIC_MODELS)
        self.assertIn("claude-haiku-4-5", P.ANTHROPIC_MODELS)
        # Complete ids — no date suffixes
        for m in P.ANTHROPIC_MODELS:
            self.assertNotRegex(m, r"-\d{8}$")

    def test_provider_label(self):
        self.assertEqual(P.provider_label("anthropic"), "Anthropic")
        self.assertEqual(P.provider_label("openai"), "OpenAI")
        self.assertEqual(P.provider_label("lmstudio"), "LM Studio")
        self.assertEqual(P.provider_label("unknown"), "unknown")


class TestSingleShotPrompt(unittest.TestCase):
    """The single-shot prompt carries grounding rules + the required tables."""

    def test_system_prompt_keeps_grounding_and_sets_attribution_boundaries(self):
        sysp = P.SINGLE_SHOT_SYSTEM
        self.assertIn("Use ONLY facts present in the DATA blocks", sysp)
        self.assertIn("Quote indicator values verbatim", sysp)
        self.assertIn("do not enrich the report", sysp)
        self.assertIn("Use ATT&CK IDs only from attack_mapping", sysp)
        self.assertIn("hypotheses", sysp)

    def test_user_prompt_has_risk_matrix_and_ioc_summary(self):
        prompt = P.build_single_shot_prompt(_min_context(), "US English")
        self.assertIn("| Category | Key Findings | Likelihood | Impact | Risk |", prompt)
        self.assertIn("| Indicator | Type | Verdict | Score | Key Signals |", prompt)
        self.assertIn("IOC Summary", prompt)
        # All ordered sections referenced
        for section in P._SINGLE_SHOT_SECTIONS:
            self.assertIn(section, prompt)

    def test_user_prompt_carries_coverage_and_attribution_evidence(self):
        ctx = _min_context()
        ctx["capture_metrics"] = {
            "detectors": {"zeek": "unavailable", "dns": "available"},
            "visibility_gaps": ["zeek"],
            "limitations": ["Zeek protocol logs are unavailable."],
        }
        ctx["attack_mapping"] = {
            "attack_version": "19.1",
            "techniques": [
                {
                    "technique_id": "T1071.004",
                    "technique_name": "DNS",
                    "tactic": "command-and-control",
                    "confidence": 0.6,
                    "evidence": ["DNS tunneling indicators"],
                    "limitations": ["Network evidence is a hypothesis."],
                }
            ],
        }

        prompt = P.build_single_shot_prompt(ctx)

        self.assertIn("[analysis_scope]", prompt)
        self.assertIn('"zeek":"unavailable"', prompt)
        self.assertIn("[attack_mapping]", prompt)
        self.assertIn("T1071.004", prompt)
        self.assertIn("Network evidence is a hypothesis.", prompt)

    def test_user_prompt_quotes_real_indicators(self):
        # Production-shape correlation → indicator must appear verbatim in DATA.
        from app.analysis.correlation import CorrelationResult, CorrelationSignal

        ctx = _min_context()
        ctx["correlations"] = [
            CorrelationResult(
                indicator="45.33.32.156",
                indicator_type="ip",
                signals=[CorrelationSignal("beacon_score", 0.9, 0.9, "beacon")],
                composite_score=0.91,
                verdict="critical",
            )
        ]
        prompt = P.build_single_shot_prompt(ctx, "US English")
        self.assertIn("45.33.32.156", prompt)
        self.assertIn("beacon_score", prompt)

    def test_language_instruction_traditional_chinese(self):
        prompt = P.build_single_shot_prompt(_min_context(), "Tradition Chinese (zh-tw)")
        self.assertIn("Traditional Chinese", prompt)
        self.assertIn("Taiwan", prompt)

    def test_larger_context_window_includes_more_evidence(self):
        ctx = _min_context()
        ctx["features"] = {
            "flows": [{"src": f"10.0.0.{i}", "dst": "198.51.100.10", "proto": "TCP", "count": i} for i in range(1, 401)]
        }

        local_prompt = P.build_single_shot_prompt(ctx, context_window_tokens=10_000)
        frontier_prompt = P.build_single_shot_prompt(ctx, context_window_tokens=1_000_000)

        self.assertGreater(len(frontier_prompt), len(local_prompt))
        self.assertNotIn("10.0.0.300", local_prompt)
        self.assertIn("10.0.0.300", frontier_prompt)

    def test_unlimited_context_includes_all_rows_even_with_10k_slider(self):
        ctx = _min_context()
        ctx["features"] = {
            "flows": [{"src": f"10.0.0.{i}", "dst": "198.51.100.10", "proto": "TCP"} for i in range(1, 401)]
        }

        prompt = P.build_single_shot_prompt(ctx, context_window_tokens=10_000, unlimited_context=True)

        self.assertIn("10.0.0.400", prompt)


class TestSynthesizeDispatch(unittest.TestCase):
    """synthesize_report routes to the correct backend per provider."""

    def test_lmstudio_dispatches_to_chunked_generate_report(self):
        with patch.object(P._client, "generate_report", return_value="## chunked") as gen:
            out = P.synthesize_report(
                P.PROVIDER_LMSTUDIO,
                base_url="http://localhost:1234",
                api_key="lm",
                model="local",
                context=_min_context(),
                language="US English",
            )
        gen.assert_called_once()
        # Positional signature: (base_url, api_key, model, context)
        args = gen.call_args.args
        self.assertEqual(args[0], "http://localhost:1234")
        self.assertEqual(args[2], "local")
        self.assertEqual(gen.call_args.kwargs["context_window_tokens"], 32_000)
        self.assertEqual(out, "## chunked")

    def test_lmstudio_unlimited_uses_one_full_context_request(self):
        with (
            patch.object(P._client, "generate_report") as chunked,
            patch.object(P, "_synthesize_openai", return_value="## full context") as single,
        ):
            out = P.synthesize_report(
                P.PROVIDER_LMSTUDIO,
                base_url="http://localhost:1234",
                api_key="lm",
                model="local",
                context=_min_context(),
                unlimited_context=True,
            )

        chunked.assert_not_called()
        single.assert_called_once()
        self.assertTrue(single.call_args.kwargs["unlimited_context"])
        self.assertTrue(single.call_args.kwargs["local_compatible"])
        self.assertEqual(out, "## full context")

    def test_openai_makes_one_call_not_n_sections(self):
        fake_openai = MagicMock()
        completion = MagicMock()
        completion.choices = [MagicMock(message=MagicMock(content="## Executive Summary\n\nbody"))]
        fake_openai.return_value.chat.completions.create.return_value = completion

        with patch.dict(sys.modules, {"openai": MagicMock(OpenAI=fake_openai)}):
            out = P.synthesize_report(
                P.PROVIDER_OPENAI,
                base_url="",
                api_key="sk-test",
                model="gpt-4o",
                context=_min_context(),
                language="US English",
            )
        # Exactly ONE call — single-shot, not 9 section calls
        self.assertEqual(fake_openai.return_value.chat.completions.create.call_count, 1)
        call = fake_openai.return_value.chat.completions.create.call_args
        self.assertEqual(call.kwargs["model"], "gpt-4o")
        self.assertEqual(call.kwargs["temperature"], 0.0)
        # System + user messages
        self.assertEqual(len(call.kwargs["messages"]), 2)
        self.assertEqual(call.kwargs["messages"][0]["role"], "system")
        # The legitimate first section heading must survive post-processing
        self.assertIn("Executive Summary", out)

    def test_openai_prompt_and_output_respect_10k_window(self):
        fake_openai = MagicMock()
        completion = MagicMock()
        completion.choices = [MagicMock(message=MagicMock(content="## Executive Summary\n\nbody"))]
        fake_openai.return_value.chat.completions.create.return_value = completion
        ctx = _min_context()
        ctx["features"] = {"flows": [{"src": "10.0.0.1", "dst": "198.51.100.1", "blob": "x" * 1000}] * 500}

        with patch.dict(sys.modules, {"openai": MagicMock(OpenAI=fake_openai)}):
            P.synthesize_report(
                P.PROVIDER_OPENAI,
                base_url="",
                api_key="sk-test",
                model="gpt-4o",
                context=ctx,
                context_window_tokens=10_000,
            )

        call = fake_openai.return_value.chat.completions.create.call_args
        messages = call.kwargs["messages"]
        self.assertLessEqual(estimate_messages(messages[0]["content"], messages[1]["content"]), 5_000)
        self.assertEqual(call.kwargs["max_tokens"], 5_000)

    def test_openai_unlimited_does_not_truncate_or_cap_output(self):
        fake_openai = MagicMock()
        completion = MagicMock()
        completion.choices = [MagicMock(message=MagicMock(content="## Executive Summary\n\nbody"))]
        fake_openai.return_value.chat.completions.create.return_value = completion
        ctx = _min_context()
        ctx["features"] = {
            "flows": [{"src": f"10.0.0.{i}", "dst": "198.51.100.1", "blob": "x" * 1000} for i in range(1, 101)]
        }

        with patch.dict(sys.modules, {"openai": MagicMock(OpenAI=fake_openai)}):
            P.synthesize_report(
                P.PROVIDER_OPENAI,
                base_url="",
                api_key="sk-test",
                model="gpt-4o",
                context=ctx,
                context_window_tokens=10_000,
                unlimited_context=True,
            )

        call = fake_openai.return_value.chat.completions.create.call_args
        messages = call.kwargs["messages"]
        self.assertGreater(estimate_messages(messages[0]["content"], messages[1]["content"]), 5_000)
        self.assertIn("10.0.0.100", messages[1]["content"])
        self.assertEqual(call.kwargs["max_tokens"], 32_000)

    def test_single_shot_postprocess_strips_report_title_keeps_sections(self):
        # A redundant document title before the first `## Executive Summary`
        # should be stripped, but the section heading must remain.
        raw = "# Threat Hunting Report\n\n## Executive Summary\n\nThe capture shows..."
        cleaned = P._postprocess_single_shot(raw)
        self.assertNotIn("# Threat Hunting Report", cleaned)
        self.assertTrue(cleaned.startswith("## Executive Summary"))

    def test_single_shot_postprocess_strips_enclosing_code_fence(self):
        raw = "```markdown\n## Executive Summary\n\nbody\n```"
        cleaned = P._postprocess_single_shot(raw)
        self.assertTrue(cleaned.startswith("## Executive Summary"))
        self.assertNotIn("```", cleaned)

    def test_openai_blank_base_url_uses_sdk_default(self):
        fake_openai = MagicMock()
        completion = MagicMock()
        completion.choices = [MagicMock(message=MagicMock(content="body"))]
        fake_openai.return_value.chat.completions.create.return_value = completion

        with patch.dict(sys.modules, {"openai": MagicMock(OpenAI=fake_openai)}):
            P.synthesize_report(
                P.PROVIDER_OPENAI,
                base_url="",
                api_key="sk",
                model="gpt-4o",
                context=_min_context(),
                language="US English",
            )
        # blank base_url → no base_url kwarg passed (SDK default endpoint)
        self.assertNotIn("base_url", fake_openai.call_args.kwargs)

    def test_anthropic_constructs_official_client_and_streams(self):
        # Streaming context manager returning a final message with text blocks
        final_msg = SimpleNamespace(content=[_text_block("## Executive Summary\n\nThreat report body.")])
        stream_cm = MagicMock()
        stream_cm.__enter__.return_value.get_final_message.return_value = final_msg
        stream_cm.__exit__.return_value = False

        anth_client = MagicMock()
        anth_client.messages.stream.return_value = stream_cm
        _fake_anthropic.Anthropic.reset_mock()
        _fake_anthropic.Anthropic.return_value = anth_client

        out = P.synthesize_report(
            P.PROVIDER_ANTHROPIC,
            base_url="",
            api_key="ak-test",
            model="claude-opus-4-8",
            context=_min_context(),
            language="US English",
        )

        # Official anthropic.Anthropic was constructed with the api key
        _fake_anthropic.Anthropic.assert_called_once()
        self.assertEqual(_fake_anthropic.Anthropic.call_args.kwargs.get("api_key"), "ak-test")

        # messages.stream called with the model + correct thinking/effort kwargs
        stream_kwargs = anth_client.messages.stream.call_args.kwargs
        self.assertEqual(stream_kwargs["model"], "claude-opus-4-8")
        self.assertEqual(stream_kwargs["thinking"], {"type": "adaptive"})
        self.assertEqual(stream_kwargs["output_config"], {"effort": "high"})
        # Forbidden sampling params must NOT be sent
        self.assertNotIn("temperature", stream_kwargs)
        self.assertNotIn("top_p", stream_kwargs)
        self.assertNotIn("top_k", stream_kwargs)
        self.assertNotIn("budget_tokens", stream_kwargs)
        # max_tokens present and large
        self.assertGreaterEqual(stream_kwargs["max_tokens"], 16000)

        self.assertIn("Threat report body.", out)

    def test_anthropic_joins_multiple_text_blocks(self):
        final_msg = SimpleNamespace(
            content=[
                _text_block("## Executive Summary\n\nPart one. "),
                SimpleNamespace(type="thinking", thinking="ignored"),
                _text_block("Part two."),
            ]
        )
        stream_cm = MagicMock()
        stream_cm.__enter__.return_value.get_final_message.return_value = final_msg
        stream_cm.__exit__.return_value = False
        anth_client = MagicMock()
        anth_client.messages.stream.return_value = stream_cm
        _fake_anthropic.Anthropic.reset_mock()
        _fake_anthropic.Anthropic.return_value = anth_client

        out = P.synthesize_report(
            P.PROVIDER_ANTHROPIC,
            base_url="",
            api_key="ak",
            model="claude-opus-4-8",
            context=_min_context(),
            language="US English",
        )
        # Both text blocks joined; the thinking block excluded
        self.assertIn("Part one. Part two.", out)
        self.assertNotIn("ignored", out)

    def test_anthropic_auth_error_returns_graceful_string(self):
        anth_client = MagicMock()
        anth_client.messages.stream.side_effect = _FakeAuthError("bad key")
        _fake_anthropic.Anthropic.reset_mock()
        _fake_anthropic.Anthropic.return_value = anth_client

        out = P.synthesize_report(
            P.PROVIDER_ANTHROPIC,
            base_url="",
            api_key="bad",
            model="claude-opus-4-8",
            context=_min_context(),
            language="US English",
        )
        # No crash — graceful error string
        self.assertIsInstance(out, str)
        self.assertIn("authentication failed", out.lower())


class TestProbeProvider(unittest.TestCase):
    def test_probe_lmstudio_delegates_to_test_connection(self):
        with patch.object(P._client, "test_connection", return_value="") as tc:
            ok, msg = P.probe_provider(
                P.PROVIDER_LMSTUDIO, base_url="http://localhost:1234", api_key="lm", model="local"
            )
        tc.assert_called_once()
        self.assertTrue(tc.call_args.kwargs["local_compatible"])
        self.assertTrue(ok)

    def test_probe_openai_blank_url_uses_default_endpoint(self):
        with patch.object(P._client, "test_connection", return_value="") as tc:
            ok, _ = P.probe_provider(P.PROVIDER_OPENAI, base_url="", api_key="sk", model="gpt-4o")
        # Probe still hits the real default endpoint instead of erroring on no URL
        self.assertEqual(tc.call_args.args[0], "https://api.openai.com/v1")
        self.assertFalse(tc.call_args.kwargs["local_compatible"])
        self.assertTrue(ok)

    def test_probe_openai_error_returns_false(self):
        with patch.object(P._client, "test_connection", return_value="401 Unauthorized"):
            ok, msg = P.probe_provider(P.PROVIDER_OPENAI, base_url="", api_key="sk", model="gpt-4o")
        self.assertFalse(ok)
        self.assertIn("401", msg)

    def test_probe_anthropic_ok(self):
        anth_client = MagicMock()
        anth_client.messages.create.return_value = MagicMock()
        _fake_anthropic.Anthropic.reset_mock()
        _fake_anthropic.Anthropic.return_value = anth_client

        ok, msg = P.probe_provider(P.PROVIDER_ANTHROPIC, base_url="", api_key="ak", model="claude-opus-4-8")
        self.assertTrue(ok)
        # Tiny 16-token non-streaming ping
        create_kwargs = anth_client.messages.create.call_args.kwargs
        self.assertEqual(create_kwargs["max_tokens"], 16)
        self.assertEqual(create_kwargs["model"], "claude-opus-4-8")

    def test_probe_anthropic_missing_key_short_circuits(self):
        _fake_anthropic.Anthropic.reset_mock()
        ok, msg = P.probe_provider(P.PROVIDER_ANTHROPIC, base_url="", api_key="", model="claude-opus-4-8")
        self.assertFalse(ok)
        self.assertIn("Missing", msg)
        # No client constructed when key is absent
        _fake_anthropic.Anthropic.assert_not_called()

    def test_probe_anthropic_auth_failure_returns_false(self):
        anth_client = MagicMock()
        anth_client.messages.create.side_effect = _FakeAuthError("nope")
        _fake_anthropic.Anthropic.reset_mock()
        _fake_anthropic.Anthropic.return_value = anth_client

        ok, msg = P.probe_provider(P.PROVIDER_ANTHROPIC, base_url="", api_key="bad", model="claude-opus-4-8")
        self.assertFalse(ok)
        self.assertIn("Authentication failed", msg)


if __name__ == "__main__":
    unittest.main()
