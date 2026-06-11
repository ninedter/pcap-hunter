import re
import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock openai module BEFORE importing app.llm.client
mock_openai_module = MagicMock()
sys.modules["openai"] = mock_openai_module

# Now we can import the client
from app.llm.client import fetch_models


class TestLLMClient(unittest.TestCase):
    @patch("app.llm.client.OpenAI")
    def test_fetch_models_success(self, mock_openai_cls):
        # Setup the mock client returned by OpenAI constructor
        mock_client_instance = MagicMock()
        mock_openai_cls.return_value = mock_client_instance

        # Mock models.list() response
        mock_model_1 = MagicMock()
        mock_model_1.id = "model-a"
        mock_model_2 = MagicMock()
        mock_model_2.id = "model-b"

        # models.list() returns an iterable
        mock_client_instance.models.list.return_value = [mock_model_1, mock_model_2]

        models = fetch_models("http://test", "key")

        # Verify OpenAI was called with correct args (bare URLs are normalized to carry /v1)
        mock_openai_cls.assert_called_once()
        call_kwargs = mock_openai_cls.call_args
        self.assertEqual(call_kwargs.kwargs.get("base_url"), "http://test/v1")
        self.assertEqual(call_kwargs.kwargs.get("api_key"), "key")
        self.assertEqual(models, ["model-a", "model-b"])

    @patch("app.llm.client.OpenAI")
    def test_fetch_models_failure(self, mock_openai_cls):
        # Setup exception
        mock_openai_cls.side_effect = Exception("Connection error")
        models = fetch_models("http://test", "key")
        self.assertEqual(models, [])  # Should return empty list on error

    @patch("app.llm.client.OpenAI")
    def test_generate_report(self, mock_openai_cls):
        # Import inside test to avoid early import issues with mocks
        from app.llm.client import generate_report

        # Mock client
        mock_client_instance = MagicMock()
        mock_openai_cls.return_value = mock_client_instance

        # Mock completions.create
        mock_completion = MagicMock()
        mock_completion.choices = [MagicMock(message=MagicMock(content="Section Content"))]
        mock_client_instance.chat.completions.create.return_value = mock_completion

        # Call generate_report
        context = {"features": {}, "osint": {}, "zeek": {}, "packet_count": 100}
        report = generate_report("http://test", "key", "model-x", context, language="US English")

        # Verify calls - Should be called 9 times (once per section, incl. IOC Summary)
        self.assertEqual(mock_client_instance.chat.completions.create.call_count, 9)

        # Verify output concatenation
        # Logic appends "## Title\n\nContent" for each section
        self.assertIn("## Executive Summary", report)
        self.assertIn("## IOC Summary", report)
        self.assertIn("Section Content", report)
        # Just checking basic structure
        self.assertTrue(report.startswith("## Executive Summary"))


def _production_context() -> dict:
    """Production-shape LLM context: real dataclasses, not lookalike dicts.

    flow_asymmetry/port_anomalies carry the actual FlowAsymmetryResult /
    PortAnomalyResult dataclasses main.py stores in session state, and
    correlations carry CorrelationResult with nested CorrelationSignal.
    """
    from app.analysis.correlation import CorrelationResult, CorrelationSignal
    from app.analysis.flow_analysis import FlowAsymmetryResult, PortAnomalyResult

    return {
        "features": {
            "flows": [
                {
                    "src": "10.0.0.5",
                    "dst": "34.12.37.224",
                    "sport": 55004,
                    "dport": 6888,
                    "proto": "TCP",
                    "count": 1200,
                    "bytes": 524288,
                },
            ],
            "artifacts": {"ips": ["34.12.37.224"], "domains": ["evil.example"], "urls": [], "hashes": [], "ja3": []},
        },
        "osint": {
            "ips": {
                "34.12.37.224": {
                    "vt": {"data": {"attributes": {"reputation": -12, "last_analysis_stats": {"malicious": 5}}}},
                    "ptr": "c2.bad.example",
                    "country": "Czechia",
                    "city": "Prague",
                },
            },
            "domains": {},
        },
        "zeek": {},
        "beaconing": [{"src": "10.0.0.5", "dst": "34.12.37.224", "dport": 6888, "score": 0.96, "count": 120}],
        "packet_count": 5234,
        "correlations": [
            CorrelationResult(
                indicator="34.12.37.224",
                indicator_type="ip",
                signals=[
                    CorrelationSignal("vt_detections", -12, 0.12, "virustotal"),
                    CorrelationSignal("beacon_score", 0.96, 0.96, "beacon"),
                ],
                composite_score=0.85,
                verdict="critical",
            ),
        ],
        "flow_asymmetry": [
            FlowAsymmetryResult(
                src="10.0.0.5",
                dst="34.12.37.224",
                outbound_bytes=52_000_000,
                inbound_bytes=400_000,
                ratio=130.0,
                total_packets=4200,
                score=0.9,
                is_suspicious=True,
                reason="130:1 outbound ratio",
            ),
            FlowAsymmetryResult(
                src="10.0.0.6",
                dst="1.1.1.1",
                outbound_bytes=1000,
                inbound_bytes=900,
                ratio=1.1,
                total_packets=10,
                score=0.0,
                is_suspicious=False,
                reason="",
            ),
        ],
        "port_anomalies": [
            PortAnomalyResult(
                src="10.0.0.5",
                dst="34.12.37.224",
                port=4444,
                proto="tcp",
                anomaly_type="c2_port",
                expected_service="",
                score=0.8,
                reason="Known C2 framework port 4444",
            ),
        ],
        "ja3_analysis": {
            "total_tls_sessions": 40,
            "unique_ja3": 6,
            "malware_detected": True,
            "malware_ja3": [
                {
                    "ja3": "6734f37431670b3ab4292b8f60f29984",
                    "ja3_client": "Trickbot",
                    "src": "10.0.0.5",
                    "dst": "34.12.37.224",
                },
            ],
            "unknown_ja3": 2,
            "top_clients": {"Chrome": 20, "Trickbot": 4},
        },
        "rdns_map": {"34.12.37.224": "c2.bad.example", "142.250.204.110": "syd09s25.1e100.net"},
    }


def _capture_section_prompts(context: dict, language: str = "US English"):
    """Run generate_report with a mocked client; return (report, {title: user_prompt}, system_prompt)."""
    from app.llm import client as llm_client

    with patch.object(llm_client, "OpenAI") as mock_openai:
        completion = MagicMock()
        completion.choices = [MagicMock(message=MagicMock(content="Body"))]
        mock_openai.return_value.chat.completions.create.return_value = completion
        report = llm_client.generate_report("http://test", "key", "model-x", context, language=language)
        calls = mock_openai.return_value.chat.completions.create.call_args_list

    prompts: dict[str, str] = {}
    system_prompt = ""
    for call in calls:
        messages = call.kwargs["messages"]
        system_prompt = messages[0]["content"]
        user = messages[1]["content"]
        m = re.search(r"Write ONLY the body content for the '([^']+)' section", user)
        assert m, f"section prompt missing title preamble: {user[:120]}"
        prompts[m.group(1)] = user
    return report, prompts, system_prompt


RISK_TABLE_HEADER = "| Category | Key Findings | Likelihood | Impact | Risk |"
IOC_TABLE_HEADER = "| Indicator | Type | Verdict | Score | Key Signals |"


class TestRiskMatrixTableInstruction(unittest.TestCase):
    """The Risk Assessment section must demand a real GFM table, in every language."""

    def test_risk_section_contains_exact_table_header(self):
        _, prompts, _ = _capture_section_prompts(_production_context())
        risk = prompts["Risk Assessment"]
        self.assertIn(RISK_TABLE_HEADER, risk)
        self.assertIn("|---|---|---|---|---|", risk)
        self.assertIn("None observed", risk)
        self.assertIn("| Network / C2 |", risk)
        self.assertIn("| Data Exposure |", risk)

    def test_translated_risk_instruction_still_carries_table_spec(self):
        # Static translations replace the English instruction wholesale; the
        # fallback must re-append the table spec for non-English reports.
        _, prompts, _ = _capture_section_prompts(_production_context(), language="Tradition Chinese (zh-tw)")
        risk = prompts["風險評估"]
        self.assertIn(RISK_TABLE_HEADER, risk)
        self.assertIn("|---|---|---|---|---|", risk)


class TestIOCSummarySection(unittest.TestCase):
    """Every report ends with a copy-paste IOC table grounded in correlations."""

    def test_ioc_summary_is_final_section_with_table_header(self):
        report, prompts, _ = _capture_section_prompts(_production_context())
        self.assertIn("IOC Summary", prompts)
        ioc = prompts["IOC Summary"]
        self.assertIn(IOC_TABLE_HEADER, ioc)
        # Real correlation data quoted for the model — indicator + signal names
        self.assertIn("34.12.37.224", ioc)
        self.assertIn("beacon_score", ioc)
        self.assertIn("critical", ioc)
        # Wired in after Recommended Actions
        self.assertLess(report.index("## Recommended Actions"), report.index("## IOC Summary"))

    def test_ioc_summary_empty_correlations_instructs_none_row(self):
        context = {"features": {}, "osint": {}, "zeek": {}, "packet_count": 10}
        _, prompts, _ = _capture_section_prompts(context)
        ioc = prompts["IOC Summary"]
        self.assertIn(IOC_TABLE_HEADER, ioc)
        self.assertIn("| None | - | - | - | No scored indicators |", ioc)


class TestEvidenceGrounding(unittest.TestCase):
    """Anti-hallucination rules + new evidence blocks wired into section prompts."""

    def test_system_prompt_contains_grounding_rules(self):
        from app.llm.client import SYSTEM_INSTRUCTIONS

        self.assertIn("Use ONLY facts present in the DATA blocks", SYSTEM_INSTRUCTIONS)
        self.assertIn("Never invent indicators, counts,", SYSTEM_INSTRUCTIONS)
        self.assertIn("Quote indicator values verbatim", SYSTEM_INSTRUCTIONS)
        self.assertIn("state that no findings were observed", SYSTEM_INSTRUCTIONS)
        # The no-heading-echo instruction must remain intact alongside the new rules
        _, prompts, system_prompt = _capture_section_prompts(_production_context())
        self.assertIn("Use ONLY facts present in the DATA blocks", system_prompt)
        self.assertIn("Do NOT include the section title", prompts["Executive Summary"])

    def test_flow_asymmetry_wired_into_beacon_section(self):
        _, prompts, _ = _capture_section_prompts(_production_context())
        beacon = prompts["Beaconing / C2 Analysis"]
        self.assertIn("Flow asymmetry", beacon)
        self.assertIn('"mb_out":52.0', beacon)  # compact JSON, MB out/in + ratio
        self.assertIn('"ratio":130.0', beacon)
        self.assertIn("34.12.37.224", beacon)
        self.assertIn("exfiltration", beacon.lower())
        # Non-suspicious pairs must not be fed to the model
        self.assertNotIn("1.1.1.1", beacon)

    def test_port_anomalies_wired_into_beacon_section(self):
        _, prompts, _ = _capture_section_prompts(_production_context())
        beacon = prompts["Beaconing / C2 Analysis"]
        self.assertIn("Port anomalies", beacon)
        self.assertIn("4444", beacon)
        self.assertIn("c2_port", beacon)

    def test_ja3_wired_into_dns_tls_section(self):
        _, prompts, _ = _capture_section_prompts(_production_context())
        dns_tls = prompts["DNS & TLS Analysis"]
        self.assertIn("JA3", dns_tls)
        self.assertIn("6734f37431670b3ab4292b8f60f29984", dns_tls)
        self.assertIn("Trickbot", dns_tls)

    def test_host_identities_wired_into_executive_summary(self):
        _, prompts, _ = _capture_section_prompts(_production_context())
        exec_summary = prompts["Executive Summary"]
        self.assertIn("host_identities", exec_summary)
        self.assertIn("c2.bad.example", exec_summary)
        self.assertIn("Prague, Czechia", exec_summary)

    def test_recommended_actions_cites_real_top_threat_iocs(self):
        _, prompts, _ = _capture_section_prompts(_production_context())
        actions = prompts["Recommended Actions"]
        self.assertIn("34.12.37.224", actions)
        self.assertIn("VERBATIM", actions)

    def test_absent_evidence_leaves_sections_clean(self):
        # No flow asymmetry / port anomalies / ja3 → no fabricated discussion hooks
        context = {"features": {}, "osint": {}, "zeek": {}, "packet_count": 10}
        _, prompts, _ = _capture_section_prompts(context)
        beacon = prompts["Beaconing / C2 Analysis"]
        self.assertNotIn("Flow asymmetry", beacon)
        self.assertNotIn("Port anomalies", beacon)
        self.assertNotIn("JA3 TLS client fingerprints", prompts["DNS & TLS Analysis"])


class TestStripDuplicateHeading(unittest.TestCase):
    """The LLM sometimes echoes the section title; _strip_duplicate_heading removes it."""

    def setUp(self):
        from app.llm.client import _strip_duplicate_heading

        self.strip = _strip_duplicate_heading
        self.aliases = {"Executive Summary"}

    def test_plain_title_stripped(self):
        content = "Executive Summary\n\nBody text starts here."
        result = self.strip(content, self.aliases)
        self.assertEqual(result, "Body text starts here.")

    def test_bold_title_stripped(self):
        content = "**Executive Summary**\n\nBody text."
        self.assertEqual(self.strip(content, self.aliases), "Body text.")

    def test_markdown_h2_stripped(self):
        content = "## Executive Summary\n\nBody text."
        self.assertEqual(self.strip(content, self.aliases), "Body text.")

    def test_markdown_h1_stripped(self):
        content = "# Executive Summary\n\nBody text."
        self.assertEqual(self.strip(content, self.aliases), "Body text.")

    def test_leading_blanks_skipped(self):
        content = "\n\nExecutive Summary\n\nBody text."
        self.assertEqual(self.strip(content, self.aliases), "Body text.")

    def test_case_insensitive(self):
        content = "executive SUMMARY\n\nBody."
        self.assertEqual(self.strip(content, self.aliases), "Body.")

    def test_translated_alias_stripped(self):
        content = "摘要\n\n報告內容"
        result = self.strip(content, {"Executive Summary", "摘要"})
        self.assertEqual(result, "報告內容")

    def test_no_match_passes_through(self):
        content = "The captured traffic shows...\n\nMore details."
        self.assertEqual(self.strip(content, self.aliases), content)

    def test_empty_content(self):
        self.assertEqual(self.strip("", self.aliases), "")

    def test_only_heading_returns_empty(self):
        # If the entire content is just the heading, return empty (edge case)
        self.assertEqual(self.strip("## Executive Summary", self.aliases), "")


class TestProbeTimeouts:
    def test_test_connection_sets_timeout(self):
        from app.llm import client as llm_client

        with patch.object(llm_client, "OpenAI") as mock_openai:
            mock_openai.return_value.chat.completions.create.return_value = MagicMock()
            llm_client.test_connection("http://localhost:1234/v1", "", "test-model")
        assert mock_openai.call_args.kwargs.get("timeout") == 15.0

    def test_fetch_models_sets_timeout(self):
        from app.llm import client as llm_client

        mock_model = MagicMock()
        mock_model.id = "model-a"

        with patch.object(llm_client, "OpenAI") as mock_openai:
            mock_openai.return_value.models.list.return_value = [mock_model]
            result = llm_client.fetch_models("http://localhost:1234/v1", "")
        assert mock_openai.call_args.kwargs.get("timeout") == 15.0
        assert result == ["model-a"]


class TestNormalizeBaseUrl:
    """The OpenAI SDK appends /chat/completions to base_url verbatim, so a bare
    host:port URL must gain /v1 or LM Studio rejects the request."""

    def test_bare_host_port_gets_v1(self):
        from app.llm.client import _normalize_base_url

        assert _normalize_base_url("http://localhost:1234") == "http://localhost:1234/v1"

    def test_trailing_slash_stripped_then_v1_appended(self):
        from app.llm.client import _normalize_base_url

        assert _normalize_base_url("http://h:1234/") == "http://h:1234/v1"

    def test_existing_v1_path_unchanged(self):
        from app.llm.client import _normalize_base_url

        assert _normalize_base_url("http://h:1234/v1") == "http://h:1234/v1"

    def test_existing_custom_path_unchanged(self):
        from app.llm.client import _normalize_base_url

        assert _normalize_base_url("http://h:1234/api/v0") == "http://h:1234/api/v0"

    def test_empty_string_passes_through(self):
        from app.llm.client import _normalize_base_url

        assert _normalize_base_url("") == ""

    def test_test_connection_passes_normalized_url_to_openai(self):
        from app.llm import client as llm_client

        with patch.object(llm_client, "OpenAI") as mock_openai:
            mock_openai.return_value.chat.completions.create.return_value = MagicMock()
            llm_client.test_connection("http://host.docker.internal:1234", "", "test-model")
        assert mock_openai.call_args.kwargs.get("base_url") == "http://host.docker.internal:1234/v1"

    def test_fetch_models_passes_normalized_url_to_openai(self):
        from app.llm import client as llm_client

        mock_model = MagicMock()
        mock_model.id = "model-a"

        with patch.object(llm_client, "OpenAI") as mock_openai:
            mock_openai.return_value.models.list.return_value = [mock_model]
            llm_client.fetch_models("http://localhost:1234", "")
        assert mock_openai.call_args.kwargs.get("base_url") == "http://localhost:1234/v1"

    def test_generate_report_passes_normalized_url_to_openai(self):
        from app.llm import client as llm_client

        with patch.object(llm_client, "OpenAI") as mock_openai:
            mock_completion = MagicMock()
            mock_completion.choices = [MagicMock(message=MagicMock(content="Body"))]
            mock_openai.return_value.chat.completions.create.return_value = mock_completion
            context = {"features": {}, "osint": {}, "zeek": {}, "packet_count": 1}
            llm_client.generate_report("http://localhost:1234", "key", "model-x", context)
        assert mock_openai.call_args.kwargs.get("base_url") == "http://localhost:1234/v1"


if __name__ == "__main__":
    unittest.main()
