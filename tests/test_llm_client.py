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

        # Verify OpenAI was called with correct args
        mock_openai_cls.assert_called_once()
        call_kwargs = mock_openai_cls.call_args
        self.assertEqual(call_kwargs.kwargs.get("base_url"), "http://test")
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

        # Verify calls - Should be called 8 times (once per section)
        self.assertEqual(mock_client_instance.chat.completions.create.call_count, 8)

        # Verify output concatenation
        # Logic appends "## Title\n\nContent" for each section
        self.assertIn("## Executive Summary", report)
        self.assertIn("Section Content", report)
        # Should have 8 sections * (Header + Content)
        # Just checking basic structure
        self.assertTrue(report.startswith("## Executive Summary"))


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


if __name__ == "__main__":
    unittest.main()
