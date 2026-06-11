"""Tests for OSINT provider connectivity probes (probe_providers).

All HTTP traffic is mocked — these tests must never hit the network.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import requests

from app.pipeline.osint import (
    PROBE_RESULT_INVALID_KEY,
    PROBE_RESULT_NO_KEY,
    PROBE_RESULT_OK,
    PROBE_RESULT_RATE_LIMITED,
    PROBE_RESULT_UNREACHABLE,
    probe_providers,
)

ALL_KEYS = {
    "GREYNOISE_KEY": "gn-key",
    "ABUSEIPDB_KEY": "ab-key",
    "VT_KEY": "vt-key",
    "SHODAN_KEY": "sh-key",
    "OTX_KEY": "otx-key",
}

EXPECTED_PROVIDERS = {"GreyNoise", "AbuseIPDB", "VirusTotal", "Shodan", "OTX"}


def _mock_response(status_code: int = 200, json_body: dict | None = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    if json_body is not None:
        resp.json.return_value = json_body
        resp.text = json.dumps(json_body)
    else:
        resp.json.side_effect = ValueError("no json body")
        resp.text = text
    return resp


def _patched_session(mock_get):
    session = MagicMock()
    session.get = mock_get
    return patch("app.pipeline.osint._get_session", return_value=session)


class TestProbeProviders:
    def test_all_providers_ok_and_deduped(self):
        get = MagicMock(return_value=_mock_response(200, {"status": "ok"}))
        with _patched_session(get):
            results = probe_providers(ALL_KEYS)

        # One row per UI provider — vt is deduped across IP and domain defs
        assert {r["provider"] for r in results} == EXPECTED_PROVIDERS
        assert len(results) == len(EXPECTED_PROVIDERS)
        assert all(r["status"] == PROBE_RESULT_OK for r in results)
        assert get.call_count == len(EXPECTED_PROVIDERS)

    def test_invalid_key_on_401_and_403(self):
        for code in (401, 403):
            get = MagicMock(return_value=_mock_response(code, {"message": "bad key"}))
            with _patched_session(get):
                results = probe_providers(ALL_KEYS)
            assert all(r["status"] == PROBE_RESULT_INVALID_KEY for r in results), f"HTTP {code}"

    def test_rate_limited_surfaces_body_detail(self):
        # Real GreyNoise community 429 body shape
        body = {
            "plan": "Community",
            "rate_limit": "25-W",
            "message": "You have exceeded your provisioned rate limit.",
        }
        get = MagicMock(return_value=_mock_response(429, body))
        with _patched_session(get):
            results = probe_providers(ALL_KEYS)

        gn = next(r for r in results if r["provider"] == "GreyNoise")
        assert gn["status"] == PROBE_RESULT_RATE_LIMITED
        assert "Community" in gn["detail"]
        assert "exceeded your provisioned rate limit" in gn["detail"]

    def test_rate_limited_non_json_body_falls_back_to_text(self):
        get = MagicMock(return_value=_mock_response(429, None, text="Too Many Requests"))
        with _patched_session(get):
            results = probe_providers(ALL_KEYS)
        assert all(r["status"] == PROBE_RESULT_RATE_LIMITED for r in results)
        assert all("Too Many Requests" in r["detail"] for r in results)

    def test_network_error_maps_to_unreachable(self):
        get = MagicMock(side_effect=requests.ConnectionError("connection refused"))
        with _patched_session(get):
            results = probe_providers(ALL_KEYS)
        assert all(r["status"] == PROBE_RESULT_UNREACHABLE for r in results)

    def test_missing_keys_report_no_key_without_network_calls(self):
        get = MagicMock()
        with _patched_session(get):
            results = probe_providers({})
        assert {r["provider"] for r in results} == EXPECTED_PROVIDERS
        assert all(r["status"] == PROBE_RESULT_NO_KEY for r in results)
        get.assert_not_called()

    def test_partial_keys_mix_no_key_and_ok(self):
        get = MagicMock(return_value=_mock_response(200, {"status": "ok"}))
        with _patched_session(get):
            results = probe_providers({"VT_KEY": "vt-key"})

        by_provider = {r["provider"]: r["status"] for r in results}
        assert by_provider["VirusTotal"] == PROBE_RESULT_OK
        for provider in EXPECTED_PROVIDERS - {"VirusTotal"}:
            assert by_provider[provider] == PROBE_RESULT_NO_KEY
        assert get.call_count == 1

    def test_one_failing_probe_does_not_stop_others(self):
        responses = [
            requests.ConnectionError("dns failure"),  # first provider blows up
            _mock_response(200, {}),
            _mock_response(200, {}),
            _mock_response(200, {}),
            _mock_response(200, {}),
        ]
        get = MagicMock(side_effect=responses)
        with _patched_session(get):
            results = probe_providers(ALL_KEYS)

        statuses = [r["status"] for r in results]
        assert statuses.count(PROBE_RESULT_UNREACHABLE) == 1
        assert statuses.count(PROBE_RESULT_OK) == 4

    def test_unexpected_http_status_maps_to_unreachable_with_code(self):
        get = MagicMock(return_value=_mock_response(503, None, text="upstream down"))
        with _patched_session(get):
            results = probe_providers(ALL_KEYS)
        assert all(r["status"] == PROBE_RESULT_UNREACHABLE for r in results)
        assert all("503" in r["detail"] for r in results)

    def test_probe_substitutes_key_and_indicator(self):
        get = MagicMock(return_value=_mock_response(200, {}))
        with _patched_session(get):
            probe_providers(ALL_KEYS)

        urls = [call.args[0] if call.args else call.kwargs.get("url", "") for call in get.call_args_list]
        # IP providers probe with the benign IP, domain providers with the benign domain
        assert any("8.8.8.8" in u for u in urls)
        assert any("google.com" in u for u in urls)

        # The GreyNoise call carries the key in headers (template "__KEY__" substituted)
        gn_call = next(c for c in get.call_args_list if "greynoise" in (c.args[0] if c.args else ""))
        assert gn_call.kwargs["headers"]["key"] == "gn-key"
        assert "__KEY__" not in str(gn_call.kwargs)

    def test_probe_passes_timeout(self):
        get = MagicMock(return_value=_mock_response(200, {}))
        with _patched_session(get):
            probe_providers(ALL_KEYS, timeout=5.0)
        assert all(call.kwargs.get("timeout") == 5.0 for call in get.call_args_list)
