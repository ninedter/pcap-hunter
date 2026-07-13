"""Tests for OSINT provider plumbing: response classification (_j), negative-result
caching (_cached_query), aggregated health (provider_status), and connectivity
probes (probe_providers).

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
    _cached_query,
    _j,
    enrich,
    probe_providers,
    provider_status,
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


class TestJResponseClassification:
    """_j must distinguish clean negatives (404) from real provider failures."""

    URL = "https://api.example.test/lookup/1.2.3.4"

    def _call(self, response) -> dict:
        get = MagicMock(return_value=response)
        with _patched_session(get):
            return _j(self.URL)

    def test_200_returns_json_payload(self):
        result = self._call(_mock_response(200, {"ports": [443]}))
        assert result == {"ports": [443]}

    def test_200_non_json_returns_raw_text(self):
        result = self._call(_mock_response(200, None, text="plain body"))
        assert result == {"_raw": "plain body"}

    def test_404_is_nodata_not_error(self):
        # Shodan answers 404 for IPs it never scanned; VT/OTX for unknown domains.
        result = self._call(_mock_response(404, {"error": "No information available"}))
        assert result == {"_nodata": True, "_url": self.URL}
        assert "_error" not in result

    def test_401_and_403_map_to_auth_failed(self):
        for code in (401, 403):
            result = self._call(_mock_response(code, {"message": "bad key"}))
            assert result["_error"] == f"auth failed (HTTP {code})", f"HTTP {code}"
            assert result["_url"] == self.URL

    def test_429_maps_to_rate_limited_with_body_detail(self):
        body = {"plan": "Community", "message": "You have exceeded your provisioned rate limit."}
        result = self._call(_mock_response(429, body))
        assert result["_error"] == "rate limited"
        assert "Community" in result["_detail"]
        assert "exceeded your provisioned rate limit" in result["_detail"]

    def test_other_status_maps_to_generic_http_error(self):
        result = self._call(_mock_response(503, None, text="upstream down"))
        assert result["_error"] == "HTTP 503"

    def test_network_exception_maps_to_error(self):
        get = MagicMock(side_effect=requests.ConnectionError("connection refused"))
        with _patched_session(get):
            result = _j(self.URL)
        assert "connection refused" in result["_error"]


class TestCachedQueryNegativeCaching:
    """_cached_query must cache clean negatives (_nodata) but never _error results."""

    def _run(self, fresh_result: dict) -> MagicMock:
        cache = MagicMock()
        cache.get.return_value = None  # always a cache miss
        with patch("app.pipeline.osint._get_cache", return_value=cache):
            result = _cached_query("1.2.3.4", "shodan", lambda: fresh_result)
        assert result == fresh_result
        return cache

    def test_success_payload_is_cached(self):
        cache = self._run({"ports": [22, 443]})
        cache.set.assert_called_once_with("1.2.3.4", "shodan", {"ports": [22, 443]})

    def test_nodata_result_is_cached(self):
        # Repeated 404 lookups burn quota for indicators the provider will never know.
        nodata = {"_nodata": True, "_url": "https://api.example.test/x"}
        cache = self._run(nodata)
        cache.set.assert_called_once_with("1.2.3.4", "shodan", nodata)

    def test_error_result_is_not_cached(self):
        cache = self._run({"_error": "rate limited", "_detail": "plan exceeded", "_url": "u"})
        cache.set.assert_not_called()

    def test_cache_hit_marks_result_cached(self):
        cache = MagicMock()
        cache.get.return_value = {"_nodata": True, "_url": "u"}
        query_fn = MagicMock()
        with patch("app.pipeline.osint._get_cache", return_value=cache):
            result = _cached_query("1.2.3.4", "shodan", query_fn)
        assert result["_cached"] is True
        assert result["_nodata"] is True
        query_fn.assert_not_called()


class TestProviderStatus:
    """Aggregated health: ok > rate_limited > auth_failed > error > nodata > none."""

    OK = {"ports": [443]}
    NODATA = {"_nodata": True, "_url": "u"}
    RATE_LIMITED = {"_error": "rate limited", "_detail": "plan exceeded", "_url": "u"}
    AUTH_FAILED = {"_error": "auth failed (HTTP 401)", "_url": "u"}
    GENERIC_ERROR = {"_error": "HTTP 503", "_url": "u"}

    def test_empty_list_is_none(self):
        assert provider_status([]) == "none"

    def test_all_none_entries_is_none(self):
        assert provider_status([None, None]) == "none"

    def test_none_input_is_none(self):
        assert provider_status(None) == "none"

    def test_single_success_is_ok(self):
        assert provider_status([self.OK]) == "ok"

    def test_ok_beats_everything(self):
        results = [self.NODATA, self.RATE_LIMITED, self.AUTH_FAILED, self.GENERIC_ERROR, self.OK]
        assert provider_status(results) == "ok"

    def test_one_404_among_successes_is_still_ok(self):
        # The original bug: one sampled 404 painted the whole provider ❌.
        assert provider_status([self.NODATA, self.OK, self.OK]) == "ok"

    def test_nodata_only_is_nodata(self):
        assert provider_status([self.NODATA, self.NODATA]) == "nodata"

    def test_cached_nodata_is_still_nodata(self):
        cached = dict(self.NODATA, _cached=True)
        assert provider_status([cached]) == "nodata"

    def test_mixed_nodata_and_error_is_error(self):
        assert provider_status([self.NODATA, self.GENERIC_ERROR]) == "error"

    def test_mixed_ok_and_rate_limited_is_ok(self):
        assert provider_status([self.RATE_LIMITED, self.OK]) == "ok"

    def test_rate_limited_beats_auth_failed_and_error(self):
        assert provider_status([self.GENERIC_ERROR, self.AUTH_FAILED, self.RATE_LIMITED]) == "rate_limited"

    def test_auth_failed_beats_generic_error(self):
        assert provider_status([self.GENERIC_ERROR, self.AUTH_FAILED]) == "auth_failed"

    def test_generic_error_beats_nodata(self):
        assert provider_status([self.GENERIC_ERROR, self.NODATA, None]) == "error"

    def test_empty_dict_counts_as_success(self):
        # A 200 with an empty JSON body is still a successful provider answer.
        assert provider_status([{}, self.NODATA]) == "ok"


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


class TestEnrichDomainFiltering:
    """enrich() must not leak internal/private domain names to third-party OSINT
    providers (VirusTotal, OTX) — only public, routable domains get queried."""

    def _run(self, artifacts: dict) -> tuple[dict, list[str]]:
        queried: list[str] = []

        def fake_query_providers(indicator, providers, keys):
            queried.append(indicator)
            # cache_hits=1 so enrich() doesn't sleep(throttle) between calls.
            return {"_raw": "ok"}, 1

        cache = MagicMock()
        with (
            patch("app.pipeline.osint._get_cache", return_value=cache),
            patch("app.pipeline.osint._query_providers", side_effect=fake_query_providers),
        ):
            result = enrich(artifacts, keys={})
        return result, queried

    def test_internal_domain_is_never_queried(self):
        result, queried = self._run({"ips": [], "domains": ["evil.com", "dc01.internal.corp"]})
        assert queried == ["evil.com"]
        assert "evil.com" in result["domains"]
        assert "dc01.internal.corp" not in result["domains"]

    def test_all_internal_domains_means_no_queries(self):
        result, queried = self._run({"ips": [], "domains": ["printer.local", "host.lan"]})
        assert queried == []
        assert result["domains"] == {}
