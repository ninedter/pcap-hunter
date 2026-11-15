"""OSINT enrichment: rate-limit retry, circuit breaker, domain cap, cache setting, IPv6."""

from __future__ import annotations

import json
import sys
import threading
from unittest.mock import MagicMock

import pandas as pd
import pytest

from app import config as C
from app.analysis.visibility import build_capture_metrics
from app.pipeline import osint
from app.pipeline.dns_analysis import analyze_dns
from app.pipeline.osint import (
    ProviderGuard,
    _j,
    _j_with_retry,
    _retry_after_seconds,
    enrich,
    flagged_domains_from_dns,
    prioritize_domains,
    provider_status,
    resolve_cache_enabled,
)
from app.pipeline.osint_cache import OSINTCache

KEYS = {"VT_KEY": "vt-key-12345", "OTX_KEY": "otx-key-12345", "SHODAN_KEY": "sh-key-12345"}


class FakeResponse:
    """requests.Response stand-in with real headers (MagicMock headers are not a Mapping)."""

    def __init__(self, status_code=200, body=None, headers=None, text=""):
        self.status_code = status_code
        self._body = body
        self.headers = dict(headers or {})
        self.text = text if body is None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("no json body")
        return self._body


class Router:
    """Thread-safe fake session.get that routes on URL substring and records calls."""

    def __init__(self, rules):
        self.rules = rules  # list of (substring, callable(url) -> FakeResponse)
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def get(self, url, headers=None, params=None, **_):
        with self._lock:
            self.calls.append(url)
        for needle, fn in self.rules:
            if needle in url:
                return fn(url)
        return FakeResponse(404, {"error": "unknown"})

    def count(self, needle: str) -> int:
        return sum(1 for u in self.calls if needle in u)


@pytest.fixture
def harness(monkeypatch, tmp_path):
    """Real OSINTCache on disk, no real sleeping, no real rDNS/GeoIP."""
    cache = OSINTCache(tmp_path / "osint_cache.db", ttl_hours=1, enabled=False)
    sleeps: list[float] = []
    monkeypatch.setattr(osint, "_get_cache", lambda: cache)
    monkeypatch.setattr(osint, "_sleep", sleeps.append)
    monkeypatch.setattr(osint.time, "sleep", lambda s: None)
    monkeypatch.setattr(osint, "resolve_ip", lambda ip: None)
    monkeypatch.setattr(osint.GeoIP, "lookup", classmethod(lambda cls, ip: None))

    def install(rules) -> Router:
        router = Router(rules)
        session = MagicMock()
        session.get = router.get
        monkeypatch.setattr(osint, "_get_session", lambda: session)
        return router

    return type("Harness", (), {"cache": cache, "sleeps": sleeps, "install": staticmethod(install)})


class TestRetryAfterParsing:
    def test_delta_seconds(self):
        assert _retry_after_seconds(FakeResponse(429, headers={"Retry-After": "7"})) == 7.0

    def test_http_date_in_the_past_is_zero(self):
        resp = FakeResponse(429, headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})
        assert _retry_after_seconds(resp) == 0.0

    def test_missing_or_garbage_is_none(self):
        assert _retry_after_seconds(FakeResponse(429)) is None
        assert _retry_after_seconds(FakeResponse(429, headers={"Retry-After": "soon"})) is None
        assert _retry_after_seconds(MagicMock()) is None  # mock headers must not explode

    def test_j_exposes_status_and_retry_after(self, harness):
        harness.install([("example", lambda u: FakeResponse(429, {"message": "slow down"}, {"Retry-After": "3"}))])
        result = _j("https://api.example.test/x")
        assert result["_error"] == "rate limited"
        assert result["_status"] == 429
        assert result["_retry_after"] == 3.0


class TestRetry:
    def test_429_then_success_honours_retry_after(self, harness):
        answers = iter([FakeResponse(429, {"message": "slow"}, {"Retry-After": "2"}), FakeResponse(200, {"ok": 1})])
        router = harness.install([("example", lambda u: next(answers))])
        guard = ProviderGuard()

        result = _j_with_retry("https://api.example.test/x", provider="vt", guard=guard)

        assert result == {"ok": 1}
        assert harness.sleeps == [2.0]
        assert len(router.calls) == 2
        assert guard.open_reason("vt") is None
        assert guard.snapshot()["vt"]["retries"] == 1

    def test_5xx_uses_exponential_backoff_then_gives_up(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_MAX_RETRIES", 2)
        monkeypatch.setattr(C, "OSINT_BACKOFF_BASE_SECONDS", 1.0)
        router = harness.install([("example", lambda u: FakeResponse(503, text="upstream down"))])
        guard = ProviderGuard()

        result = _j_with_retry("https://api.example.test/x", provider="shodan", guard=guard)

        assert result["_error"] == "HTTP 503"
        assert harness.sleeps == [1.0, 2.0]
        assert len(router.calls) == 3  # 1 + OSINT_MAX_RETRIES
        assert guard.snapshot()["shodan"]["server_errors"] == 1

    def test_retry_after_is_bounded(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_RETRY_AFTER_MAX_SECONDS", 30.0)
        router = harness.install(
            [("example", lambda u: FakeResponse(429, {"message": "daily quota"}, {"Retry-After": "86400"}))]
        )
        guard = ProviderGuard()

        result = _j_with_retry("https://api.example.test/x", provider="vt", guard=guard)

        assert result["_error"] == "rate limited"
        assert harness.sleeps == [], "must not sleep for an out-of-bounds Retry-After"
        assert len(router.calls) == 1
        assert "Retry-After 86400s" in guard.open_reason("vt")

    def test_auth_failure_and_404_are_not_retried(self, harness):
        for code in (401, 404):
            router = harness.install([("example", lambda u, c=code: FakeResponse(c, {"m": "x"}))])
            _j_with_retry("https://api.example.test/x", provider="vt", guard=ProviderGuard())
            assert len(router.calls) == 1, code
        assert harness.sleeps == []


class TestCircuitBreaker:
    def test_provider_is_skipped_after_repeated_429_and_recorded(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_MAX_RETRIES", 1)
        monkeypatch.setattr(C, "OSINT_BREAKER_THRESHOLD", 2)
        router = harness.install(
            [
                ("virustotal.com", lambda u: FakeResponse(429, {"message": "quota exceeded"})),
                ("otx.alienvault.com", lambda u: FakeResponse(200, {"pulse_info": {"count": 0}})),
            ]
        )
        domains = [f"d{i}.example.org" for i in range(6)]

        res = enrich({"ips": [], "domains": domains}, KEYS, cache_enabled=False)

        # 2 domains x (1 try + 1 retry) = 4 VT calls, then the breaker opens.
        assert router.count("virustotal.com") == 4
        assert router.count("otx.alienvault.com") == 6, "a healthy provider keeps being queried"

        health = res["provider_health"]["vt"]
        assert health["circuit_open"] is True
        assert health["rate_limited"] == 2
        assert health["skipped"] == 4
        assert "vt" in res["provider_health"] and "otx" not in res["provider_health"]
        assert any("VirusTotal disabled" in w for w in res["warnings"])

        skipped = res["domains"]["d5.example.org"]["vt"]
        assert skipped["_circuit_open"] is True and skipped["_skipped"] is True
        assert res["domains"]["d5.example.org"]["otx"] == {"pulse_info": {"count": 0}}
        # Existing health classification still reports the provider as rate limited.
        assert provider_status([d.get("vt") for d in res["domains"].values()]) == "rate_limited"

        metrics = build_capture_metrics({"features": {"flows": [], "artifacts": {}}, "osint": res})
        assert any("OSINT providers stopped answering" in lim and "vt" in lim for lim in metrics["limitations"])

    def test_success_resets_the_failure_streak(self):
        guard = ProviderGuard(threshold=2)
        guard.record_failure("vt", "rate_limited")
        guard.record_ok("vt")
        guard.record_failure("vt", "rate_limited")
        assert guard.open_reason("vt") is None
        guard.record_failure("vt", "rate_limited")
        assert guard.open_reason("vt")

    def test_breaker_is_per_run(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_MAX_RETRIES", 0)
        monkeypatch.setattr(C, "OSINT_BREAKER_THRESHOLD", 1)
        router = harness.install([("virustotal.com", lambda u: FakeResponse(503, text="down"))])
        keys = {"VT_KEY": "vt-key-12345"}
        enrich({"ips": [], "domains": ["a.example.org", "b.example.org"]}, keys, cache_enabled=False)
        assert router.count("virustotal.com") == 1
        res = enrich({"ips": [], "domains": ["c.example.org"]}, keys, cache_enabled=False)
        assert router.count("virustotal.com") == 2, "a new run must try the provider again"
        assert provider_status([res["domains"]["c.example.org"]["vt"]]) == "error"

    def test_clean_run_reports_no_health_issues(self, harness):
        harness.install([("", lambda u: FakeResponse(200, {"data": {}}))])
        res = enrich({"ips": ["8.8.8.8"], "domains": ["a.example.org"]}, KEYS, cache_enabled=False)
        assert res["provider_health"] == {}
        assert res["warnings"] == []
        assert set(res) >= {"ips", "domains", "ja3", "limits", "provider_health", "warnings"}


def _dns_log_frame() -> pd.DataFrame:
    """A Zeek dns.log table (JSON-log column names) with DGA-looking and ordinary queries."""
    dga = ["xkqzvbnmwrtp7.com", "qwzxjkvbpmtrl9.net", "zxcvbqwrtplkm3.org"]
    benign = [f"www{i}.example.com" for i in range(40)]
    rows = []
    for i, query in enumerate(benign + dga):
        rows.append(
            {
                "ts": 1700000000.0 + i,
                "uid": f"C{i}",
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 50000 + i,
                "id.resp_h": "10.0.0.1",
                "id.resp_p": 53,
                "proto": "udp",
                "query": query,
                "qtype_name": "A",
                "rcode_name": "NXDOMAIN" if query in dga else "NOERROR",
                "answers": [] if query in dga else ["93.184.216.34"],
                "TTLs": [] if query in dga else [300.0],
            }
        )
    return pd.DataFrame(rows)


class TestDomainCap:
    def test_default_cap_limits_domains_and_reports_it(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_MAX_DOMAINS_DEFAULT", 5)
        router = harness.install([("", lambda u: FakeResponse(200, {"data": {}}))])
        domains = [f"d{i:02d}.example.org" for i in range(12)]

        res = enrich({"ips": [], "domains": domains}, {"VT_KEY": "vt-key-12345"}, cache_enabled=False)

        assert list(res["domains"]) == domains[:5]
        assert router.count("virustotal.com") == 5
        assert res["limits"] == {"domain_cap": 5, "domains_total": 12, "domains_queried": 5, "domains_skipped": 7}
        assert any("queried 5 of 12 domains" in w for w in res["warnings"])

        metrics = build_capture_metrics({"features": {"flows": [], "artifacts": {}}, "osint": res})
        assert any("OSINT domain enrichment was capped: 5 of 12" in lim for lim in metrics["limitations"])

    def test_zero_means_no_cap(self, harness):
        harness.install([("", lambda u: FakeResponse(200, {"data": {}}))])
        domains = [f"d{i:03d}.example.org" for i in range(130)]
        res = enrich(
            {"ips": [], "domains": domains}, {"VT_KEY": "vt-key-12345"}, cache_enabled=False, max_domains=0, throttle=0
        )
        assert len(res["domains"]) == 130
        assert res["limits"]["domains_skipped"] == 0 and res["limits"]["domain_cap"] is None

    def test_dns_flagged_domains_survive_the_cap(self, harness):
        """Production shape: the real analyze_dns() output drives prioritisation."""
        dns_analysis = analyze_dns({"dns.log": _dns_log_frame()})
        flagged = flagged_domains_from_dns(dns_analysis)
        assert flagged, f"fixture should produce DGA detections, got keys {sorted(dns_analysis)}"
        assert set(flagged) <= {"xkqzvbnmwrtp7.com", "qwzxjkvbpmtrl9.net", "zxcvbqwrtplkm3.org"}

        harness.install([("", lambda u: FakeResponse(200, {"data": {}}))])
        domains = sorted(_dns_log_frame()["query"].tolist())  # alphabetical: DGA names sort last
        res = enrich(
            {"ips": [], "domains": domains},
            {"VT_KEY": "vt-key-12345"},
            cache_enabled=False,
            max_domains=len(flagged) + 2,
            dns_analysis=dns_analysis,
        )

        queried = list(res["domains"])
        assert queried[: len(flagged)] == [d for d in domains if d in set(flagged)]
        assert set(flagged) <= set(queried)
        assert len(queried) == len(flagged) + 2

    def test_prioritize_is_stable_and_handles_subdomains(self):
        domains = ["a.com", "x1.tunnel.net", "b.com", "tunnel.net", "x2.tunnel.net", "c.com"]
        assert prioritize_domains(domains, ["Tunnel.NET."]) == [
            "tunnel.net",
            "x1.tunnel.net",
            "x2.tunnel.net",
            "a.com",
            "b.com",
            "c.com",
        ]
        assert prioritize_domains(domains, []) == domains

    def test_flagged_domains_tolerates_missing_or_error_results(self):
        assert flagged_domains_from_dns(None) == []
        assert flagged_domains_from_dns({"error": "No DNS log data", "records": 0}) == []
        assert flagged_domains_from_dns({"dga_detections": [{"score": 0.9}, "junk", {"domain": "A.b"}]}) == ["a.b"]

    def test_previous_results_do_not_count_against_the_cap(self, harness):
        router = harness.install([("", lambda u: FakeResponse(200, {"data": {}}))])
        previous = {"ips": {}, "domains": {"old.example.org": {"vt": {"data": {"cached": True}}}}}
        res = enrich(
            {"ips": [], "domains": ["old.example.org", "new1.example.org", "new2.example.org"]},
            {"VT_KEY": "vt-key-12345"},
            cache_enabled=False,
            max_domains=1,
            previous_results=previous,
        )
        assert set(res["domains"]) == {"old.example.org", "new1.example.org"}
        assert router.count("virustotal.com") == 1
        assert res["limits"]["domains_total"] == 2 and res["limits"]["domains_skipped"] == 1


class TestCacheSetting:
    def test_explicit_parameter_wins(self):
        assert resolve_cache_enabled(True) is True
        assert resolve_cache_enabled(False) is False

    def test_headless_falls_back_to_saved_config(self, monkeypatch):
        import app.utils.config_manager as cm

        monkeypatch.setattr(osint, "streamlit_script_context_active", lambda: False)
        for saved in (True, False):
            manager = MagicMock()
            manager.get.return_value = saved
            monkeypatch.setattr(cm, "get_config_manager", lambda m=manager: m)
            assert resolve_cache_enabled(None) is saved
            manager.get.assert_called_once_with("cfg_osint_cache_enabled", False)

    def test_unreadable_config_defaults_to_off(self, monkeypatch):
        import app.utils.config_manager as cm

        def boom():
            raise ValueError("Saved credentials cannot be decrypted")

        monkeypatch.setattr(osint, "streamlit_script_context_active", lambda: False)
        monkeypatch.setattr(cm, "get_config_manager", boom)
        assert resolve_cache_enabled(None) is False

    def test_streamlit_session_used_only_with_a_live_script_context(self, monkeypatch):
        import app.utils.config_manager as cm

        manager = MagicMock()
        manager.get.return_value = False
        monkeypatch.setattr(cm, "get_config_manager", lambda: manager)
        monkeypatch.setattr(osint, "streamlit_session_state", lambda: {"cfg_osint_cache_enabled": True})

        monkeypatch.setattr(osint, "streamlit_script_context_active", lambda: True)
        assert resolve_cache_enabled(None) is True
        monkeypatch.setattr(osint, "streamlit_script_context_active", lambda: False)
        assert resolve_cache_enabled(None) is False, "a bare-mode session must not be trusted"

    def test_enabled_cache_is_used_from_provider_threads(self, harness):
        """The setting is resolved once per run; pool threads must not switch it back off."""
        router = harness.install([("", lambda u: FakeResponse(200, {"data": {"rep": 1}}))])
        keys = {"VT_KEY": "vt-key-12345"}
        arts = {"ips": [], "domains": ["a.example.org", "b.example.org"]}

        first = enrich(arts, keys, cache_enabled=True)
        assert harness.cache.enabled is True
        assert router.count("virustotal.com") == 2

        second = enrich(arts, keys, cache_enabled=True)
        assert router.count("virustotal.com") == 2, "second run must be served from the cache"
        assert second["domains"]["a.example.org"]["vt"]["_cached"] is True
        assert first["domains"]["a.example.org"]["vt"] == {"data": {"rep": 1}}

    def test_disabled_cache_always_queries(self, harness):
        router = harness.install([("", lambda u: FakeResponse(200, {"data": {}}))])
        keys = {"VT_KEY": "vt-key-12345"}
        arts = {"ips": [], "domains": ["a.example.org"]}
        enrich(arts, keys, cache_enabled=False)
        enrich(arts, keys, cache_enabled=False)
        assert router.count("virustotal.com") == 2
        assert harness.cache.enabled is False

    def test_get_cache_does_not_read_streamlit_per_query(self, monkeypatch, tmp_path):
        cache = OSINTCache(tmp_path / "c.db", ttl_hours=1, enabled=True)
        monkeypatch.setattr(osint, "_cache", cache)
        fake_st = MagicMock()
        fake_st.session_state = {"cfg_osint_cache_enabled": False}
        monkeypatch.setitem(sys.modules, "streamlit", fake_st)
        assert osint._get_cache() is cache
        assert cache.enabled is True, "_get_cache must not flip the enabled flag"


class TestIPv6:
    def test_public_ipv6_is_enriched_and_private_is_not(self, harness):
        router = harness.install([("", lambda u: FakeResponse(200, {"data": {}}))])
        ips = ["2001:4860:4860::8888", "fe80::1", "fd00::5", "10.0.0.5", "8.8.8.8", "224.0.0.251"]
        res = enrich({"ips": ips, "domains": []}, {"VT_KEY": "vt-key-12345"}, cache_enabled=False)
        assert set(res["ips"]) == {"2001:4860:4860::8888", "8.8.8.8"}
        # the address is URL-encoded into the path (no raw ':' injection)
        assert any("2001%3A4860%3A4860%3A%3A8888" in url for url in router.calls)


class _Phase:
    """PhaseHandle stand-in (set/done/should_skip), as the runner and UI supply it."""

    def __init__(self, skip_when=lambda: False):
        self._skip_when = skip_when
        self.messages: list[str] = []

    def set(self, percent: int, message: str = "") -> None:
        self.messages.append(message)

    def done(self, message: str = "Done") -> None:
        self.messages.append(message)

    def should_skip(self) -> bool:
        return bool(self._skip_when())


class TestSleepBudget:
    def test_alternating_success_and_429_opens_the_breaker_once_the_budget_is_spent(self, harness, monkeypatch):
        """Success resets the failure streak, so only the sleep budget can stop this provider."""
        monkeypatch.setattr(C, "OSINT_MAX_RETRIES", 2)
        monkeypatch.setattr(C, "OSINT_BREAKER_THRESHOLD", 3)
        monkeypatch.setattr(C, "OSINT_PROVIDER_SLEEP_BUDGET_SECONDS", 120.0)
        throttled = FakeResponse(429, {"message": "slow down"}, {"Retry-After": "30"})

        def virustotal(url):
            # Every other domain is answered; the rest are throttled on every attempt.
            index = int(url.rsplit("/d", 1)[1].split(".", 1)[0])
            return FakeResponse(200, {"data": {}}) if index % 2 == 0 else throttled

        router = harness.install(
            [("virustotal.com", virustotal), ("otx.alienvault.com", lambda u: FakeResponse(200, {"pulse_info": {}}))]
        )
        domains = [f"d{i}.example.org" for i in range(12)]

        res = enrich({"ips": [], "domains": domains}, KEYS, cache_enabled=False, max_domains=0)

        # d1 and d3 each sleep 2 x 30 s = the whole 120 s budget; d5 trips the breaker
        # on its first throttled answer instead of sleeping again.
        assert sum(harness.sleeps) == 120.0
        health = res["provider_health"]["vt"]
        assert health["circuit_open"] is True and "backoff budget of 120s" in health["reason"]
        assert health["skipped"] == 6  # d6..d11 were never sent
        assert res["domains"]["d11.example.org"]["vt"]["_circuit_open"] is True
        assert router.count("virustotal.com") == 3 + 3 + 3 + 1  # d0,d2,d4 + d1 x3 + d3 x3 + d5 x1
        assert router.count("otx.alienvault.com") == 12, "the healthy provider is unaffected"
        assert any("VirusTotal disabled" in w for w in res["warnings"])

    def test_budget_is_per_provider_and_per_run(self, harness, monkeypatch):
        guard = ProviderGuard(sleep_budget=10)
        assert guard.reserve_sleep("vt", 6, "rate_limited") is True
        assert guard.reserve_sleep("otx", 6, "rate_limited") is True  # separate budget
        assert guard.reserve_sleep("vt", 6, "rate_limited") is False
        assert "backoff budget of 10s" in guard.open_reason("vt") and guard.open_reason("otx") is None
        assert ProviderGuard(sleep_budget=10).reserve_sleep("vt", 6, "rate_limited") is True  # a new run starts over
        assert ProviderGuard().sleep_budget == C.OSINT_PROVIDER_SLEEP_BUDGET_SECONDS == 120.0

    def test_backoff_sleep_is_interrupted_by_a_phase_skip(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_SLEEP_SLICE_SECONDS", 0.5)
        router = harness.install([("example", lambda u: FakeResponse(429, {"message": "slow"}, {"Retry-After": "30"}))])
        # The analyst presses "skip" two seconds into the 30-second wait.
        guard = ProviderGuard(should_skip=lambda: sum(harness.sleeps) >= 2.0)

        result = _j_with_retry("https://api.example.test/x", provider="vt", guard=guard)

        assert result["_error"] == "rate limited"
        assert harness.sleeps == [0.5, 0.5, 0.5, 0.5], "sliced, and stopped as soon as the skip was seen"
        assert len(router.calls) == 1, "no further attempt after a skip"

    def test_enrich_hands_the_phase_skip_check_to_the_backoff(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_SLEEP_SLICE_SECONDS", 0.5)
        router = harness.install(
            [("virustotal.com", lambda u: FakeResponse(429, {"message": "slow"}, {"Retry-After": "30"}))]
        )
        phase = _Phase(skip_when=lambda: sum(harness.sleeps) >= 1.0)

        enrich(
            {"ips": [], "domains": ["a.example.org", "b.example.org"]},
            {"VT_KEY": "vt-key-12345"},
            phase=phase,
            cache_enabled=False,
        )

        assert harness.sleeps == [0.5, 0.5]  # not 30 s, and not 60 s for the retries
        assert router.count("virustotal.com") == 1  # the second domain is never queried

    def test_unskipped_phase_still_sleeps_the_full_delay_in_slices(self, harness, monkeypatch):
        monkeypatch.setattr(C, "OSINT_SLEEP_SLICE_SECONDS", 0.5)
        answers = iter([FakeResponse(429, {"message": "slow"}, {"Retry-After": "2"}), FakeResponse(200, {"ok": 1})])
        harness.install([("example", lambda u: next(answers))])
        guard = ProviderGuard(should_skip=lambda: False)

        assert _j_with_retry("https://api.example.test/x", provider="vt", guard=guard) == {"ok": 1}
        assert harness.sleeps == [0.5, 0.5, 0.5, 0.5]

    def test_a_raising_skip_check_never_breaks_a_lookup(self, harness):
        def broken() -> bool:
            raise RuntimeError("no script context in this thread")

        answers = iter([FakeResponse(503, text="down"), FakeResponse(200, {"ok": 1})])
        harness.install([("example", lambda u: next(answers))])
        result = _j_with_retry("https://api.example.test/x", provider="vt", guard=ProviderGuard(should_skip=broken))
        assert result == {"ok": 1}
