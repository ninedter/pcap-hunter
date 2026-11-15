from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote

from app import config as C
from app.pipeline.geoip import GeoIP
from app.pipeline.osint_cache import get_osint_cache
from app.pipeline.progress import PhaseHandle
from app.security.opsec import hardened_session
from app.utils.common import resolve_ip
from app.utils.logger import streamlit_script_context_active, streamlit_session_state
from app.utils.network_utils import is_public_ip

logger = logging.getLogger(__name__)

# Indirection so tests can observe/skip backoff sleeps without patching time globally.
_sleep = time.sleep

# Thread-local storage for per-thread HTTP sessions (connection pooling is
# per-session and requests.Session is not thread-safe).
_thread_local = threading.local()


def _get_session():
    """Get or create a thread-local hardened HTTP session."""
    if not hasattr(_thread_local, "session"):
        _thread_local.session = hardened_session(timeout=12)
    return _thread_local.session


# Global cache instance (lazy loaded)
_cache = None


def _get_cache():
    """Get or create the cache instance.

    The enabled flag is deliberately NOT touched here. This runs on every query,
    including from provider pool threads; it used to re-read
    ``st.session_state["cfg_osint_cache_enabled"]`` each time, which outside a live
    Streamlit script thread (API / agent workers, and those pool threads) silently
    reads an empty bare-mode session, returns the default ``False`` and switched
    the cache off. :func:`enrich` now resolves the setting once per run via
    :func:`resolve_cache_enabled`.
    """
    global _cache
    if _cache is None:
        _cache = get_osint_cache()
    return _cache


def resolve_cache_enabled(explicit: bool | None = None) -> bool:
    """Decide whether the OSINT response cache is on for this run.

    Resolution order:
        1. ``explicit`` — the caller's parameter, when not None.
        2. ``st.session_state["cfg_osint_cache_enabled"]`` — only when the calling
           thread really is inside a Streamlit script run.
        3. The persisted ``cfg_osint_cache_enabled`` config value (what headless
           API / agent workers get).
        4. ``False`` (the shipped default) if the config cannot be read.

    Args:
        explicit: Caller override; None means "look it up".

    Returns:
        True when responses should be read from / written to the cache.
    """
    if explicit is not None:
        return bool(explicit)
    if streamlit_script_context_active():
        state = streamlit_session_state()
        try:
            if state is not None and "cfg_osint_cache_enabled" in state:
                return bool(state["cfg_osint_cache_enabled"])
        except Exception:
            pass
    try:
        from app.utils.config_manager import get_config_manager

        return bool(get_config_manager().get("cfg_osint_cache_enabled", False))
    except Exception as e:
        logger.debug("OSINT cache setting unavailable from saved config: %s", e)
        return False


def _retry_after_seconds(response) -> float | None:
    """Parse a ``Retry-After`` header (delta-seconds or HTTP-date) into seconds."""
    headers = getattr(response, "headers", None)
    if not isinstance(headers, Mapping):
        return None
    raw = headers.get("Retry-After")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return max(0.0, float(raw))
    if not isinstance(raw, str) or not raw.strip():
        return None
    raw = raw.strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError, OverflowError):
        return None


class ProviderGuard:
    """Per-run, per-provider circuit breaker and failure tally (thread-safe).

    A provider that keeps answering 429 / 5xx is not going to recover within one
    enrichment run, and hammering it burns quota and wall-clock. After
    ``threshold`` consecutive indicators exhaust their retries the provider is
    "open": no further requests are sent to it this run, and each skipped lookup is
    recorded so the result can say the provider's coverage is incomplete.
    """

    def __init__(
        self,
        threshold: int | None = None,
        *,
        sleep_budget: float | None = None,
        should_skip: Callable[[], bool] | None = None,
    ) -> None:
        """Create the guard for one enrichment run.

        Args:
            threshold: Consecutive failed indicators that open a provider's breaker.
            sleep_budget: Total backoff seconds one provider may cost this run
                (default ``C.OSINT_PROVIDER_SLEEP_BUDGET_SECONDS``).
            should_skip: The phase's skip check; lets a backoff sleep be interrupted.
        """
        self.threshold = max(1, int(threshold if threshold is not None else C.OSINT_BREAKER_THRESHOLD))
        budget = C.OSINT_PROVIDER_SLEEP_BUDGET_SECONDS if sleep_budget is None else sleep_budget
        self.sleep_budget = max(0.0, float(budget))
        self.should_skip = should_skip
        self._slept: dict[str, float] = {}
        self._lock = threading.Lock()
        self._consecutive: dict[str, int] = {}
        self._open: dict[str, str] = {}
        self._open_kind: dict[str, str] = {}
        self._stats: dict[str, dict[str, int]] = {}
        self.network_calls = 0

    def _stat(self, provider: str) -> dict[str, int]:
        return self._stats.setdefault(provider, {"rate_limited": 0, "server_errors": 0, "retries": 0, "skipped": 0})

    def open_reason(self, provider: str) -> str | None:
        """Return why ``provider`` is disabled for this run, or None if it is usable."""
        with self._lock:
            return self._open.get(provider)

    def note_call(self) -> None:
        with self._lock:
            self.network_calls += 1

    def note_retry(self, provider: str) -> None:
        with self._lock:
            self._stat(provider)["retries"] += 1

    def note_skip(self, provider: str) -> None:
        with self._lock:
            self._stat(provider)["skipped"] += 1

    def record_ok(self, provider: str) -> None:
        """A non-throttled answer: the provider is healthy, reset its failure streak."""
        with self._lock:
            self._consecutive[provider] = 0

    def record_failure(self, provider: str, kind: str, *, trip_now: bool = False, detail: str = "") -> None:
        """Record one indicator that ended throttled (``rate_limited``) or 5xx (``server_errors``)."""
        with self._lock:
            self._stat(provider)[kind] += 1
            streak = self._consecutive.get(provider, 0) + 1
            self._consecutive[provider] = streak
            if provider in self._open or not (trip_now or streak >= self.threshold):
                return
            label = "rate limited" if kind == "rate_limited" else "server errors"
            reason = f"{label}: {detail}" if detail else f"{streak} consecutive lookups ended {label}"
            self._open[provider] = reason
            self._open_kind[provider] = kind
        logger.warning("OSINT provider %s disabled for the rest of this run: %s", provider, reason)

    def reserve_sleep(self, provider: str, delay: float, kind: str) -> bool:
        """Charge one backoff sleep to the provider's per-run budget.

        A provider that alternates successes with throttled answers resets its
        failure streak every time, so the streak alone never opens the breaker
        while each failing lookup still costs up to two full backoff sleeps. When
        the next sleep would exceed the budget the breaker opens instead.

        Args:
            provider: Breaker identity.
            delay: Seconds about to be slept.
            kind: ``rate_limited`` or ``server_errors`` (recorded if the breaker opens).

        Returns:
            True when the sleep may go ahead; False when the provider was disabled.
        """
        with self._lock:
            spent = self._slept.get(provider, 0.0)
            allowed = spent + delay <= self.sleep_budget
            if allowed:
                self._slept[provider] = spent + delay
        if not allowed:
            self.record_failure(
                provider,
                kind,
                trip_now=True,
                detail=f"retry backoff budget of {int(self.sleep_budget)}s for this run is used up",
            )
        return allowed

    def skip_requested(self) -> bool:
        """Whether the analyst asked to skip the phase (never raises)."""
        if self.should_skip is None:
            return False
        try:
            return bool(self.should_skip())
        except Exception:
            return False

    def open_kind(self, provider: str) -> str:
        with self._lock:
            return self._open_kind.get(provider, "rate_limited")

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Health summary for providers that had any trouble (empty when all were fine)."""
        with self._lock:
            out: dict[str, dict[str, Any]] = {}
            for provider in sorted(set(self._stats) | set(self._open)):
                stats = dict(self._stats.get(provider) or {})
                if not any(stats.values()) and provider not in self._open:
                    continue
                out[provider] = {
                    "circuit_open": provider in self._open,
                    "reason": self._open.get(provider, ""),
                    "rate_limited": stats.get("rate_limited", 0),
                    "server_errors": stats.get("server_errors", 0),
                    "retries": stats.get("retries", 0),
                    "skipped": stats.get("skipped", 0),
                }
            return out


def _circuit_open_result(provider: str, guard: ProviderGuard) -> dict:
    """Placeholder result for a lookup that was not sent because the breaker is open.

    The ``_error`` text keeps :func:`provider_status` classifying the provider as
    ``rate_limited`` (or ``error`` for 5xx) exactly as a live failure would.
    """
    reason = guard.open_reason(provider) or ""
    prefix = "rate limited" if guard.open_kind(provider) == "rate_limited" else "provider unavailable"
    return {
        "_error": f"{prefix}: skipped, provider disabled for this run",
        "_detail": reason,
        "_skipped": True,
        "_circuit_open": True,
    }


def _j_with_retry(url, headers=None, params=None, *, provider: str = "", guard: ProviderGuard | None = None) -> dict:
    """``_j`` plus bounded retry for throttling (429) and server errors (5xx).

    Honours ``Retry-After`` up to ``C.OSINT_RETRY_AFTER_MAX_SECONDS``; otherwise
    backs off exponentially. Every sleep is charged to the provider's per-run budget
    (``C.OSINT_PROVIDER_SLEEP_BUDGET_SECONDS``) and is interrupted by a phase skip.
    A ``Retry-After`` longer than ``C.OSINT_RETRY_AFTER_MAX_SECONDS`` means the quota
    will not come back during this run, so the provider's breaker is opened immediately
    instead of sleeping.

    Args:
        url: Request URL.
        headers: Request headers.
        params: Query parameters.
        provider: Provider name used for breaker accounting.
        guard: Per-run breaker; None disables breaker accounting (retries still apply).

    Returns:
        The provider payload or an ``_error`` / ``_nodata`` dict, as ``_j`` returns.
    """
    max_retries = max(0, int(C.OSINT_MAX_RETRIES))
    max_wait = float(C.OSINT_RETRY_AFTER_MAX_SECONDS)
    attempt = 0
    while True:
        if guard is not None:
            guard.note_call()
        result = _j(url, headers=headers, params=params)
        status = result.get("_status") if isinstance(result, dict) else None
        throttled = status == 429
        server_error = isinstance(status, int) and 500 <= status < 600
        if not (throttled or server_error):
            if guard is not None:
                guard.record_ok(provider)
            return result

        kind = "rate_limited" if throttled else "server_errors"
        retry_after = result.get("_retry_after")
        if isinstance(retry_after, (int, float)) and retry_after > max_wait:
            if guard is not None:
                guard.record_failure(
                    provider, kind, trip_now=True, detail=f"Retry-After {int(retry_after)}s exceeds {int(max_wait)}s"
                )
            return result
        if attempt >= max_retries or (guard is not None and guard.open_reason(provider)):
            if guard is not None:
                guard.record_failure(provider, kind)
            return result

        delay = retry_after if isinstance(retry_after, (int, float)) else C.OSINT_BACKOFF_BASE_SECONDS * (2**attempt)
        delay = max(0.0, min(float(delay), max_wait))
        logger.info(
            "OSINT %s answered HTTP %s; retry %d/%d in %.1fs", provider or url, status, attempt + 1, max_retries, delay
        )
        if guard is not None:
            if not guard.reserve_sleep(provider, delay, kind):
                return result  # backoff budget used up: the breaker is now open
            guard.note_retry(provider)
            if not _backoff_sleep(delay, guard):
                return result  # the analyst skipped the phase during the wait
        else:
            _sleep(delay)
        attempt += 1


def _backoff_sleep(delay: float, guard: ProviderGuard) -> bool:
    """Sleep ``delay`` seconds, in short slices when a skip check is available.

    Returns:
        False when the phase was skipped before the full delay had passed.
    """
    if guard.should_skip is None:
        _sleep(delay)
        return True
    step = max(0.05, float(C.OSINT_SLEEP_SLICE_SECONDS))
    remaining = float(delay)
    while remaining > 0:
        if guard.skip_requested():
            return False
        chunk = min(step, remaining)
        _sleep(chunk)
        remaining -= chunk
    return not guard.skip_requested()


def _j(url, headers=None, params=None):
    session = _get_session()
    try:
        r = session.get(url, headers=headers or {}, params=params or {})
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
        if r.status_code == 404:
            # Normal negative result — Shodan returns 404 for IPs it has never
            # scanned, VT/OTX return 404 for unknown domains. The provider is
            # working; it simply knows nothing about this indicator.
            return {"_nodata": True, "_url": url}
        if r.status_code in (401, 403):
            return {"_error": f"auth failed (HTTP {r.status_code})", "_url": url, "_status": r.status_code}
        if r.status_code == 429:
            return {
                "_error": "rate limited",
                "_detail": _rate_limit_detail(r),
                "_url": url,
                "_status": 429,
                "_retry_after": _retry_after_seconds(r),
            }
        return {
            "_error": f"HTTP {r.status_code}",
            "_url": url,
            "_status": r.status_code,
            "_retry_after": _retry_after_seconds(r),
        }
    except Exception as e:
        return {"_error": str(e), "_url": url}


def _cached_query(indicator: str, provider: str, query_fn) -> dict:
    """
    Query with caching support.

    Args:
        indicator: IP or domain to query
        provider: Provider name for cache key
        query_fn: Function to call if cache miss

    Returns:
        Cached or fresh response
    """
    cache = _get_cache()

    # Try cache first
    cached = cache.get(indicator, provider)
    if cached is not None:
        cached["_cached"] = True
        return cached

    # Cache miss - make API call
    result = query_fn()

    # Cache successful payloads AND clean negative results (_nodata) — the
    # provider will answer 404 for the same unknown indicator every time, so
    # re-querying only burns quota. Transient failures (_error: auth, rate
    # limit, network) stay uncached so they retry on the next run.
    if "_error" not in result:
        cache.set(indicator, provider, result)

    return result


def provider_status(results: list[dict | None]) -> str:
    """Classify a provider's health from all its per-indicator results.

    Returns one of: "ok" (any successful payload), "rate_limited", "auth_failed",
    "error", "nodata" (queried, every answer was a clean 404), "none" (never queried).
    Precedence: ok > rate_limited > auth_failed > error > nodata > none.
    """
    seen_rate_limited = seen_auth_failed = seen_error = seen_nodata = False
    for r in results or []:
        if not isinstance(r, dict):
            continue
        err = r.get("_error")
        if err:
            err_text = str(err).lower()
            if "rate limited" in err_text:
                seen_rate_limited = True
            elif "auth failed" in err_text:
                seen_auth_failed = True
            else:
                seen_error = True
        elif r.get("_nodata"):
            seen_nodata = True
        else:
            # Any successful payload proves the provider works.
            return "ok"
    if seen_rate_limited:
        return "rate_limited"
    if seen_auth_failed:
        return "auth_failed"
    if seen_error:
        return "error"
    if seen_nodata:
        return "nodata"
    return "none"


def _query_provider(
    indicator: str,
    provider: str,
    key_name: str,
    keys: dict[str, str],
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    guard: ProviderGuard | None = None,
    guard_name: str | None = None,
) -> tuple[dict | None, bool]:
    """Query a single OSINT provider with caching, retry and circuit breaking.

    Args:
        indicator: IP or domain.
        provider: Cache namespace for this provider/indicator type.
        key_name: Name of the API key in ``keys``.
        keys: API key mapping.
        url: Fully substituted request URL.
        headers: Header template (``__KEY__`` is replaced by the API key).
        params: Query-parameter template (same substitution).
        guard: Per-run breaker shared by all lookups of one ``enrich`` call.
        guard_name: Breaker identity (the provider's result key, so VirusTotal IP
            and domain lookups share one quota view). Defaults to ``provider``.

    Returns (result_dict, was_cached) or (None, False) if the key is missing.
    """
    api_key = keys.get(key_name)
    if not api_key:
        return None, False

    final_headers = {k: (api_key if v == "__KEY__" else v) for k, v in (headers or {}).items()}
    final_params = {k: (api_key if v == "__KEY__" else v) for k, v in (params or {}).items()}
    name = guard_name or provider

    def _fetch() -> dict:
        # Checked on a cache miss only: cached answers are still served while open.
        if guard is not None and guard.open_reason(name):
            guard.note_skip(name)
            return _circuit_open_result(name, guard)
        return _j_with_retry(
            url, headers=final_headers or None, params=final_params or None, provider=name, guard=guard
        )

    result = _cached_query(indicator, provider, _fetch)
    return result, bool(result.get("_cached"))


# Provider definitions: (result_key, cache_provider, key_name, url_template, headers, params)
_IP_PROVIDERS = [
    (
        "greynoise",
        "greynoise",
        "GREYNOISE_KEY",
        "https://api.greynoise.io/v3/community/{indicator}",
        {"key": "__KEY__", "Accept": "application/json"},
        None,
    ),
    (
        "abuseipdb",
        "abuseipdb",
        "ABUSEIPDB_KEY",
        "https://api.abuseipdb.com/api/v2/check",
        {"Key": "__KEY__", "Accept": "application/json"},
        {"ipAddress": "{indicator}", "maxAgeInDays": "90"},
    ),
    (
        "vt",
        "vt_ip",
        "VT_KEY",
        "https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
        {"x-apikey": "__KEY__"},
        None,
    ),
    (
        "shodan",
        "shodan",
        "SHODAN_KEY",
        "https://api.shodan.io/shodan/host/{indicator}",
        None,
        {"key": "__KEY__"},
    ),
]

_DOMAIN_PROVIDERS = [
    (
        "vt",
        "vt_domain",
        "VT_KEY",
        "https://www.virustotal.com/api/v3/domains/{indicator}",
        {"x-apikey": "__KEY__"},
        None,
    ),
    (
        "otx",
        "otx",
        "OTX_KEY",
        "https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general",
        {"X-OTX-API-KEY": "__KEY__"},
        None,
    ),
]


# ---------------------------------------------------------------------------
# Provider connectivity probes
# ---------------------------------------------------------------------------

PROBE_RESULT_OK = "ok"
PROBE_RESULT_INVALID_KEY = "invalid_key"
PROBE_RESULT_RATE_LIMITED = "rate_limited"
PROBE_RESULT_UNREACHABLE = "unreachable"
PROBE_RESULT_NO_KEY = "no_key"

# Benign, well-known indicators used for live probes
_PROBE_IP = "8.8.8.8"
_PROBE_DOMAIN = "google.com"

# Display names consistent with the Config tab key inputs
_PROVIDER_DISPLAY_NAMES = {
    "greynoise": "GreyNoise",
    "abuseipdb": "AbuseIPDB",
    "vt": "VirusTotal",
    "shodan": "Shodan",
    "otx": "OTX",
}


def _rate_limit_detail(response) -> str:
    """Extract plan/quota text from a 429 body for display (e.g. GreyNoise plan info)."""
    try:
        body = response.json()
    except Exception:
        body = None
    if isinstance(body, dict):
        parts = [str(body[k]) for k in ("message", "plan", "rate_limit") if body.get(k)]
        if parts:
            return "; ".join(parts)[:300]
        return str(body)[:300]
    text = (getattr(response, "text", "") or "").strip()
    return text[:300] or "HTTP 429"


def probe_providers(keys: dict[str, str], timeout: float = 12.0) -> list[dict]:
    """Live-check every configured OSINT provider with a benign indicator.

    Returns one dict per provider: {"provider", "status", "detail"} where status
    is one of the PROBE_RESULT_* constants. 401/403 → invalid_key, 429 →
    rate_limited (include any plan/message text from the body in detail),
    2xx → ok, network errors → unreachable, missing key → no_key.

    Probes bypass the OSINT cache (must be live) and run independently — one
    provider failing never stops the others.
    """
    probes: list[tuple[str, str, str, str, dict | None, dict | None]] = []
    seen: set[str] = set()
    for provider_defs, indicator in ((_IP_PROVIDERS, _PROBE_IP), (_DOMAIN_PROVIDERS, _PROBE_DOMAIN)):
        for result_key, _cache_prov, key_name, url_tpl, hdr_tpl, param_tpl in provider_defs:
            if result_key in seen:
                continue  # vt appears in both IP and domain defs — probe once
            seen.add(result_key)
            probes.append((result_key, indicator, key_name, url_tpl, hdr_tpl, param_tpl))

    results: list[dict] = []
    session = _get_session()
    for result_key, indicator, key_name, url_tpl, hdr_tpl, param_tpl in probes:
        provider = _PROVIDER_DISPLAY_NAMES.get(result_key, result_key)
        api_key = (keys or {}).get(key_name) or ""
        if not api_key:
            results.append({"provider": provider, "status": PROBE_RESULT_NO_KEY, "detail": "no API key configured"})
            continue

        url = url_tpl.replace("{indicator}", quote(indicator, safe=""))
        headers = {
            k: (api_key if v == "__KEY__" else v.replace("{indicator}", indicator)) if isinstance(v, str) else v
            for k, v in (hdr_tpl or {}).items()
        }
        params = {
            k: (api_key if v == "__KEY__" else v.replace("{indicator}", indicator)) if isinstance(v, str) else v
            for k, v in (param_tpl or {}).items()
        }

        try:
            resp = session.get(url, headers=headers or None, params=params or None, timeout=timeout)
        except Exception as e:
            results.append({"provider": provider, "status": PROBE_RESULT_UNREACHABLE, "detail": str(e)[:300]})
            continue

        code = getattr(resp, "status_code", 0)
        if 200 <= code < 300:
            results.append({"provider": provider, "status": PROBE_RESULT_OK, "detail": f"HTTP {code}"})
        elif code in (401, 403):
            results.append({"provider": provider, "status": PROBE_RESULT_INVALID_KEY, "detail": f"HTTP {code}"})
        elif code == 429:
            results.append(
                {"provider": provider, "status": PROBE_RESULT_RATE_LIMITED, "detail": _rate_limit_detail(resp)}
            )
        else:
            results.append({"provider": provider, "status": PROBE_RESULT_UNREACHABLE, "detail": f"HTTP {code}"})

    return results


def _query_single_provider_task(
    indicator: str,
    safe_indicator: str,
    result_key: str,
    cache_prov: str,
    key_name: str,
    url_tpl: str,
    hdr_tpl: dict | None,
    param_tpl: dict | None,
    keys: dict[str, str],
    guard: ProviderGuard | None = None,
) -> tuple[str, dict | None, bool]:
    """Query a single provider — designed to run inside a thread pool."""
    url = url_tpl.replace("{indicator}", safe_indicator)
    headers = {k: v.replace("{indicator}", indicator) if isinstance(v, str) else v for k, v in (hdr_tpl or {}).items()}
    params = {k: v.replace("{indicator}", indicator) if isinstance(v, str) else v for k, v in (param_tpl or {}).items()}
    result, cached = _query_provider(
        indicator,
        cache_prov,
        key_name,
        keys,
        url,
        headers=headers,
        params=params,
        guard=guard,
        guard_name=result_key,
    )
    return result_key, result, cached


def _query_providers(
    indicator: str,
    provider_defs: list,
    keys: dict[str, str],
    guard: ProviderGuard | None = None,
) -> tuple[dict, int]:
    """Run all configured providers for an indicator in parallel."""
    # URL-encode the indicator to prevent SSRF / injection via crafted values
    safe_indicator = quote(indicator, safe="")

    obj: dict[str, Any] = {}
    cache_hits = 0

    # Query providers concurrently using a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(provider_defs), 1)) as executor:
        futures = {
            executor.submit(
                _query_single_provider_task,
                indicator,
                safe_indicator,
                result_key,
                cache_prov,
                key_name,
                url_tpl,
                hdr_tpl,
                param_tpl,
                keys,
                guard,
            ): result_key
            for result_key, cache_prov, key_name, url_tpl, hdr_tpl, param_tpl in provider_defs
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                rkey, result, cached = future.result()
                if result is not None:
                    obj[rkey] = result
                    if cached:
                        cache_hits += 1
            except Exception as e:
                name = futures[future]
                logger.warning("Provider %s failed for %s: %s", name, indicator, e)

    return obj, cache_hits


def flagged_domains_from_dns(dns_analysis: Mapping[str, Any] | None) -> list[str]:
    """Domains the DNS analysis stage flagged (DGA, tunneling, fast flux), best first.

    Args:
        dns_analysis: The ``analyze_dns`` result dict (or None).

    Returns:
        De-duplicated lower-cased domains, ordered by detection score within each
        detector, DGA first.
    """
    if not isinstance(dns_analysis, Mapping):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for key in ("dga_detections", "tunneling_detections", "fast_flux_detections"):
        rows = dns_analysis.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            domain = row.get("domain") if isinstance(row, Mapping) else None
            if isinstance(domain, str) and domain.strip():
                d = domain.strip().lower().rstrip(".")
                if d not in seen:
                    seen.add(d)
                    out.append(d)
    return out


def prioritize_domains(domains: Iterable[str], flagged: Iterable[str]) -> list[str]:
    """Order ``domains`` so flagged ones are enriched before the domain cap applies.

    Exact matches of a flagged domain come first, then subdomains of a flagged
    domain (tunneling is reported per base domain), then everything else. Order
    within each tier follows the input, so the result is deterministic.

    Args:
        domains: Candidate domains.
        flagged: Domains flagged by DNS analysis.

    Returns:
        The same domains, reordered.
    """
    flagged_set = {str(f).strip().lower().rstrip(".") for f in flagged if isinstance(f, str) and f.strip()}
    doms = list(domains)
    if not flagged_set:
        return doms
    suffixes = tuple("." + f for f in flagged_set)

    def tier(domain: Any) -> int:
        d = str(domain).strip().lower().rstrip(".")
        if d in flagged_set:
            return 0
        return 1 if d.endswith(suffixes) else 2

    return sorted(doms, key=tier)  # stable: preserves input order within a tier


def enrich(
    artifacts: dict[str, list],
    keys: dict[str, str],
    phase: PhaseHandle | None = None,
    throttle: float = 0.35,
    previous_results: dict[str, Any] | None = None,
    *,
    cache_enabled: bool | None = None,
    max_domains: int | None = None,
    priority_domains: Iterable[str] | None = None,
    dns_analysis: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Enrich artifacts with OSINT data from configured providers.

    Args:
        artifacts: Dict with 'ips', 'domains', 'macs' lists.
        keys: API key mapping (provider -> key).
        phase: Optional progress tracker.
        throttle: Delay between API calls (seconds).
        previous_results: Prior OSINT results for deduplication in batch mode.
            IPs/domains already present here are skipped (reused as-is).
        cache_enabled: Use the response cache. None resolves the setting via
            :func:`resolve_cache_enabled` (Streamlit session when one exists,
            otherwise the saved config).
        max_domains: Cap on domains queried this run. None uses
            ``C.OSINT_MAX_DOMAINS_DEFAULT``; 0 or negative means no cap.
        priority_domains: Domains to enrich first (before the cap applies).
        dns_analysis: ``analyze_dns`` result; its flagged domains are added to
            ``priority_domains``.

    Returns:
        OSINT enrichment dict with 'ips', 'domains', 'ja3', 'macs'. Also carries
        'limits' (what the domain cap left out), 'provider_health' (providers that
        were throttled / disabled mid-run) and 'warnings' (human-readable notes).
    """
    if phase and phase.should_skip():
        phase.done("OSINT skipped.")
        return {"ips": {}, "domains": {}, "ja3": {}}

    # Resolve the cache setting once, on the calling thread — provider pool
    # threads have no Streamlit context and must not re-derive it per query.
    try:
        cache = _get_cache()
        cache.set_enabled(resolve_cache_enabled(cache_enabled))
    except Exception as e:
        cache = None
        logger.warning("OSINT cache unavailable: %s", e)

    # Invalidate cache if API keys changed since last run
    keys_str = "|".join(sorted(f"{k}={v[:8]}" for k, v in keys.items() if v))
    keys_hash = hashlib.sha256(keys_str.encode()).hexdigest()[:16]
    try:
        if cache is not None:
            cache.invalidate_on_key_change(keys_hash)
    except Exception as e:
        logger.warning("Cache key-change check failed: %s", e)

    prev = previous_results or {}
    prev_ips = prev.get("ips") or {}
    prev_doms = prev.get("domains") or {}

    # Both address families: an IPv4-only filter silently dropped every IPv6 host.
    all_ips = [ip for ip in artifacts.get("ips", []) if is_public_ip(ip)]
    all_doms = list(artifacts.get("domains", []) or [])

    # Deduplicate: skip indicators already enriched in a previous batch run
    new_ips = [ip for ip in all_ips if ip not in prev_ips]
    new_doms = [d for d in all_doms if d not in prev_doms]
    dedup_ip = len(all_ips) - len(new_ips)
    dedup_dom = len(all_doms) - len(new_doms)
    if dedup_ip or dedup_dom:
        logger.info(
            "OSINT dedup: skipping %d IPs and %d domains already enriched",
            dedup_ip,
            dedup_dom,
        )

    # Domain cap. `osint_top_n` only ever bounded IPs, so a DNS-heavy capture could
    # queue thousands of domain lookups. Flagged domains go first so the cap drops
    # the least interesting ones.
    flagged = [*(priority_domains or []), *flagged_domains_from_dns(dns_analysis)]
    new_doms = prioritize_domains(new_doms, flagged)
    domain_cap = C.OSINT_MAX_DOMAINS_DEFAULT if max_domains is None else int(max_domains)
    domains_total = len(new_doms)
    if domain_cap > 0 and domains_total > domain_cap:
        new_doms = new_doms[:domain_cap]
        logger.warning("OSINT domain cap: querying %d of %d domains", len(new_doms), domains_total)

    ips = new_ips
    doms = new_doms
    total = len(ips) + len(doms)
    done = 0
    guard = ProviderGuard(should_skip=phase.should_skip if phase else None)

    # Start with previous results so deduped indicators are preserved
    res: dict[str, Any] = {"ips": dict(prev_ips), "domains": dict(prev_doms), "ja3": {}}

    def tick(msg):
        nonlocal done
        done += 1
        if phase and total > 0:
            phase.set(10 + int((done / total) * 80), msg)

    if phase:
        phase.set(5, f"Querying {len(ips)} IPs and {len(doms)} domains…")

    for ip in ips:
        if phase and phase.should_skip():
            break

        calls_before = guard.network_calls
        obj, cache_hits = _query_providers(ip, _IP_PROVIDERS, keys, guard=guard)

        # Reverse DNS (not cached - fast local operation)
        ptr = resolve_ip(ip)
        if ptr:
            obj["ptr"] = ptr

        # GeoIP (City/Country)
        geo = GeoIP.lookup(ip)
        if geo:
            obj["city"] = geo.get("city")
            obj["country"] = geo.get("country")

        res["ips"][ip] = obj
        cache_status = f" (cached: {cache_hits})" if cache_hits > 0 else ""
        tick(f"OSINT IP {ip}{cache_status}")

        # Only throttle if we made actual API calls
        if cache_hits == 0 and guard.network_calls > calls_before:
            time.sleep(throttle)

    for dom in doms:
        if phase and phase.should_skip():
            break

        calls_before = guard.network_calls
        obj, cache_hits = _query_providers(dom, _DOMAIN_PROVIDERS, keys, guard=guard)

        res["domains"][dom] = obj
        cache_status = f" (cached: {cache_hits})" if cache_hits > 0 else ""
        tick(f"OSINT domain {dom}{cache_status}")

        # Only throttle if we made actual API calls
        if cache_hits == 0 and guard.network_calls > calls_before:
            time.sleep(throttle)

    # MAC Manufacturer Lookup
    macs = artifacts.get("macs", [])
    if macs:
        res["macs"] = {}
        for mac in macs:
            res["macs"][mac] = {"manufacturer": get_mac_manufacturer(mac)}

    # Coverage accounting — never let a cap or a tripped breaker be silent.
    run_warnings: list[str] = []
    domains_skipped = domains_total - len(doms)
    res["limits"] = {
        "domain_cap": domain_cap if domain_cap > 0 else None,
        "domains_total": domains_total,
        "domains_queried": len(doms),
        "domains_skipped": domains_skipped,
    }
    if domains_skipped:
        run_warnings.append(f"Domain cap reached: queried {len(doms)} of {domains_total} domains.")
    health = guard.snapshot()
    res["provider_health"] = health
    for name, info in health.items():
        display = _PROVIDER_DISPLAY_NAMES.get(name, name)
        if info["circuit_open"]:
            run_warnings.append(
                f"{display} disabled for the rest of the run ({info['reason']}); {info['skipped']} lookup(s) skipped."
            )
        elif info["rate_limited"] or info["server_errors"]:
            run_warnings.append(
                f"{display}: {info['rate_limited']} rate-limited and {info['server_errors']} server-error lookup(s)."
            )
    res["warnings"] = run_warnings

    if phase:
        phase.done("OSINT enrichment complete." if not phase.should_skip() else "OSINT skipped.")
    return res


def get_mac_manufacturer(mac: str) -> str:
    """Simple MAC manufacturer lookup based on OUI."""
    if not mac or ":" not in mac:
        return "Unknown"

    # Simple dictionary of some common OUIs
    COMMON_OUIS = {
        "00:05:5D": "D-Link",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "00:15:5D": "Microsoft (Hyper-V)",
        "00:1C:42": "Parallels",
        "00:16:3E": "Xen",
        "00:25:90": "Supermicro",
        "00:1A:11": "Google",
        "3C:5A:B4": "Google",
        "00:03:FF": "Microsoft",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
    }

    oui = mac.upper()[:8]
    return COMMON_OUIS.get(oui, "Unknown")
