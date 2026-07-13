from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import threading
import time
from typing import Any
from urllib.parse import quote

from app.pipeline.geoip import GeoIP
from app.pipeline.osint_cache import get_osint_cache
from app.pipeline.state import PhaseHandle
from app.security.opsec import hardened_session
from app.utils.common import is_public_ipv4, resolve_ip
from app.utils.network_utils import is_enrichable_domain

logger = logging.getLogger(__name__)

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
    """Get or create cache instance with enabled state from config."""
    global _cache
    if _cache is None:
        _cache = get_osint_cache()

    # Update enabled state from session config
    try:
        import streamlit as st

        enabled = st.session_state.get("cfg_osint_cache_enabled", False)
        _cache.set_enabled(enabled)
    except Exception:
        pass  # Not in Streamlit context

    return _cache


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
            return {"_error": f"auth failed (HTTP {r.status_code})", "_url": url}
        if r.status_code == 429:
            return {"_error": "rate limited", "_detail": _rate_limit_detail(r), "_url": url}
        return {"_error": f"HTTP {r.status_code}", "_url": url}
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
) -> tuple[dict | None, bool]:
    """Query a single OSINT provider with caching.

    Returns (result_dict, was_cached) or (None, False) if the key is missing.
    """
    api_key = keys.get(key_name)
    if not api_key:
        return None, False

    final_headers = {k: (api_key if v == "__KEY__" else v) for k, v in (headers or {}).items()}
    final_params = {k: (api_key if v == "__KEY__" else v) for k, v in (params or {}).items()}

    result = _cached_query(
        indicator, provider, lambda: _j(url, headers=final_headers or None, params=final_params or None)
    )
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
    )
    return result_key, result, cached


def _query_providers(
    indicator: str,
    provider_defs: list,
    keys: dict[str, str],
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


def enrich(
    artifacts: dict[str, list],
    keys: dict[str, str],
    phase: PhaseHandle | None = None,
    throttle: float = 0.35,
    previous_results: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Enrich artifacts with OSINT data from configured providers.

    Args:
        artifacts: Dict with 'ips', 'domains', 'macs' lists.
        keys: API key mapping (provider -> key).
        phase: Optional progress tracker.
        throttle: Delay between API calls (seconds).
        previous_results: Prior OSINT results for deduplication in batch mode.
            IPs/domains already present here are skipped (reused as-is).

    Returns:
        OSINT enrichment dict with 'ips', 'domains', 'ja3', 'macs'.
    """
    if phase and phase.should_skip():
        phase.done("OSINT skipped.")
        return {"ips": {}, "domains": {}, "ja3": {}}

    # Invalidate cache if API keys changed since last run
    keys_str = "|".join(sorted(f"{k}={v[:8]}" for k, v in keys.items() if v))
    keys_hash = hashlib.sha256(keys_str.encode()).hexdigest()[:16]
    try:
        cache = _get_cache()
        cache.invalidate_on_key_change(keys_hash)
    except Exception as e:
        logger.warning("Cache key-change check failed: %s", e)

    prev = previous_results or {}
    prev_ips = prev.get("ips") or {}
    prev_doms = prev.get("domains") or {}

    all_ips = [ip for ip in artifacts.get("ips", []) if is_public_ipv4(ip)]
    all_doms = [d for d in artifacts.get("domains", []) if is_enrichable_domain(d)]

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

    ips = new_ips
    doms = new_doms
    total = len(ips) + len(doms)
    done = 0

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

        obj, cache_hits = _query_providers(ip, _IP_PROVIDERS, keys)

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
        if cache_hits == 0:
            time.sleep(throttle)

    for dom in doms:
        if phase and phase.should_skip():
            break

        obj, cache_hits = _query_providers(dom, _DOMAIN_PROVIDERS, keys)

        res["domains"][dom] = obj
        cache_status = f" (cached: {cache_hits})" if cache_hits > 0 else ""
        tick(f"OSINT domain {dom}{cache_status}")

        # Only throttle if we made actual API calls
        if cache_hits == 0:
            time.sleep(throttle)

    # MAC Manufacturer Lookup
    macs = artifacts.get("macs", [])
    if macs:
        res["macs"] = {}
        for mac in macs:
            res["macs"][mac] = {"manufacturer": get_mac_manufacturer(mac)}

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
