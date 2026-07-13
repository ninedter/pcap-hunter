from __future__ import annotations

import concurrent.futures
import functools
import ipaddress
import logging
import re
import socket
import urllib.parse

logger = logging.getLogger(__name__)

# Default timeout for individual rDNS lookups (seconds)
_RDNS_TIMEOUT = 2.0

# Save and restore the default socket timeout so we only modify it
# inside our own call.
_orig_timeout = socket.getdefaulttimeout()


def resolve_ip(ip: str, timeout: float = _RDNS_TIMEOUT) -> str | None:
    """Resolve IP to domain name (Reverse DNS) with a timeout."""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(old)
    except (socket.herror, socket.gaierror, OSError, socket.timeout):
        return None


def bulk_resolve_ips(
    ips: list[str],
    max_workers: int = 10,
    use_cache: bool = True,
) -> dict[str, str]:
    """Resolve many IPs to hostnames in parallel, with caching.

    Args:
        ips: List of IP address strings (public IPs only are meaningful).
        max_workers: Thread pool size.
        use_cache: Whether to check/store in the rDNS SQLite cache.

    Returns:
        ``{ip: hostname}`` for every IP that resolved successfully.
    """
    if not ips:
        return {}

    unique_ips = list(set(ips))
    result: dict[str, str] = {}

    # Check cache first
    uncached: list[str] = unique_ips
    if use_cache:
        try:
            from app.pipeline.rdns_cache import get_rdns_cache

            cache = get_rdns_cache()
            cached = cache.get_batch(unique_ips)
            result.update(cached)
            uncached = [ip for ip in unique_ips if ip not in cached]
        except Exception as e:
            logger.debug("rdns lookup failed: %s", e)  # cache unavailable — resolve everything

    if not uncached:
        return result

    # Resolve uncached IPs in parallel
    new_entries: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(uncached))) as executor:
        future_to_ip = {executor.submit(resolve_ip, ip): ip for ip in uncached}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                hostname = future.result()
                if hostname:
                    result[ip] = hostname
                    new_entries.append((ip, hostname))
            except Exception as e:
                logger.debug("rdns lookup failed: %s", e)

    # Store new resolutions in cache
    if use_cache and new_entries:
        try:
            from app.pipeline.rdns_cache import get_rdns_cache

            get_rdns_cache().set_batch(new_entries)
        except Exception:
            pass

    logger.info("rDNS resolved %d/%d IPs (%d cached)", len(result), len(unique_ips), len(unique_ips) - len(uncached))
    return result


def _validate_domain(domain: str) -> bool:
    """
    Validate a domain name to prevent SSRF and injection attacks.

    Args:
        domain: Domain string to validate

    Returns:
        True if domain appears valid, False otherwise
    """
    if not domain or len(domain) > 253:
        return False
    # Must contain at least one dot
    if "." not in domain:
        return False
    # Only allow valid domain characters
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    if not re.match(pattern, domain):
        return False
    return True


_PRIVATE_TLDS = frozenset(
    {
        "local",
        "internal",
        "lan",
        "corp",
        "home",
        "intranet",
        "test",
        "example",
        "invalid",
        "localhost",
    }
)


def is_enrichable_domain(domain: str) -> bool:
    """True only for public, routable domains worth sending to OSINT providers.

    Prevents leaking internal infrastructure names (dc01.internal.corp, *.local)
    to third-party SaaS (VirusTotal submissions are visible to paid subscribers).

    Rejects: invalid domains per ``_validate_domain`` (dot required, no
    underscore), single-label names, reverse-DNS artifacts
    (``*.in-addr.arpa``/``*.ip6.arpa``), IP-shaped strings, and private/internal
    TLDs (local/internal/lan/corp/home/intranet/test/example/invalid/localhost).
    """
    if not domain or not _validate_domain(domain):  # dot required, no underscore
        return False
    lower = domain.lower().rstrip(".")

    # _validate_domain's regex allows all-numeric labels, so IP literals like
    # "1.2.3.4" pass it — reject them explicitly since they aren't domains.
    try:
        ipaddress.ip_address(lower)
        return False
    except ValueError:
        pass

    if lower.endswith((".in-addr.arpa", ".ip6.arpa")):
        return False
    tld = lower.rsplit(".", 1)[-1]
    if tld in _PRIVATE_TLDS:
        return False
    return True


def get_whois_info(target: str) -> dict | str:
    """
    Retrieve WHOIS information for a domain or IP.
    For IPs, uses RDAP (Registration Data Access Protocol).
    For domains, uses whois library.
    """
    import whois

    from app.security.opsec import hardened_session

    try:
        if is_public_ipv4(target):
            # RDAP Lookup for IPs — URL-encode the target to prevent injection
            safe_target = urllib.parse.quote(target, safe="")
            url = f"https://rdap.arin.net/registry/ip/{safe_target}"
            r = hardened_session(timeout=10).get(url)
            if r.status_code == 200:
                data = r.json()
                # Map RDAP fields to common schema
                res = {
                    "domain_name": data.get("handle", target),
                    "registrar": data.get("name", "n/a"),
                    "creation_date": "n/a",
                    "expiration_date": "n/a",
                    "name": "n/a",
                    "org": "n/a",
                    "country": data.get("country", "n/a"),
                    "emails": "n/a",
                }
                # Extraction of Org/Entity info
                entities = data.get("entities", [])
                if entities:
                    ent = entities[0]
                    org_name = ent.get("vcardArray", [None, [["fn", {}, "text", "n/a"]]])[1][0][3]
                    res["org"] = org_name
                    res["name"] = org_name
                    # Try to find emails
                    vcard = ent.get("vcardArray", [None, []])[1]
                    emails = [item[3] for item in vcard if item[0] == "email"]
                    if emails:
                        res["emails"] = emails

                # Try to get events (created/updated)
                events = data.get("events", [])
                for ev in events:
                    if ev.get("eventAction") == "registration":
                        res["creation_date"] = ev.get("eventDate")
                    elif ev.get("eventAction") == "last changed":
                        res["expiration_date"] = ev.get("eventDate")  # Using as 'last updated/expires' proxy

                return res
            else:
                return f"RDAP lookup failed (HTTP {r.status_code})"

        # Domain Lookup — validate before making the request
        if not _validate_domain(target):
            return {"error": f"Invalid domain name: {target}"}

        w = whois.whois(target)
        if hasattr(w, "text"):
            return w
        return dict(w)
    except Exception as e:
        return f"WHOIS lookup failed for {target}: {e}"


@functools.lru_cache(maxsize=4096)
def is_public_ipv4(s: str) -> bool:
    """Check if string is a valid *public* IPv4 address.

    Pure string -> bool; cached because it is called repeatedly for the same
    IPs across pipeline stages, correlation, and UI rendering.
    """
    try:
        ip = ipaddress.ip_address(s)
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except (ValueError, TypeError):
        return False


def pick_top_public_ips(features: dict, n: int) -> list[str]:
    """
    Return top-N public IPv4s by packet volume across flows.
    If n <= 0, return all public IPv4s from artifacts.
    """
    if not isinstance(features, dict) or n <= 0:
        return [ip for ip in (features or {}).get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]

    flows = (features or {}).get("flows", [])
    if not flows:
        return [ip for ip in (features or {}).get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]

    counts = {}
    for f in flows:
        pkts = int(f.get("count") or 0)
        src = f.get("src")
        dst = f.get("dst")
        if src and is_public_ipv4(src):
            counts[src] = counts.get(src, 0) + pkts
        if dst and is_public_ipv4(dst):
            counts[dst] = counts.get(dst, 0) + pkts

    if not counts:
        return [ip for ip in (features or {}).get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]

    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return [ip for ip, _ in ranked[: max(1, n)]]
