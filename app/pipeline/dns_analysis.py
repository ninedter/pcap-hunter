"""DNS query/response analysis for threat detection.

Provides detection for:
- DGA (Domain Generation Algorithm) domains
- DNS tunneling indicators
- Fast flux DNS behavior
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from app.pipeline.state import PhaseHandle

logger = logging.getLogger(__name__)

# --- Domain Validation Constants ---
MAX_DOMAIN_LENGTH = 253  # RFC 1035
MAX_LABEL_LENGTH = 63  # RFC 1035
VALID_DOMAIN_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9\-_.]*[a-z0-9])?$", re.IGNORECASE)
IP_LIKE_PATTERN = re.compile(r"^[\d.]+$")


def validate_domain(domain: str) -> bool:
    """
    Validate domain name to prevent ReDoS and injection attacks.

    Args:
        domain: Domain name to validate

    Returns:
        True if domain is valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False

    # Check total length (RFC 1035)
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False

    # Check each label length
    labels = domain.split(".")
    if not all(0 < len(label) <= MAX_LABEL_LENGTH for label in labels):
        return False

    # Check for valid characters (alphanumeric, hyphen, dot, underscore for DNS)
    if not VALID_DOMAIN_PATTERN.match(domain):
        return False

    return True


# Known legitimate TLDs that often have high entropy subdomains
ENTROPY_WHITELIST_TLDS = {
    "cloudfront.net",
    "amazonaws.com",
    "akamaiedge.net",
    "akadns.net",
    "googleusercontent.com",
    "1e100.net",
    "cloudflare.com",
}

# Common benign long domain patterns (pre-compiled for performance)
BENIGN_PATTERNS = [
    re.compile(r"^_dmarc\."),
    re.compile(r"^_domainkey\."),
    re.compile(r"^_acme-challenge\."),
    re.compile(r"^autodiscover\."),
    re.compile(r"^selector[12]\."),
]

# --- Detection Thresholds ---
DGA_SCORE_THRESHOLD = 0.3
DGA_CONFIRMED_THRESHOLD = 0.5
TUNNELING_SCORE_THRESHOLD = 0.2
TUNNELING_CONFIRMED_THRESHOLD = 0.5
TUNNELING_MIN_SUBDOMAINS = 5
FAST_FLUX_SCORE_THRESHOLD = 0.2
FAST_FLUX_CONFIRMED_THRESHOLD = 0.5
FAST_FLUX_TOP_DOMAINS = 50
NXDOMAIN_RATIO_THRESHOLD = 0.3
QUERY_VELOCITY_THRESHOLD = 50  # queries per second

# --- Result Limits ---
MAX_DGA_RESULTS = 50
MAX_TUNNELING_RESULTS = 20
MAX_FAST_FLUX_RESULTS = 20
MAX_TOP_QUERIED = 20
MAX_COMMON_INDICATORS = 100


@dataclass
class DNSRecord:
    """Parsed DNS query/response record."""

    ts: float
    src: str
    dst: str
    query: str
    qtype: str
    rcode: str = ""
    answers: list[str] = field(default_factory=list)
    ttls: list[int] = field(default_factory=list)


@dataclass
class DGAResult:
    """DGA detection result for a domain."""

    domain: str
    score: float  # 0-1, higher = more likely DGA
    entropy: float
    consonant_ratio: float
    digit_ratio: float
    length: int
    is_dga: bool
    reason: str


@dataclass
class TunnelingResult:
    """DNS tunneling detection result."""

    domain: str
    subdomain_count: int
    avg_subdomain_length: float
    max_subdomain_length: int
    unique_subdomains: int
    query_volume: int
    txt_record_ratio: float
    score: float  # 0-1, higher = more likely tunneling
    is_tunneling: bool
    reason: str


@dataclass
class FastFluxResult:
    """Fast flux detection result."""

    domain: str
    unique_ips: int
    ip_changes: int
    min_ttl: int
    avg_ttl: float
    time_window: float  # seconds
    score: float
    is_fast_flux: bool
    reason: str


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s.lower())
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def calculate_consonant_ratio(s: str) -> float:
    """Calculate ratio of consonants to total alphabetic characters."""
    s = s.lower()
    consonants = set("bcdfghjklmnpqrstvwxyz")
    alpha_chars = [c for c in s if c.isalpha()]
    if not alpha_chars:
        return 0.0
    consonant_count = sum(1 for c in alpha_chars if c in consonants)
    return consonant_count / len(alpha_chars)


def calculate_digit_ratio(s: str) -> float:
    """Calculate ratio of digits to total characters."""
    if not s:
        return 0.0
    digit_count = sum(1 for c in s if c.isdigit())
    return digit_count / len(s)


def extract_domain_parts(domain: str) -> tuple[str, str, str]:
    """
    Extract subdomain, domain, and TLD from a domain name.

    Returns:
        (subdomain, domain, tld)
    """
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return "", domain, ""
    if len(parts) == 2:
        return "", parts[0], parts[1]

    # Handle multi-part TLDs (e.g., co.uk, com.br)
    if len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        if len(parts) == 3:
            return "", parts[0], f"{parts[-2]}.{parts[-1]}"
        return ".".join(parts[:-3]), parts[-3], f"{parts[-2]}.{parts[-1]}"

    return ".".join(parts[:-2]), parts[-2], parts[-1]


def is_whitelisted_domain(domain: str) -> bool:
    """Check if domain is in whitelist (CDNs, cloud providers, etc.)."""
    domain_lower = domain.lower()
    for tld in ENTROPY_WHITELIST_TLDS:
        if domain_lower.endswith(f".{tld}") or domain_lower == tld:
            return True
    for pattern in BENIGN_PATTERNS:
        if pattern.match(domain_lower):
            return True
    return False


def detect_dga(domain: str) -> DGAResult:
    """
    Detect if a domain is likely generated by a DGA.

    Uses multiple heuristics:
    - Shannon entropy of the domain name
    - Consonant to vowel ratio
    - Digit ratio
    - Length analysis

    Args:
        domain: Domain name to analyze

    Returns:
        DGAResult with detection details
    """
    subdomain, name, tld = extract_domain_parts(domain)

    # Analyze the main domain name (not subdomain or TLD)
    analyze_part = name if not subdomain else subdomain.split(".")[-1]

    entropy = calculate_entropy(analyze_part)
    consonant_ratio = calculate_consonant_ratio(analyze_part)
    digit_ratio = calculate_digit_ratio(analyze_part)
    length = len(analyze_part)

    # Scoring weights
    score = 0.0
    reasons = []

    # High entropy (random-looking)
    if entropy > 4.0:
        score += 0.3
        reasons.append(f"high entropy ({entropy:.2f})")
    elif entropy > 3.5:
        score += 0.15

    # Unusual consonant ratio
    if consonant_ratio > 0.75:
        score += 0.2
        reasons.append(f"high consonant ratio ({consonant_ratio:.2f})")
    elif consonant_ratio < 0.35 and length > 8:
        score += 0.1

    # High digit ratio
    if digit_ratio > 0.3:
        score += 0.25
        reasons.append(f"high digit ratio ({digit_ratio:.2f})")
    elif digit_ratio > 0.15:
        score += 0.1

    # Unusual length
    if length > 15:
        score += 0.15
        reasons.append(f"long name ({length} chars)")
    elif length > 12:
        score += 0.05

    # No vowels at all
    if consonant_ratio == 1.0 and length > 5:
        score += 0.15
        reasons.append("no vowels")

    # Whitelist check
    if is_whitelisted_domain(domain):
        score *= 0.3
        reasons.append("whitelisted domain type")

    is_dga = score >= 0.5

    return DGAResult(
        domain=domain,
        score=min(score, 1.0),
        entropy=entropy,
        consonant_ratio=consonant_ratio,
        digit_ratio=digit_ratio,
        length=length,
        is_dga=is_dga,
        reason="; ".join(reasons) if reasons else "normal",
    )


def detect_tunneling(
    dns_records: list[DNSRecord],
    domain: str,
    *,
    pre_filtered: list[DNSRecord] | None = None,
) -> TunnelingResult:
    """
    Detect DNS tunneling indicators for a domain.

    Tunneling indicators:
    - Many unique subdomains (encoded data)
    - Long subdomain labels
    - High volume of TXT queries
    - Regular query patterns

    Args:
        dns_records: List of DNS records to analyze (used as fallback)
        domain: Base domain to analyze
        pre_filtered: Pre-filtered records for this domain's base domain.
            If provided, skips the O(N) scan of dns_records.

    Returns:
        TunnelingResult with detection details
    """
    domain_lower = domain.lower()
    if pre_filtered is not None:
        # Use pre-filtered records (already scoped to base domain)
        relevant = [
            r for r in pre_filtered if r.query.lower().endswith(domain_lower) or r.query.lower() == domain_lower
        ]
    else:
        # Fallback: scan all records (backward compatible)
        relevant = [r for r in dns_records if r.query.lower().endswith(domain_lower) or r.query.lower() == domain_lower]

    if not relevant:
        return TunnelingResult(
            domain=domain,
            subdomain_count=0,
            avg_subdomain_length=0,
            max_subdomain_length=0,
            unique_subdomains=0,
            query_volume=0,
            txt_record_ratio=0,
            score=0,
            is_tunneling=False,
            reason="no data",
        )

    # Extract subdomains
    subdomains = []
    for r in relevant:
        query = r.query.lower()
        if query != domain_lower and query.endswith(f".{domain_lower}"):
            subdomain = query[: -(len(domain_lower) + 1)]
            subdomains.append(subdomain)

    # Calculate metrics
    unique_subdomains = len(set(subdomains))
    subdomain_lengths = [len(s) for s in subdomains] if subdomains else [0]
    avg_length = sum(subdomain_lengths) / len(subdomain_lengths)
    max_length = max(subdomain_lengths)

    txt_queries = sum(1 for r in relevant if r.qtype.upper() in ("TXT", "16"))
    txt_ratio = txt_queries / len(relevant) if relevant else 0

    # Scoring
    score = 0.0
    reasons = []

    # Many unique subdomains (data exfiltration)
    if unique_subdomains > 100:
        score += 0.3
        reasons.append(f"{unique_subdomains} unique subdomains")
    elif unique_subdomains > 50:
        score += 0.2
    elif unique_subdomains > 20:
        score += 0.1

    # Long subdomains (encoded data)
    if avg_length > 30:
        score += 0.25
        reasons.append(f"avg subdomain length {avg_length:.1f}")
    elif avg_length > 20:
        score += 0.15

    if max_length > 50:
        score += 0.15
        reasons.append(f"max subdomain length {max_length}")

    # High TXT record ratio
    if txt_ratio > 0.5:
        score += 0.2
        reasons.append(f"high TXT ratio ({txt_ratio:.1%})")
    elif txt_ratio > 0.2:
        score += 0.1

    # High query volume
    if len(relevant) > 500:
        score += 0.1
        reasons.append(f"{len(relevant)} queries")

    is_tunneling = score >= 0.5

    return TunnelingResult(
        domain=domain,
        subdomain_count=len(subdomains),
        avg_subdomain_length=avg_length,
        max_subdomain_length=max_length,
        unique_subdomains=unique_subdomains,
        query_volume=len(relevant),
        txt_record_ratio=txt_ratio,
        score=min(score, 1.0),
        is_tunneling=is_tunneling,
        reason="; ".join(reasons) if reasons else "normal",
    )


def detect_fast_flux(
    dns_records: list[DNSRecord],
    domain: str,
    *,
    pre_filtered: list[DNSRecord] | None = None,
) -> FastFluxResult:
    """
    Detect fast flux DNS behavior.

    Fast flux indicators:
    - Many unique IP addresses for same domain
    - Low TTL values
    - Frequent IP changes in short time

    Args:
        dns_records: List of DNS records to analyze (used as fallback)
        domain: Domain to analyze
        pre_filtered: Pre-filtered records for this domain's base domain.
            If provided, skips the O(N) scan of dns_records.

    Returns:
        FastFluxResult with detection details
    """
    domain_lower = domain.lower()
    if pre_filtered is not None:
        relevant = [r for r in pre_filtered if r.query.lower() == domain_lower and r.answers]
    else:
        relevant = [r for r in dns_records if r.query.lower() == domain_lower and r.answers]

    if not relevant:
        return FastFluxResult(
            domain=domain,
            unique_ips=0,
            ip_changes=0,
            min_ttl=0,
            avg_ttl=0,
            time_window=0,
            score=0,
            is_fast_flux=False,
            reason="no A/AAAA records",
        )

    # Collect unique IPs and TTLs
    all_ips = []
    all_ttls = []
    timestamps = []

    for r in relevant:
        timestamps.append(r.ts)
        for answer in r.answers:
            # Filter for IP-like answers (A/AAAA records)
            if IP_LIKE_PATTERN.match(answer) or ":" in answer:
                all_ips.append(answer)
        all_ttls.extend(r.ttls)

    unique_ips = len(set(all_ips))
    time_window = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

    # Calculate IP changes (sequential unique IPs)
    ip_changes = 0
    prev_ip = None
    for ip in all_ips:
        if prev_ip and ip != prev_ip:
            ip_changes += 1
        prev_ip = ip

    min_ttl = min(all_ttls) if all_ttls else 0
    avg_ttl = sum(all_ttls) / len(all_ttls) if all_ttls else 0

    # Scoring
    score = 0.0
    reasons = []

    # Many unique IPs
    if unique_ips > 10:
        score += 0.3
        reasons.append(f"{unique_ips} unique IPs")
    elif unique_ips > 5:
        score += 0.2
    elif unique_ips > 3:
        score += 0.1

    # Low TTL
    if min_ttl > 0 and min_ttl < 60:
        score += 0.25
        reasons.append(f"low TTL ({min_ttl}s)")
    elif min_ttl > 0 and min_ttl < 300:
        score += 0.1

    # Frequent IP changes
    if time_window > 0:
        changes_per_minute = (ip_changes / time_window) * 60
        if changes_per_minute > 2:
            score += 0.25
            reasons.append(f"frequent IP changes ({changes_per_minute:.1f}/min)")
        elif changes_per_minute > 0.5:
            score += 0.1

    is_fast_flux = score >= 0.5

    return FastFluxResult(
        domain=domain,
        unique_ips=unique_ips,
        ip_changes=ip_changes,
        min_ttl=min_ttl,
        avg_ttl=avg_ttl,
        time_window=time_window,
        score=min(score, 1.0),
        is_fast_flux=is_fast_flux,
        reason="; ".join(reasons) if reasons else "normal",
    )


def analyze_nxdomain(records: list[DNSRecord]) -> dict[str, Any]:
    """
    Analyze NXDOMAIN response ratios per source IP.

    High NXDOMAIN ratios indicate DGA activity or domain enumeration.

    Args:
        records: List of DNS records

    Returns:
        Dict with nxdomain_count, nxdomain_ratio, and per-source breakdown
    """
    nxdomain_codes = {"NXDOMAIN", "3", "NXDomain"}
    total = len(records)
    if total == 0:
        return {"nxdomain_count": 0, "nxdomain_ratio": 0.0, "sources": []}

    nxdomain_count = sum(1 for r in records if r.rcode in nxdomain_codes)
    nxdomain_ratio = nxdomain_count / total

    # Per-source breakdown
    src_total: dict[str, int] = defaultdict(int)
    src_nxdomain: dict[str, int] = defaultdict(int)
    for r in records:
        src_total[r.src] += 1
        if r.rcode in nxdomain_codes:
            src_nxdomain[r.src] += 1

    sources = []
    for src, nx_count in sorted(src_nxdomain.items(), key=lambda x: -x[1]):
        total_q = src_total[src]
        ratio = nx_count / total_q if total_q > 0 else 0
        if ratio > 0.1:  # Only include sources with >10% NXDOMAIN
            sources.append(
                {
                    "src": src,
                    "nxdomain_count": nx_count,
                    "total_queries": total_q,
                    "ratio": round(ratio, 3),
                    "is_suspicious": ratio > NXDOMAIN_RATIO_THRESHOLD,
                }
            )

    return {
        "nxdomain_count": nxdomain_count,
        "nxdomain_ratio": round(nxdomain_ratio, 3),
        "is_suspicious": nxdomain_ratio > NXDOMAIN_RATIO_THRESHOLD,
        "sources": sources[:20],
    }


def analyze_query_velocity(records: list[DNSRecord]) -> list[dict[str, Any]]:
    """
    Detect high DNS query rates per source IP.

    Sustained high query rates may indicate DNS tunneling or enumeration.

    Args:
        records: List of DNS records

    Returns:
        List of sources with high query velocity
    """
    if not records:
        return []

    # Group by source IP
    src_records: dict[str, list[float]] = defaultdict(list)
    for r in records:
        src_records[r.src].append(r.ts)

    results = []
    for src, timestamps in src_records.items():
        if len(timestamps) < 10:
            continue

        timestamps.sort()
        duration = timestamps[-1] - timestamps[0]
        if duration <= 0:
            continue

        qps = len(timestamps) / duration

        # Score based on query velocity
        score = 0.0
        if qps > QUERY_VELOCITY_THRESHOLD * 2:
            score = 0.8
        elif qps > QUERY_VELOCITY_THRESHOLD:
            score = 0.5
        elif qps > QUERY_VELOCITY_THRESHOLD / 2:
            score = 0.3
        else:
            continue

        results.append(
            {
                "src": src,
                "queries": len(timestamps),
                "duration_sec": round(duration, 1),
                "qps": round(qps, 1),
                "score": score,
                "is_suspicious": qps > QUERY_VELOCITY_THRESHOLD,
            }
        )

    results.sort(key=lambda x: x["qps"], reverse=True)
    return results[:20]


def parse_dns_log(df: pd.DataFrame) -> list[DNSRecord]:
    """
    Parse Zeek dns.log DataFrame into DNSRecord objects.

    Args:
        df: DataFrame from Zeek dns.log

    Returns:
        List of DNSRecord objects
    """
    records = []

    for row in df.to_dict(orient="records"):
        try:
            # Handle different column naming conventions
            ts = float(row.get("ts", 0))
            src = str(row.get("id.orig_h", row.get("id_orig_h", "")))
            dst = str(row.get("id.resp_h", row.get("id_resp_h", "")))
            query = str(row.get("query", ""))
            qtype = str(row.get("qtype_name", row.get("qtype", "")))
            rcode = str(row.get("rcode_name", row.get("rcode", "")))

            # Parse answers (may be list or comma-separated string)
            answers_raw = row.get("answers", [])
            if isinstance(answers_raw, str):
                answers = [a.strip() for a in answers_raw.split(",") if a.strip() and a != "-"]
            elif isinstance(answers_raw, list):
                answers = [str(a) for a in answers_raw if a and str(a) != "-"]
            else:
                answers = []

            # Parse TTLs
            ttls_raw = row.get("TTLs", row.get("ttls", []))
            ttls = []
            if isinstance(ttls_raw, str):
                ttls = [int(float(t)) for t in ttls_raw.split(",") if t.strip() and t != "-"]
            elif isinstance(ttls_raw, list):
                ttls = [int(float(t)) for t in ttls_raw if t and str(t) != "-"]

            if query and query != "-":
                records.append(
                    DNSRecord(
                        ts=ts,
                        src=src,
                        dst=dst,
                        query=query,
                        qtype=qtype,
                        rcode=rcode,
                        answers=answers,
                        ttls=ttls,
                    )
                )
        except (ValueError, TypeError) as e:
            logger.debug("Failed to parse DNS record: %s", e)
            continue

    return records


def analyze_dns(
    zeek_tables: dict[str, pd.DataFrame],
    features: dict[str, Any] | None = None,
    phase: PhaseHandle | None = None,
) -> dict[str, Any]:
    """
    Comprehensive DNS analysis from Zeek logs.

    Args:
        zeek_tables: Dictionary of Zeek log DataFrames
        features: Existing features dict (optional)
        phase: PhaseHandle for progress updates

    Returns:
        Dictionary with DNS analysis results
    """
    if phase and phase.should_skip():
        phase.done("DNS analysis skipped.")
        return {"skipped": True}

    if phase:
        phase.set(5, "Parsing DNS logs...")

    dns_df = zeek_tables.get("dns.log")
    if dns_df is None or dns_df.empty:
        if phase:
            phase.done("No DNS data available.")
        return {"error": "No DNS log data", "records": 0}

    # Parse records
    records = parse_dns_log(dns_df)
    if not records:
        if phase:
            phase.done("No valid DNS records found.")
        return {"error": "No valid DNS records", "records": 0}

    if phase:
        phase.set(20, f"Analyzing {len(records)} DNS records...")

    # Extract unique domains (with validation)
    all_domains = list({r.query for r in records if validate_domain(r.query)})

    # Group by base domain
    domain_groups: dict[str, list[str]] = defaultdict(list)
    for domain in all_domains:
        _, name, tld = extract_domain_parts(domain)
        if name and tld:
            base = f"{name}.{tld}"
            domain_groups[base].append(domain)

    # Analyze each domain
    dga_results = []
    tunneling_results = []
    fast_flux_results = []

    total_domains = len(all_domains)
    for i, domain in enumerate(all_domains):
        if phase and i % 50 == 0:
            pct = 20 + int((i / total_domains) * 50)
            phase.set(pct, f"Analyzing domain {i + 1}/{total_domains}...")

        # DGA detection
        dga = detect_dga(domain)
        if dga.score > DGA_SCORE_THRESHOLD:
            dga_results.append(dga)

    if phase:
        phase.set(70, "Analyzing tunneling patterns...")

    # Pre-index DNS records by base domain to avoid O(N*M) scans
    domain_records_index: dict[str, list[DNSRecord]] = defaultdict(list)
    for r in records:
        parts = r.query.lower().rsplit(".", 2)
        if len(parts) >= 2:
            base = ".".join(parts[-2:])
            domain_records_index[base].append(r)

    # Tunneling detection (per base domain)
    for base_domain, subdomains in domain_groups.items():
        if len(subdomains) > TUNNELING_MIN_SUBDOMAINS:
            pre_filtered = domain_records_index.get(base_domain.lower(), [])
            tunnel = detect_tunneling(records, base_domain, pre_filtered=pre_filtered)
            if tunnel.score > TUNNELING_SCORE_THRESHOLD:
                tunneling_results.append(tunnel)

    if phase:
        phase.set(85, "Analyzing fast flux patterns...")

    # Fast flux detection (top queried domains)
    domain_counts = Counter(r.query for r in records)
    top_domains = [d for d, _ in domain_counts.most_common(FAST_FLUX_TOP_DOMAINS)]

    for domain in top_domains:
        parts = domain.lower().rsplit(".", 2)
        base_key = ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()
        pre_filtered = domain_records_index.get(base_key, [])
        ff = detect_fast_flux(records, domain, pre_filtered=pre_filtered)
        if ff.score > FAST_FLUX_SCORE_THRESHOLD:
            fast_flux_results.append(ff)

    # Sort by score
    dga_results.sort(key=lambda x: x.score, reverse=True)
    tunneling_results.sort(key=lambda x: x.score, reverse=True)
    fast_flux_results.sort(key=lambda x: x.score, reverse=True)

    # Generate summary statistics
    query_types = Counter(r.qtype for r in records)
    response_codes = Counter(r.rcode for r in records if r.rcode and r.rcode != "-")
    top_queried = domain_counts.most_common(MAX_TOP_QUERIED)

    # Unique DNS servers
    dns_servers = list({r.dst for r in records})

    # NXDOMAIN analysis
    nxdomain_analysis = analyze_nxdomain(records)

    # Query velocity analysis
    query_velocity = analyze_query_velocity(records)

    # Build result
    result = {
        "total_records": len(records),
        "unique_domains": len(all_domains),
        "unique_dns_servers": len(dns_servers),
        "dns_servers": dns_servers[:10],  # Top 10
        "query_types": dict(query_types),
        "response_codes": dict(response_codes),
        "top_queried": [{"domain": d, "count": c} for d, c in top_queried],
        "nxdomain_analysis": nxdomain_analysis,
        "query_velocity": query_velocity,
        "dga_detections": [
            {
                "domain": r.domain,
                "score": r.score,
                "entropy": r.entropy,
                "consonant_ratio": r.consonant_ratio,
                "digit_ratio": r.digit_ratio,
                "length": r.length,
                "is_dga": r.is_dga,
                "reason": r.reason,
            }
            for r in dga_results[:MAX_DGA_RESULTS]
        ],
        "tunneling_detections": [
            {
                "domain": r.domain,
                "subdomain_count": r.subdomain_count,
                "avg_subdomain_length": r.avg_subdomain_length,
                "max_subdomain_length": r.max_subdomain_length,
                "unique_subdomains": r.unique_subdomains,
                "query_volume": r.query_volume,
                "txt_record_ratio": r.txt_record_ratio,
                "score": r.score,
                "is_tunneling": r.is_tunneling,
                "reason": r.reason,
            }
            for r in tunneling_results[:MAX_TUNNELING_RESULTS]
        ],
        "fast_flux_detections": [
            {
                "domain": r.domain,
                "unique_ips": r.unique_ips,
                "ip_changes": r.ip_changes,
                "min_ttl": r.min_ttl,
                "avg_ttl": r.avg_ttl,
                "time_window": r.time_window,
                "score": r.score,
                "is_fast_flux": r.is_fast_flux,
                "reason": r.reason,
            }
            for r in fast_flux_results[:MAX_FAST_FLUX_RESULTS]
        ],
        "high_risk_domains": [r.domain for r in dga_results if r.is_dga]
        + [r.domain for r in tunneling_results if r.is_tunneling]
        + [r.domain for r in fast_flux_results if r.is_fast_flux],
        "alerts": {
            "dga_count": sum(1 for r in dga_results if r.is_dga),
            "tunneling_count": sum(1 for r in tunneling_results if r.is_tunneling),
            "fast_flux_count": sum(1 for r in fast_flux_results if r.is_fast_flux),
            "nxdomain_suspicious": nxdomain_analysis.get("is_suspicious", False),
            "nxdomain_ratio": nxdomain_analysis.get("nxdomain_ratio", 0),
            "high_velocity_sources": sum(1 for v in query_velocity if v.get("is_suspicious")),
        },
    }

    if phase:
        alerts = result["alerts"]
        alert_msg = []
        if alerts["dga_count"]:
            alert_msg.append(f"{alerts['dga_count']} DGA")
        if alerts["tunneling_count"]:
            alert_msg.append(f"{alerts['tunneling_count']} tunneling")
        if alerts["fast_flux_count"]:
            alert_msg.append(f"{alerts['fast_flux_count']} fast-flux")
        if alerts.get("nxdomain_suspicious"):
            alert_msg.append(f"NXDOMAIN {alerts['nxdomain_ratio']:.0%}")
        if alerts.get("high_velocity_sources"):
            alert_msg.append(f"{alerts['high_velocity_sources']} high-velocity")

        summary = f"Analyzed {len(records)} DNS records, {len(all_domains)} domains."
        if alert_msg:
            summary += f" Alerts: {', '.join(alert_msg)}."
        phase.done(summary)

    return result
