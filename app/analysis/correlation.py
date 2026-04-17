"""Cross-indicator correlation engine.

Correlates findings across all analysis modules (OSINT, beaconing, DNS,
TLS, YARA) to produce composite threat scores per indicator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.utils.common import is_public_ipv4

logger = logging.getLogger(__name__)

# Correlation signal weights
SIGNAL_WEIGHTS = {
    "vt_detections": 0.20,
    "greynoise_malicious": 0.10,
    "abuseipdb": 0.08,
    "beacon_score": 0.18,
    "dga_domain": 0.12,
    "dns_tunneling": 0.10,
    "self_signed_cert": 0.06,
    "expired_cert": 0.04,
    "yara_match": 0.08,
    "flow_asymmetry": 0.04,
}

VERDICT_THRESHOLDS = {
    "critical": 0.75,
    "high": 0.55,
    "medium": 0.35,
    "low": 0.0,
}


@dataclass
class CorrelationSignal:
    """A single signal contributing to correlation."""

    name: str
    value: Any
    score: float  # 0.0 - 1.0 normalised contribution
    source: str  # module that produced this signal


@dataclass
class CorrelationResult:
    """Correlated threat assessment for a single indicator."""

    indicator: str
    indicator_type: str  # ip, domain
    signals: list[CorrelationSignal] = field(default_factory=list)
    composite_score: float = 0.0
    verdict: str = "low"

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "composite_score": round(self.composite_score, 3),
            "verdict": self.verdict,
            "signal_count": len(self.signals),
            "signals": [
                {"name": s.name, "value": s.value, "score": round(s.score, 3), "source": s.source} for s in self.signals
            ],
        }


def _get_verdict(score: float) -> str:
    for label, threshold in sorted(VERDICT_THRESHOLDS.items(), key=lambda x: -x[1]):
        if score >= threshold:
            return label
    return "low"


def _collect_ip_signals(
    ip: str,
    osint: dict,
    beacon_lookup: dict[str, float],
    tls_lookup: dict[str, list[str]],
    yara_ips: set[str],
    asymmetry_lookup: dict[str, float],
) -> list[CorrelationSignal]:
    """Collect all signals for an IP indicator."""
    signals: list[CorrelationSignal] = []
    ip_osint = osint.get("ips", {}).get(ip, {})

    # VirusTotal
    vt = ip_osint.get("vt", {})
    vt_attr = vt.get("data", {}).get("attributes", {})
    vt_rep = vt_attr.get("reputation", 0)
    if isinstance(vt_rep, (int, float)) and vt_rep < 0:
        normalised = min(abs(vt_rep) / 100, 1.0)
        signals.append(CorrelationSignal("vt_detections", vt_rep, normalised, "virustotal"))

    # GreyNoise
    gn = ip_osint.get("greynoise", {})
    classification = gn.get("classification", "")
    if classification == "malicious":
        signals.append(CorrelationSignal("greynoise_malicious", classification, 1.0, "greynoise"))

    # AbuseIPDB
    abuse = ip_osint.get("abuseipdb", {})
    abuse_data = abuse.get("data", {})
    abuse_score = abuse_data.get("abuseConfidenceScore", 0)
    if isinstance(abuse_score, (int, float)) and abuse_score > 0:
        signals.append(CorrelationSignal("abuseipdb", abuse_score, abuse_score / 100, "abuseipdb"))

    # Beacon score — threshold raised to 0.5 to reduce false positives from
    # benign periodic traffic (ICMP health-checks, keep-alives, NTP).
    if ip in beacon_lookup and beacon_lookup[ip] > 0.5:
        signals.append(CorrelationSignal("beacon_score", round(beacon_lookup[ip], 2), beacon_lookup[ip], "beacon"))

    # TLS anomalies
    if ip in tls_lookup:
        for alert_type in tls_lookup[ip]:
            if alert_type == "self_signed":
                signals.append(CorrelationSignal("self_signed_cert", True, 1.0, "tls"))
            elif alert_type == "expired":
                signals.append(CorrelationSignal("expired_cert", True, 1.0, "tls"))

    # YARA
    if ip in yara_ips:
        signals.append(CorrelationSignal("yara_match", True, 1.0, "yara"))

    # Flow asymmetry
    if ip in asymmetry_lookup and asymmetry_lookup[ip] > 0.3:
        signals.append(
            CorrelationSignal("flow_asymmetry", round(asymmetry_lookup[ip], 2), asymmetry_lookup[ip], "flow_analysis")
        )

    return signals


def _collect_domain_signals(
    domain: str,
    osint: dict,
    dns_analysis: dict,
) -> list[CorrelationSignal]:
    """Collect all signals for a domain indicator."""
    signals: list[CorrelationSignal] = []
    dom_osint = osint.get("domains", {}).get(domain, {})

    # VirusTotal
    vt = dom_osint.get("vt", {})
    vt_attr = vt.get("data", {}).get("attributes", {})
    last_analysis = vt_attr.get("last_analysis_stats", {})
    malicious = last_analysis.get("malicious", 0)
    if malicious > 0:
        total = sum(last_analysis.values()) or 1
        signals.append(CorrelationSignal("vt_detections", f"{malicious}/{total}", malicious / total, "virustotal"))

    # DGA detection
    dga_list = dns_analysis.get("dga_detections", [])
    for dga in dga_list:
        if dga.get("domain") == domain and dga.get("is_dga"):
            signals.append(CorrelationSignal("dga_domain", dga.get("score", 0), dga["score"], "dns"))
            break

    # Tunneling
    tunnel_list = dns_analysis.get("tunneling_detections", [])
    for tunnel in tunnel_list:
        if tunnel.get("domain") == domain and tunnel.get("is_tunneling"):
            signals.append(CorrelationSignal("dns_tunneling", tunnel.get("score", 0), tunnel["score"], "dns"))
            break

    return signals


# Tier definitions — a strong OSINT hit alone can push to "high"; behavioural
# signals need corroboration; contextual signals alone cap at "medium".
_TIER1_DEFINITIVE = {"vt_detections", "greynoise_malicious"}
_TIER2_BEHAVIOURAL = {"beacon_score", "flow_asymmetry", "dns_tunneling", "dga_domain"}
_TIER3_CONTEXTUAL = {"abuseipdb", "self_signed_cert", "expired_cert", "yara_match"}

# Strong-signal floors — a single definitive signal sets a minimum score
# regardless of the rest of the formula.
_STRONG_SIGNAL_FLOORS = {
    "vt_detections": 0.55,  # VT detection → at least "high"
    "greynoise_malicious": 0.40,  # GreyNoise malicious → at least "medium"
}


def _compute_composite(signals: list[CorrelationSignal]) -> float:
    """Compute composite score using the independence-complement formula.

    Instead of a linear weighted sum, this uses ``1 − Π(1 − wᵢsᵢ)`` which
    produces diminishing returns while still allowing multiple weak signals
    to compound meaningfully.  Strong-signal floors then set a minimum.

    Research basis: Bayesian independence model (NIST SP 800-55 risk
    aggregation) + Vectra AI / CrowdStrike Signal multi-factor approach.
    """
    if not signals:
        return 0.0

    # Independence-complement: P(at least one real) = 1 - product(1 - p_i)
    product = 1.0
    for sig in signals:
        weight = SIGNAL_WEIGHTS.get(sig.name, 0.05)
        p = min(sig.score * weight * 2.5, 0.95)  # scale so max single ≈ 0.95
        product *= 1.0 - p
    composite = 1.0 - product

    # Apply strong-signal floors
    for sig in signals:
        floor = _STRONG_SIGNAL_FLOORS.get(sig.name, 0.0)
        if floor > 0 and sig.score >= 0.5:
            composite = max(composite, floor)

    # Tier cap: contextual-only signals (no Tier 1 or Tier 2) cap at medium
    has_t1 = any(s.name in _TIER1_DEFINITIVE for s in signals)
    has_t2 = any(s.name in _TIER2_BEHAVIOURAL for s in signals)
    if not has_t1 and not has_t2:
        composite = min(composite, 0.45)  # cap below "high" threshold

    return min(composite, 1.0)


def correlate_indicators(
    features: dict | None = None,
    osint: dict | None = None,
    beacon_df: Any = None,
    dns_analysis: dict | None = None,
    tls_analysis: dict | None = None,
    yara_results: dict | None = None,
    asymmetry_results: list | None = None,
) -> list[CorrelationResult]:
    """
    Correlate indicators across all analysis modules.

    Args:
        features: Flow and artifact features
        osint: OSINT enrichment data
        beacon_df: Beacon analysis DataFrame
        dns_analysis: DNS analysis results
        tls_analysis: TLS certificate analysis
        yara_results: YARA scan results
        asymmetry_results: Flow asymmetry results

    Returns:
        List of CorrelationResult sorted by composite score (highest first)
    """
    features = features or {}
    osint = osint or {}
    dns_analysis = dns_analysis or {}
    tls_analysis = tls_analysis or {}

    # Build lookup tables
    beacon_lookup: dict[str, float] = {}
    if beacon_df is not None:
        try:
            for _, row in beacon_df.iterrows():
                dst = row.get("dst", "")
                score = row.get("score", 0)
                if dst and score > 0:
                    beacon_lookup[dst] = max(beacon_lookup.get(dst, 0), score)
        except Exception:
            pass

    tls_lookup: dict[str, list[str]] = {}
    for alert in tls_analysis.get("alerts", []):
        if isinstance(alert, dict):
            dst_ip = alert.get("dst_ip", "")
            alert_type = alert.get("type", "")
            if dst_ip and alert_type:
                tls_lookup.setdefault(dst_ip, []).append(alert_type)

    yara_ips: set[str] = set()
    if yara_results and yara_results.get("matched", 0) > 0:
        for r in yara_results.get("results", []):
            if r.get("has_matches"):
                yara_ips.add(r.get("src_ip", ""))

    asymmetry_lookup: dict[str, float] = {}
    if asymmetry_results:
        for ar in asymmetry_results:
            if hasattr(ar, "dst") and hasattr(ar, "score"):
                asymmetry_lookup[ar.dst] = max(asymmetry_lookup.get(ar.dst, 0), ar.score)
            elif isinstance(ar, dict):
                dst = ar.get("dst", "")
                score = ar.get("score", 0)
                if dst:
                    asymmetry_lookup[dst] = max(asymmetry_lookup.get(dst, 0), score)

    results: list[CorrelationResult] = []

    # Correlate IPs
    ips = [ip for ip in features.get("artifacts", {}).get("ips", []) if is_public_ipv4(ip)]
    for ip in ips:
        signals = _collect_ip_signals(ip, osint, beacon_lookup, tls_lookup, yara_ips, asymmetry_lookup)
        if not signals:
            continue
        composite = _compute_composite(signals)
        results.append(
            CorrelationResult(
                indicator=ip,
                indicator_type="ip",
                signals=signals,
                composite_score=composite,
                verdict=_get_verdict(composite),
            )
        )

    # Correlate domains
    domains = features.get("artifacts", {}).get("domains", [])
    for domain in domains:
        signals = _collect_domain_signals(domain, osint, dns_analysis)
        if not signals:
            continue
        composite = _compute_composite(signals)
        results.append(
            CorrelationResult(
                indicator=domain,
                indicator_type="domain",
                signals=signals,
                composite_score=composite,
                verdict=_get_verdict(composite),
            )
        )

    results.sort(key=lambda r: r.composite_score, reverse=True)
    return results
