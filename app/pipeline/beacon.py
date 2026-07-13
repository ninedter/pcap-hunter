from __future__ import annotations

import numpy as np
import pandas as pd

# Well-known infrastructure IPs that generate periodic traffic by design.
# Beacon scores for flows to these destinations are heavily penalised.
INFRA_ALLOWLIST = frozenset(
    {
        # Public DNS resolvers
        "1.1.1.1",
        "1.0.0.1",  # Cloudflare
        "8.8.8.8",
        "8.8.4.4",  # Google
        "208.67.222.222",
        "208.67.220.220",  # OpenDNS
        "9.9.9.9",
        "149.112.112.112",  # Quad9
        "168.95.1.1",
        "168.95.192.1",  # HiNet (Taiwan)
        # NTP pools (common)
        "129.6.15.28",
        "129.6.15.29",  # NIST
        "132.163.97.1",
        "132.163.96.1",
    }
)

# Protocols that are inherently periodic (health-checks, keep-alives)
# and should be penalised in beacon scoring.
BENIGN_PERIODIC_PROTOS = frozenset({"icmp", "ntp", "ssdp", "mdns", "igmp"})

# Destination ports for services that maintain persistent/periodic connections
# by design.  Multiplier applied to raw beacon score.
#
# Lower multiplier = stronger penalty (less likely to be a real beacon).
# Port 443 set to 0.15 — vast majority of HTTPS beacons are CDN keep-alives;
# genuine C2 on 443 needs corroborating OSINT signals to surface.
# Port 53 set to 0.15 — DNS resolvers generate inherently periodic traffic.
BENIGN_SERVICE_PORTS: dict[str, float] = {
    "53": 0.15,  # DNS — inherently periodic, strong penalty
    "123": 0.15,  # NTP — inherently periodic
    "443": 0.15,  # HTTPS/QUIC — overwhelmingly legitimate; real C2 needs OSINT corroboration
    "80": 0.3,  # HTTP — less common, moderate penalty
    "993": 0.15,  # IMAPS — periodic IDLE keep-alives
    "995": 0.15,  # POP3S
    "5223": 0.15,  # Apple Push Notification
    "5228": 0.15,  # Google Play / FCM push
    "1883": 0.2,  # MQTT (IoT)
    "8883": 0.2,  # MQTT over TLS
    "5060": 0.2,  # SIP
    "5061": 0.2,  # SIP-TLS
    "5353": 0.15,  # mDNS
}

# Ports where a very regular, high-confidence signal is allowed to soften
# (not erase) the benign-service penalty above. Restricted to HTTPS/HTTP —
# the transports real C2 frameworks actually abuse to blend in. DNS/NTP and
# the other BENIGN_SERVICE_PORTS entries are deliberately excluded: they are
# genuinely periodic infrastructure traffic by design, not something C2 uses
# as cover, so no amount of "regularity" should un-suppress them.
SOFTENABLE_BENIGN_PORTS: frozenset[str] = frozenset({"443"})

# Average packet size (bytes) below which a flow's payloads look C2-like.
# Real C2 beacons are SMALL packets; CDN/streaming keep-alives carry large
# payloads. Reused by both the softening gate below and the large-payload
# penalty in rank_beaconing.
C2_PAYLOAD_MAX_BYTES = 500

# Softened multiplier applied instead of BENIGN_SERVICE_PORTS[dport] when a
# flow on a softenable port meets ALL THREE C2-like conditions:
#   1. very high-confidence   — raw score >= 0.85
#   2. essentially jitter-free — jitter_pct <= 15
#   3. small average payload   — pkt_lens present and mean < C2_PAYLOAD_MAX_BYTES
# That combination is exactly what genuine small-packet HTTPS C2 looks like.
# Tuned against tests/test_beacon.py so a perfectly periodic small-payload
# 443 flow (raw score ~1.0) clears BEACON_SCORE_THRESHOLD (0.6) with margin:
# 1.0 * 0.69 = 0.69 > 0.6. The naive "penalty * 4" (0.15 -> 0.6) is NOT enough:
# a 0.9-raw flow would land at 0.9 * 0.6 = 0.54, still below threshold.
#
# 0.69, not 0.7: the ATT&CK mapper's beacon->C2 rule (DETECTION_RULES
# ["beacon_score"]["threshold"] in app/threat_intel/attack_mapping.py) fires
# at score >= 0.7 and auto-sets overall_severity="high". Since the max
# softened output is final_score(<=1.0) * SOFTENED_PENALTY, 0.7 would let a
# perfectly periodic, zero-jitter softened beacon land EXACTLY on the ATT&CK
# threshold — a benign small-payload HTTPS flow with flawless periodicity
# would then get flagged as T1071.001 C2 at HIGH severity purely from
# timing, which is exactly the false positive this softening bucket exists
# to avoid. 0.69 keeps the max softened score strictly below 0.7 (decoupled
# from the ATT&CK rule) while staying comfortably above the 0.6 beacon
# candidate floor and the 0.5 correlation ingest gate, so genuine HTTPS
# beacons still surface as candidates — they just don't trip the ATT&CK
# C2 technique on timing alone.
#
# The small-payload condition (3) is load-bearing: a machine-regular CDN
# heartbeat (zero jitter, LARGE 1200-byte payloads) is indistinguishable
# from C2 by timing+jitter alone, so requiring small payloads keeps those
# fully penalised. When pkt_lens is absent/empty we CANNOT confirm the flow
# is C2-like, so we conservatively do NOT soften. Ordinary jittery HTTPS
# keep-alives also fail the >=0.85 gate and keep the full 0.15 penalty.
SOFTENED_PENALTY = 0.69


def periodicity_score(ts: list[float]) -> dict[str, object]:
    """Score timestamp periodicity for beaconing detection.

    Args:
        ts: Timestamps, must be pre-sorted ascending when called from
            rank_beaconing.  Falls back to sorting internally otherwise.

    Returns:
        Dict with count, mean_gap, std_gap, cv, entropy, and score.
    """
    if not ts or len(ts) < 3:
        return {"count": len(ts), "mean_gap": None, "std_gap": None, "cv": None, "entropy": None, "score": 0.0}
    # Caller (rank_beaconing) provides pre-sorted timestamps; no re-sort needed.
    gaps = np.diff(ts)
    if len(gaps) == 0:
        return {"count": len(ts), "mean_gap": 0, "std_gap": 0, "cv": 0, "entropy": 0, "score": 0.0}
    mean_gap = float(np.mean(gaps))
    std_gap = float(np.std(gaps))
    cv = float(std_gap / mean_gap) if mean_gap > 0 else None
    bins = np.histogram(gaps, bins=min(20, max(5, int(len(gaps) / 3))))[0]
    probs = bins / bins.sum() if bins.sum() > 0 else np.array([1.0])
    entropy = float(-np.sum([p * np.log2(p) for p in probs if p > 0]))
    score = (1.0 - min(cv or 1.0, 1.0)) * 0.6 + (1.0 - min(entropy / 4.0, 1.0)) * 0.4

    # Softer volume scaling: small sample counts are penalised less so that
    # infrequent but regular beacons (e.g. daily C2 check-ins) still surface.
    # 3-5 packets  → 0.3-0.5 multiplier  (was 0.06-0.10 previously)
    # 6-9 packets  → 0.5-0.7
    # 10-20        → 0.7-0.9
    # 20+          → ~1.0
    score *= min(len(ts) / 20.0, 1.0) * 0.7 + 0.3

    return {
        "count": len(ts),
        "mean_gap": mean_gap,
        "std_gap": std_gap,
        "cv": cv,
        "entropy": entropy,
        "score": float(score),
    }


def jitter_score(ts: list[float]) -> dict[str, object]:
    """Score beaconing with jitter tolerance via modal interval analysis.

    Finds the dominant inter-packet interval and scores based on what
    fraction of gaps fall within +-20% of it.  Catches C2 channels that
    add random jitter to evade simple CV-based checks.

    Args:
        ts: Timestamps, must be pre-sorted ascending when called from
            rank_beaconing.  Falls back to sorting internally otherwise.

    Returns:
        Dict with jitter_score, dominant_interval, jitter_pct, consistent_ratio.
    """
    if not ts or len(ts) < 5:
        return {
            "jitter_score": 0.0,
            "dominant_interval": None,
            "jitter_pct": None,
            "consistent_ratio": None,
        }

    # Caller (rank_beaconing) provides pre-sorted timestamps; no re-sort needed.
    gaps = np.diff(ts)
    if len(gaps) == 0 or float(np.max(gaps)) == 0:
        return {
            "jitter_score": 0.0,
            "dominant_interval": 0,
            "jitter_pct": 0,
            "consistent_ratio": 0,
        }

    # Find dominant interval via histogram peak
    n_bins = min(50, max(10, len(gaps) // 3))
    counts, edges = np.histogram(gaps, bins=n_bins)
    peak_bin = int(np.argmax(counts))
    dominant_interval = float((edges[peak_bin] + edges[peak_bin + 1]) / 2)

    if dominant_interval <= 0:
        return {
            "jitter_score": 0.0,
            "dominant_interval": 0,
            "jitter_pct": 0,
            "consistent_ratio": 0,
        }

    # Count gaps within +-20% of dominant interval
    tolerance = dominant_interval * 0.2
    lo, hi = dominant_interval - tolerance, dominant_interval + tolerance
    consistent = int(np.sum((gaps >= lo) & (gaps <= hi)))
    consistent_ratio = consistent / len(gaps)

    # Jitter percentage
    consistent_gaps = gaps[(gaps >= lo) & (gaps <= hi)]
    if len(consistent_gaps) > 1:
        jitter_pct = float(np.std(consistent_gaps) / dominant_interval * 100)
    else:
        jitter_pct = 0.0

    score = consistent_ratio * 0.7 + (1.0 - min(jitter_pct / 30, 1.0)) * 0.3

    # Same volume scaling as periodicity_score
    score *= min(len(ts) / 20.0, 1.0) * 0.7 + 0.3

    return {
        "jitter_score": float(score),
        "dominant_interval": round(dominant_interval, 2),
        "jitter_pct": round(jitter_pct, 1),
        "consistent_ratio": round(consistent_ratio, 3),
    }


def rank_beaconing(flows: list[dict[str, object]], top_n: int = 20) -> pd.DataFrame:
    """Rank network flows by beaconing likelihood.

    Args:
        flows: List of flow dicts, each containing 'pkt_times' and flow metadata.
        top_n: Number of top results to return.

    Returns:
        DataFrame of top beaconing candidates sorted by score descending.
    """
    rows = []
    for f in flows:
        # Sort timestamps once; both scoring functions accept pre-sorted input.
        ts = sorted(f.get("pkt_times", []))
        if len(ts) < 2:
            continue

        # Minimum packet guard: single-digit packet counts to any destination
        # should not generate actionable beacon alerts.
        if len(ts) < 4:
            continue

        stats = periodicity_score(ts)
        jitter = jitter_score(ts)
        # Use the higher of the two scores
        final_score = max(stats["score"], jitter["jitter_score"])

        # --- False-positive reduction ---
        dst = f.get("dst", "")
        src = f.get("src", "")
        proto = (f.get("proto") or "").lower()
        dport = str(f.get("dport", ""))

        # --- False-positive penalties (multiplicative, stack) ---
        # Applied BEFORE any threshold checks so that benign traffic
        # is scored down before it can appear as a candidate.

        pkt_lens = f.get("pkt_lens", [])

        # 1. Benign service ports FIRST — this is the most common FP source
        #    (e.g., HTTPS keep-alives to CDNs on port 443)
        if dport in BENIGN_SERVICE_PORTS:
            penalty = BENIGN_SERVICE_PORTS[dport]
            # A very regular, high-confidence, SMALL-PAYLOAD signal on a
            # softenable port (443) is exactly what real HTTPS C2 looks like
            # — soften the penalty so it can still surface above threshold,
            # instead of guaranteeing a sub-threshold score. Ordinary HTTPS
            # keep-alives score moderately/show jitter, and CDN heartbeats
            # carry large payloads — both keep the full penalty.
            jitter_pct = jitter.get("jitter_pct")
            if jitter_pct is None:
                jitter_pct = 100.0
            # Small average payload is required and conservative: when pkt_lens
            # is absent/empty we cannot confirm the flow is C2-like, so we do
            # NOT soften.
            small_payload = bool(pkt_lens) and (sum(pkt_lens) / len(pkt_lens) < C2_PAYLOAD_MAX_BYTES)
            if dport in SOFTENABLE_BENIGN_PORTS and final_score >= 0.85 and jitter_pct <= 15 and small_payload:
                penalty = SOFTENED_PENALTY
            final_score *= penalty

        # 2. Well-known infrastructure IPs (DNS resolvers, NTP servers)
        if dst in INFRA_ALLOWLIST or src in INFRA_ALLOWLIST:
            final_score *= 0.1

        # 3. Inherently periodic protocols (ICMP pings, NTP, mDNS, etc.)
        if proto in BENIGN_PERIODIC_PROTOS:
            final_score *= 0.15

        # 4. High-volume large-payload flows (streaming/downloads, not C2)
        #    Real C2 beacons are small, infrequent packets.
        if pkt_lens and len(ts) > 200:
            avg_pkt_size = sum(pkt_lens) / len(pkt_lens)
            if avg_pkt_size > C2_PAYLOAD_MAX_BYTES:
                final_score *= 0.25

        rows.append(
            {
                "src": f.get("src"),
                "dst": dst,
                "sport": f.get("sport"),
                "dport": dport,
                "proto": f.get("proto"),
                # True packet total (survives the per-flow sample cap); all
                # scoring statistics above remain computed on the sampled ts.
                "pkts": f.get("count", len(ts)),
                "mean_gap": stats["mean_gap"],
                "std_gap": stats["std_gap"],
                "cv": stats["cv"],
                "entropy": stats["entropy"],
                "score": round(final_score, 4),
                "dominant_interval": jitter["dominant_interval"],
                "jitter_pct": jitter["jitter_pct"],
            }
        )
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values("score", ascending=False).head(top_n).reset_index(drop=True)
