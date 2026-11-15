"""C2 beaconing detection: periodicity scoring per flow and per connection series."""

from __future__ import annotations

from collections import defaultdict

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

# Mild prior for web ports. HTTP(S) is where most real C2 lives, so the prior must
# leave a strongly periodic web flow above every consumer threshold (correlation
# 0.5, LLM context 0.6, ATT&CK mapping 0.7): 0.8 keeps a near-perfect beacon at
# ~0.8 while still ranking it below the same pattern on an unusual port.
WEB_PORT_PRIOR = 0.8

# Destination ports for services that maintain persistent/periodic connections
# by design.  Multiplier applied to raw beacon score.
#
# Lower multiplier = stronger penalty (less likely to be a real beacon).
# Port 53 set to 0.15 — DNS resolvers generate inherently periodic traffic.
BENIGN_SERVICE_PORTS: dict[str, float] = {
    "53": 0.15,  # DNS — inherently periodic, strong penalty
    "123": 0.15,  # NTP — inherently periodic
    "443": WEB_PORT_PRIOR,  # HTTPS/QUIC — mostly legitimate, but also the commonest C2 channel
    "80": WEB_PORT_PRIOR,  # HTTP
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

# Aggregation levels reported in the ``aggregation`` column of rank_beaconing.
AGG_FLOW = "flow"  # packet timing inside one 5-tuple flow
AGG_CONNECTION = "connection"  # start times of separate connections to one (src, dst, dport)

# Minimum series length for either level to produce a result.
MIN_BEACON_SAMPLES = 4
# Connection series with a shorter mean interval are parallel connection bursts
# (a browser opening six sockets to one host), not check-ins.
MIN_CONNECTION_INTERVAL_SECONDS = 1.0


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
    # cv is None only when every gap is zero (no interval to measure); a cv of
    # exactly 0.0 is perfect regularity and must score best, not worst.
    cv_term = min(cv, 1.0) if cv is not None else 1.0
    score = (1.0 - cv_term) * 0.6 + (1.0 - min(entropy / 4.0, 1.0)) * 0.4

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


def _apply_fp_penalties(score: float, src: str, dst: str, proto: str, dport: str) -> float:
    """Apply the multiplicative false-positive priors shared by both aggregation levels.

    Args:
        score: Raw periodicity/jitter score.
        src: Source address.
        dst: Destination address.
        proto: Lower-cased protocol name.
        dport: Destination port as a string.

    Returns:
        Penalised score.
    """
    # 1. Service-port prior (strong for inherently periodic services, mild for web)
    if dport in BENIGN_SERVICE_PORTS:
        score *= BENIGN_SERVICE_PORTS[dport]

    # 2. Well-known infrastructure IPs (DNS resolvers, NTP servers)
    if dst in INFRA_ALLOWLIST or src in INFRA_ALLOWLIST:
        score *= 0.1

    # 3. Inherently periodic protocols (ICMP pings, NTP, mDNS, etc.)
    if proto in BENIGN_PERIODIC_PROTOS:
        score *= 0.15

    return score


def _flow_start(flow: dict[str, object]) -> float | None:
    """Start time of a flow: ``first_ts`` when present, else its earliest sampled packet."""
    first_ts = flow.get("first_ts")
    if isinstance(first_ts, (int, float)) and not isinstance(first_ts, bool):
        return float(first_ts)
    pkt_times = flow.get("pkt_times") or []
    return float(min(pkt_times)) if pkt_times else None


def _connection_series_rows(flows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Score connection-to-connection intervals per ``(src, dst, dport)``.

    Flows are keyed by the full 5-tuple upstream, so a beacon that opens a new
    connection for every check-in appears as many tiny flows, each from a fresh
    ephemeral source port, and its period is invisible inside any one of them.
    Grouping by ``(src, dst, dport)`` and scoring the series of flow start times
    measures the check-in interval itself.

    Args:
        flows: Flow dicts as emitted by the PyShark pass.

    Returns:
        Result rows in the rank_beaconing shape with ``aggregation="connection"``.
    """
    groups: dict[tuple[object, object, str], list[dict[str, object]]] = defaultdict(list)
    for f in flows:
        dport = str(f.get("dport", ""))
        if not f.get("src") or not f.get("dst") or not dport:
            continue
        groups[(f.get("src"), f.get("dst"), dport)].append(f)

    rows: list[dict[str, object]] = []
    for (src, dst, dport), members in groups.items():
        if len(members) < MIN_BEACON_SAMPLES:
            continue
        starts = sorted(t for t in (_flow_start(m) for m in members) if t is not None)
        if len(starts) < MIN_BEACON_SAMPLES:
            continue

        stats = periodicity_score(starts)
        mean_gap = stats["mean_gap"]
        if mean_gap is None or mean_gap < MIN_CONNECTION_INTERVAL_SECONDS:
            continue
        jitter = jitter_score(starts)
        proto = members[0].get("proto")
        final_score = _apply_fp_penalties(
            max(stats["score"], jitter["jitter_score"]), str(src), str(dst), str(proto or "").lower(), dport
        )

        last_seen = [m.get("last_ts") for m in members if isinstance(m.get("last_ts"), (int, float))]
        rows.append(
            {
                "src": src,
                "dst": dst,
                "sport": None,  # one ephemeral port per connection
                "dport": dport,
                "proto": proto,
                "pkts": sum(int(m.get("count") or len(m.get("pkt_times") or [])) for m in members),
                "mean_gap": mean_gap,
                "std_gap": stats["std_gap"],
                "cv": stats["cv"],
                "entropy": stats["entropy"],
                "score": round(final_score, 4),
                "dominant_interval": jitter["dominant_interval"],
                "jitter_pct": jitter["jitter_pct"],
                "aggregation": AGG_CONNECTION,
                "connections": len(members),
                "first_ts": starts[0],
                "last_ts": max(last_seen) if last_seen else starts[-1],
            }
        )
    return rows


def rank_beaconing(flows: list[dict[str, object]], top_n: int = 20) -> pd.DataFrame:
    """Rank network flows by beaconing likelihood.

    Scores two views of the same flows and ranks them together:

    * ``aggregation="flow"`` - packet timing inside each 5-tuple flow (a beacon
      riding one long-lived connection).
    * ``aggregation="connection"`` - start times of the separate connections one
      source made to one ``(dst, dport)`` (a beacon that reconnects per check-in).
      ``sport`` is None for these rows and ``connections`` holds the series size.

    Args:
        flows: List of flow dicts, each containing 'pkt_times' and flow metadata
            (``first_ts``/``last_ts``/``count`` are used when present).
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
        if len(ts) < MIN_BEACON_SAMPLES:
            continue

        stats = periodicity_score(ts)
        jitter = jitter_score(ts)
        # Use the higher of the two scores
        final_score = max(stats["score"], jitter["jitter_score"])

        dst = f.get("dst", "")
        src = f.get("src", "")
        proto = (f.get("proto") or "").lower()
        dport = str(f.get("dport", ""))

        # False-positive priors (multiplicative, stack). Applied BEFORE any
        # threshold checks so that benign traffic is scored down before it can
        # appear as a candidate.
        final_score = _apply_fp_penalties(final_score, src, dst, proto, dport)

        # 4. High-volume large-payload flows (streaming/downloads, not C2)
        #    Real C2 beacons are small, infrequent packets.
        pkt_lens = f.get("pkt_lens", [])
        if pkt_lens and len(ts) > 200:
            avg_pkt_size = sum(pkt_lens) / len(pkt_lens)
            if avg_pkt_size > 500:
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
                "aggregation": AGG_FLOW,
                "connections": 1,
                "first_ts": f.get("first_ts", ts[0]),
                "last_ts": f.get("last_ts", ts[-1]),
            }
        )

    rows.extend(_connection_series_rows(flows))
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values("score", ascending=False).head(top_n).reset_index(drop=True)
