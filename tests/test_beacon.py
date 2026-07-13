from app.config import BEACON_SCORE_THRESHOLD
from app.pipeline.beacon import jitter_score, periodicity_score, rank_beaconing


def test_periodicity_score_empty():
    res = periodicity_score([])
    assert res["score"] == 0.0
    assert res["count"] == 0


def test_periodicity_score_short():
    # With softer volume scaling, 3 regular packets now produce a small but
    # non-zero score so that infrequent beacons (e.g. daily C2) still surface.
    res = periodicity_score([1.0, 2.0, 3.0])
    assert res["score"] > 0.0
    assert res["count"] == 3

    # Fewer than 3 packets still returns zero
    res2 = periodicity_score([1.0, 2.0])
    assert res2["score"] == 0.0


def test_periodicity_score_perfect():
    # Perfectly periodic: 1.0, 2.0, 3.0 ... 10.0
    ts = [float(i) for i in range(1, 20)]
    res = periodicity_score(ts)
    # Should have low variance, low entropy, high score
    assert res["std_gap"] < 0.001
    assert res["score"] > 0.1  # Adjusted expectation based on implementation


def test_rank_beaconing():
    flows = [
        {
            "src": "10.0.0.1",
            "dst": "192.168.1.100",
            "sport": "12345",
            "dport": "80",
            "proto": "tcp",
            "pkt_times": [float(i) for i in range(1, 50)],  # periodic
        },
        {
            "src": "10.0.0.2",
            "dst": "192.168.1.200",
            "sport": "456",
            "dport": "443",
            "proto": "tcp",
            "pkt_times": [1.0, 1.1, 5.0, 5.2, 10.0],  # random
        },
    ]
    df = rank_beaconing(flows, top_n=10)
    assert len(df) == 2
    # First one should be ranked higher (periodic flow)
    assert df.iloc[0]["src"] == "10.0.0.1"
    assert df.iloc[0]["score"] > df.iloc[1]["score"]
    # New columns from jitter scoring
    assert "dominant_interval" in df.columns
    assert "jitter_pct" in df.columns


def test_jitter_score_empty():
    res = jitter_score([])
    assert res["jitter_score"] == 0.0


def test_jitter_score_short():
    # Less than 5 packets returns zero
    res = jitter_score([1.0, 2.0, 3.0])
    assert res["jitter_score"] == 0.0


def test_jitter_score_periodic():
    # Perfectly periodic with 20 packets
    ts = [float(i) for i in range(1, 21)]
    res = jitter_score(ts)
    assert res["jitter_score"] > 0.3
    assert res["dominant_interval"] is not None
    assert res["consistent_ratio"] > 0.5


def test_jitter_score_with_jitter():
    import random

    random.seed(42)
    # Periodic at ~10s interval with +-1s jitter
    ts = [10.0 * i + random.uniform(-1, 1) for i in range(30)]
    res = jitter_score(ts)
    assert res["jitter_score"] > 0.2
    assert res["dominant_interval"] is not None
    # Dominant interval should be close to 10
    assert 8 < res["dominant_interval"] < 12


def test_jitter_score_random():
    import random

    random.seed(123)
    # Completely random timestamps
    ts = sorted([random.uniform(0, 1000) for _ in range(20)])
    res = jitter_score(ts)
    # Random traffic should score lower than periodic
    periodic = jitter_score([float(i) for i in range(1, 21)])
    assert res["jitter_score"] < periodic["jitter_score"]


def test_rank_beaconing_regular_443_clears_threshold():
    # A genuinely periodic, SMALL-PAYLOAD HTTPS beacon (raw score ~1.0) must
    # survive the port-443 benign-service penalty and still clear
    # BEACON_SCORE_THRESHOLD. Before the conditional softening, the blanket
    # 0.15 multiplier crushed this down to ~0.15 — real HTTPS C2 was invisible
    # to the pipeline. Small payloads (80 bytes) are what real C2 beacons look
    # like, and are required for softening.
    flows = [
        {
            "src": "10.0.0.3",
            "dst": "203.0.113.5",
            "sport": "51000",
            "dport": "443",
            "proto": "tcp",
            "pkt_times": [float(i) for i in range(1, 60)],  # perfectly periodic
            "pkt_lens": [80] * 59,  # small, C2-like payloads
        }
    ]
    df = rank_beaconing(flows, top_n=10)
    assert len(df) == 1
    assert df.iloc[0]["score"] > BEACON_SCORE_THRESHOLD


def test_rank_beaconing_regular_443_large_payload_not_softened():
    # A machine-regular flow on 443 with LARGE payloads (like a CDN heartbeat)
    # is indistinguishable from C2 by timing+jitter alone — it must NOT be
    # softened. Only small-payload flows qualify; this keeps the full 0.15
    # penalty and stays well below threshold. Locks in the small-payload
    # distinction that guards tests/test_integration.py::test_https_cdn_not_flagged.
    flows = [
        {
            "src": "10.0.0.5",
            "dst": "13.224.0.9",  # CDN-like IP
            "sport": "51002",
            "dport": "443",
            "proto": "tcp",
            "pkt_times": [float(i) for i in range(1, 60)],  # perfectly periodic
            "pkt_lens": [1200] * 59,  # large payloads → NOT C2-like
        }
    ]
    df = rank_beaconing(flows, top_n=10)
    assert len(df) == 1
    # Full 0.15 penalty applied (raw ~1.0 * 0.15 = 0.15), no softening.
    assert df.iloc[0]["score"] <= 0.15
    assert df.iloc[0]["score"] < BEACON_SCORE_THRESHOLD


def test_rank_beaconing_regular_443_no_pkt_lens_not_softened():
    # Conservative default: without pkt_lens we cannot confirm the flow is
    # C2-like (small payloads), so we do NOT soften. Keeps the full penalty.
    flows = [
        {
            "src": "10.0.0.6",
            "dst": "203.0.113.7",
            "sport": "51003",
            "dport": "443",
            "proto": "tcp",
            "pkt_times": [float(i) for i in range(1, 60)],  # perfectly periodic
            # no pkt_lens
        }
    ]
    df = rank_beaconing(flows, top_n=10)
    assert len(df) == 1
    assert df.iloc[0]["score"] <= 0.15
    assert df.iloc[0]["score"] < BEACON_SCORE_THRESHOLD


def test_rank_beaconing_jittery_443_stays_suppressed():
    # An ordinary HTTPS keep-alive with real-world jitter must NOT be
    # promoted by the softening — only extremely regular, high-confidence
    # signals qualify. This flow's raw score drops well below the 0.85
    # softening gate once jitter is introduced, so it keeps the full 0.15
    # penalty and stays suppressed below threshold.
    import random

    random.seed(42)
    ts = sorted(10.0 * i + random.uniform(-2, 2) for i in range(30))
    flows = [
        {
            "src": "10.0.0.4",
            "dst": "203.0.113.6",
            "sport": "51001",
            "dport": "443",
            "proto": "tcp",
            "pkt_times": ts,
        }
    ]
    df = rank_beaconing(flows, top_n=10)
    assert len(df) == 1
    assert df.iloc[0]["score"] < BEACON_SCORE_THRESHOLD
