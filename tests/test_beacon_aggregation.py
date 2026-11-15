"""Beaconing across connections, the web-port prior, and perfect-regularity scoring.

Flows use the shape ``parse_pcap_pyshark`` emits: one dict per
``(src, dst, sport, dport, proto)`` with ``count``/``bytes``/``first_ts``/``last_ts``
scalars and capped ``pkt_times``/``pkt_lens`` samples.
"""

from __future__ import annotations

import random

from app.pipeline.beacon import (
    AGG_CONNECTION,
    AGG_FLOW,
    BENIGN_SERVICE_PORTS,
    periodicity_score,
    rank_beaconing,
)

T0 = 1700000000.0
CORRELATION_THRESHOLD = 0.5
LLM_THRESHOLD = 0.6
ATTACK_MAPPING_THRESHOLD = 0.7


def _flow(start: float, sport: int, *, dst="203.0.113.10", dport="443", src="192.168.1.50", n_pkts=6) -> dict:
    """One short connection: a handful of packets inside ~200 ms."""
    pkt_times = [start + i * 0.04 for i in range(n_pkts)]
    pkt_lens = [74, 66, 583, 1466, 180, 66][:n_pkts]
    return {
        "src": src,
        "dst": dst,
        "sport": str(sport),
        "dport": dport,
        "proto": "tcp",
        "count": n_pkts,
        "bytes": sum(pkt_lens),
        "first_ts": pkt_times[0],
        "last_ts": pkt_times[-1],
        "pkt_times": pkt_times,
        "pkt_lens": pkt_lens,
        "mac_src": "aa:bb:cc:00:00:01",
        "mac_dst": "aa:bb:cc:00:00:02",
    }


def _checkins(n: int, interval: float, jitter: float = 0.0, **kwargs) -> list[dict]:
    """``n`` separate connections, each from a new ephemeral port."""
    rng = random.Random(42)
    return [_flow(T0 + i * interval + rng.uniform(-jitter, jitter), 49152 + i, **kwargs) for i in range(n)]


class TestConnectionAggregation:
    def test_reconnecting_beacon_is_found_at_connection_level(self):
        """25 check-ins, 60 s apart, each its own tiny flow from a new source port."""
        df = rank_beaconing(_checkins(25, 60.0), top_n=50)

        conn = df[df["aggregation"] == AGG_CONNECTION]
        assert len(conn) == 1
        row = conn.iloc[0]
        assert (row["src"], row["dst"], row["dport"]) == ("192.168.1.50", "203.0.113.10", "443")
        assert row["sport"] is None
        assert row["connections"] == 25
        assert row["pkts"] == 25 * 6
        assert abs(row["mean_gap"] - 60.0) < 0.01
        assert row["first_ts"] == T0
        assert row["last_ts"] > T0 + 24 * 60
        # Surfaces above every downstream threshold, on port 443
        assert row["score"] >= ATTACK_MAPPING_THRESHOLD

        # It is the top-ranked row; the per-flow rows measure only the handshake
        assert df.iloc[0]["aggregation"] == AGG_CONNECTION
        assert set(df["aggregation"]) == {AGG_CONNECTION, AGG_FLOW}

    def test_jittered_checkins_still_surface(self):
        df = rank_beaconing(_checkins(30, 120.0, jitter=6.0), top_n=50)
        conn = df[df["aggregation"] == AGG_CONNECTION]
        assert len(conn) == 1
        assert conn.iloc[0]["score"] >= CORRELATION_THRESHOLD

    def test_irregular_connections_score_low(self):
        rng = random.Random(7)
        t = T0
        flows = []
        for i in range(25):
            t += rng.expovariate(1 / 90.0)  # human-like, memoryless arrivals
            flows.append(_flow(t, 49152 + i))
        df = rank_beaconing(flows, top_n=50)
        conn = df[df["aggregation"] == AGG_CONNECTION]
        assert conn.empty or conn.iloc[0]["score"] < CORRELATION_THRESHOLD

    def test_parallel_connection_burst_is_not_a_beacon(self):
        """A browser opening six sockets 50 ms apart is evenly spaced, not a check-in."""
        flows = [_flow(T0 + i * 0.05, 49152 + i) for i in range(6)]
        df = rank_beaconing(flows, top_n=50)
        assert (df["aggregation"] == AGG_CONNECTION).sum() == 0

    def test_fewer_than_four_connections_are_not_aggregated(self):
        df = rank_beaconing(_checkins(3, 60.0), top_n=50)
        assert (df["aggregation"] == AGG_CONNECTION).sum() == 0

    def test_groups_are_per_source_destination_and_port(self):
        flows = (
            _checkins(10, 60.0)
            + _checkins(10, 60.0, dst="203.0.113.99")
            + _checkins(10, 60.0, dport="8443")
            + _checkins(10, 60.0, src="192.168.1.77")
        )
        df = rank_beaconing(flows, top_n=100)
        conn = df[df["aggregation"] == AGG_CONNECTION]
        assert len(conn) == 4
        assert set(conn["connections"]) == {10}

    def test_first_ts_falls_back_to_sampled_packet_times(self):
        """Legacy flows saved before ``first_ts`` existed."""
        flows = _checkins(20, 60.0)
        for f in flows:
            del f["first_ts"], f["last_ts"]
        conn = rank_beaconing(flows, top_n=50).query("aggregation == 'connection'")
        assert len(conn) == 1
        assert abs(conn.iloc[0]["mean_gap"] - 60.0) < 0.01

    def test_infrastructure_destinations_stay_penalised(self):
        df = rank_beaconing(_checkins(25, 60.0, dst="8.8.8.8", dport="53"), top_n=50)
        assert df["score"].max() < 0.1

    def test_single_long_lived_flow_reports_flow_level(self):
        flow = _flow(T0, 50000, dport="4444")
        flow["pkt_times"] = [T0 + i * 30.0 for i in range(40)]
        flow["pkt_lens"] = [90] * 40
        flow["count"], flow["bytes"], flow["last_ts"] = 40, 3600, T0 + 39 * 30.0
        df = rank_beaconing([flow])
        assert len(df) == 1
        row = df.iloc[0]
        assert row["aggregation"] == AGG_FLOW
        assert row["connections"] == 1
        assert row["sport"] == "50000"
        assert (row["first_ts"], row["last_ts"]) == (T0, T0 + 39 * 30.0)


class TestWebPortPrior:
    def test_web_ports_use_a_mild_prior(self):
        assert BENIGN_SERVICE_PORTS["443"] >= 0.7
        assert BENIGN_SERVICE_PORTS["80"] >= 0.7
        # Inherently periodic services keep their strong penalty
        assert BENIGN_SERVICE_PORTS["53"] <= 0.2
        assert BENIGN_SERVICE_PORTS["123"] <= 0.2

    def test_periodic_web_flow_clears_consumer_thresholds(self):
        for port in ("443", "80"):
            flow = _flow(T0, 50000, dport=port)
            flow["pkt_times"] = [T0 + i * 45.0 for i in range(30)]
            flow["pkt_lens"] = [120] * 30
            flow["count"] = 30
            score = rank_beaconing([flow]).iloc[0]["score"]
            assert score >= ATTACK_MAPPING_THRESHOLD > LLM_THRESHOLD > CORRELATION_THRESHOLD, port


class TestPerfectRegularity:
    def test_zero_cv_scores_best_not_worst(self):
        ts = [T0 + i * 60.0 for i in range(20)]
        res = periodicity_score(ts)
        assert res["cv"] == 0.0
        assert res["score"] > 0.95

    def test_regular_series_beats_irregular_series(self):
        regular = periodicity_score([T0 + i * 60.0 for i in range(20)])
        rng = random.Random(3)
        t, irregular_ts = T0, []
        for _ in range(20):
            t += rng.expovariate(1 / 60.0)
            irregular_ts.append(t)
        irregular = periodicity_score(irregular_ts)
        assert regular["score"] > irregular["score"] + 0.3

    def test_all_zero_gaps_do_not_score_as_periodic(self):
        """cv is undefined when every gap is zero; that is not regularity."""
        res = periodicity_score([T0] * 10)
        assert res["cv"] is None
        assert res["score"] <= 0.4
