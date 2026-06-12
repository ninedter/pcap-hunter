"""Tests for per-flow packet-sample cap in pyshark_pass and beacon strip in runner.

Task 4: Per-flow cap — ensures that pkt_times/pkt_lens lists are bounded to
MAX_FLOW_SAMPLES entries (keep-first semantics), while flow["count"] keeps
counting all packets. Also guards that runner._run_beacon strips pkt_times and
pkt_lens from the serialized beacon records.

Cap regression guards: true flow totals (bytes/first_ts/last_ts) must be
tracked as scalars beyond the cap, and downstream consumers (flow asymmetry,
beacon pkts display) must use them instead of the capped sample lists.
"""

from __future__ import annotations

import io
from unittest.mock import patch

import pandas as pd
import pytest

from app import config as C
from app.analysis.flow_analysis import detect_flow_asymmetry
from app.pipeline.beacon import rank_beaconing

# ---------------------------------------------------------------------------
# Helpers shared across this file (NOT imported from other test modules)
# ---------------------------------------------------------------------------


class FakePopen:
    """Minimal Popen stand-in whose stdout is iterable line by line.

    Mirrors the FakePopen in test_carve_streaming.py — kept independent per
    project convention (tests do not import across test files).
    """

    def __init__(self, lines, exit_code=0):
        self.stdout = iter(list(lines))
        self.stderr = io.StringIO("")
        self.returncode = None
        self._exit_code = exit_code
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        if self.returncode is None:
            self.returncode = 0

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self._exit_code
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def _make_tshark_line(i: int) -> str:
    """Return a single tab-separated tshark output line for a fixed 5-tuple.

    Field order (from TSHARK_FIELDS + frame.len appended):
      parts[0]  = frame.time_epoch
      parts[1]  = ip.src
      parts[2]  = ip.dst
      parts[3]  = ipv6.src       (empty)
      parts[4]  = ipv6.dst       (empty)
      parts[5]  = tcp.srcport
      parts[6]  = tcp.dstport
      parts[7]  = udp.srcport    (empty)
      parts[8]  = udp.dstport    (empty)
      parts[9]  = frame.protocols
      parts[10] = eth.src
      parts[11] = eth.dst
      parts[12] = frame.len
    """
    ts = f"1700000000.{i:06d}"
    fields = [
        ts,
        "10.0.0.5",
        "203.0.113.9",
        "",
        "",
        "50000",
        "443",
        "",
        "",
        "eth:ethertype:ip:tcp:tls",
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
        "120",
    ]
    return "\t".join(fields) + "\n"


# ---------------------------------------------------------------------------
# Test A — real parse path: cap + keep-first + count still counts all
# ---------------------------------------------------------------------------


class TestFlowSampleCapRealParsePath:
    """Monkeypatch subprocess.Popen so the parser loop runs against fake data."""

    def test_cap_limits_pkt_times_to_max_flow_samples(self, monkeypatch):
        """Emitting 200 lines for one flow with cap=50 gives count=200, len(pkt_times)=50."""
        monkeypatch.setattr(C, "MAX_FLOW_SAMPLES", 50)

        lines = [_make_tshark_line(i) for i in range(200)]
        fake = FakePopen(lines)

        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            from app.pipeline.pyshark_pass import parse_pcap_pyshark

            result = parse_pcap_pyshark(
                "/dev/null",  # existence check bypassed by monkeypatching find_bin
                limit_packets=None,
                phase=None,
                total_packets=None,
            )

        flows = result["flows"]
        assert len(flows) == 1, f"expected 1 flow, got {len(flows)}"
        flow = flows[0]

        # count must reflect ALL packets, not the cap
        assert flow["count"] == 200, f"count should be 200, got {flow['count']}"

        # stored samples must be capped
        assert len(flow["pkt_times"]) == 50, f"pkt_times should be capped at 50, got {len(flow['pkt_times'])}"
        assert len(flow["pkt_lens"]) == 50, f"pkt_lens should be capped at 50, got {len(flow['pkt_lens'])}"

    def test_cap_keep_first_semantics(self, monkeypatch):
        """The stored timestamps must be the FIRST MAX_FLOW_SAMPLES, not the last."""
        monkeypatch.setattr(C, "MAX_FLOW_SAMPLES", 50)

        lines = [_make_tshark_line(i) for i in range(200)]
        fake = FakePopen(lines)

        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            from app.pipeline.pyshark_pass import parse_pcap_pyshark

            result = parse_pcap_pyshark(
                "/dev/null",
                limit_packets=None,
                phase=None,
                total_packets=None,
            )

        flow = result["flows"][0]
        # First stored timestamp corresponds to i=0
        assert flow["pkt_times"][0] == pytest.approx(1700000000.000000, abs=1e-3)
        # 50th stored timestamp corresponds to i=49 (keep-first, not last)
        assert flow["pkt_times"][49] == pytest.approx(1700000000.000049, abs=1e-3)

    def test_cap_not_triggered_when_count_below_limit(self, monkeypatch):
        """When packet count < cap, all packets are stored and count matches."""
        monkeypatch.setattr(C, "MAX_FLOW_SAMPLES", 50)

        lines = [_make_tshark_line(i) for i in range(30)]
        fake = FakePopen(lines)

        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            from app.pipeline.pyshark_pass import parse_pcap_pyshark

            result = parse_pcap_pyshark(
                "/dev/null",
                limit_packets=None,
                phase=None,
                total_packets=None,
            )

        flow = result["flows"][0]
        assert flow["count"] == 30
        assert len(flow["pkt_times"]) == 30
        assert len(flow["pkt_lens"]) == 30


# ---------------------------------------------------------------------------
# Test A2 — true totals: bytes / first_ts / last_ts stay correct beyond the cap
# ---------------------------------------------------------------------------


class TestFlowTrueTotalsBeyondCap:
    """Scalar totals must keep tracking ALL packets after sampling stops."""

    def test_bytes_and_timestamps_track_all_packets(self, monkeypatch):
        """200 packets of 120 bytes with cap=50: bytes/first_ts/last_ts cover all 200."""
        monkeypatch.setattr(C, "MAX_FLOW_SAMPLES", 50)

        lines = [_make_tshark_line(i) for i in range(200)]
        fake = FakePopen(lines)

        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            from app.pipeline.pyshark_pass import parse_pcap_pyshark

            result = parse_pcap_pyshark(
                "/dev/null",
                limit_packets=None,
                phase=None,
                total_packets=None,
            )

        flow = result["flows"][0]
        assert flow["count"] == 200
        # True byte total: 200 packets x 120 bytes, NOT capped at 50 samples
        assert flow["bytes"] == 200 * 120
        # first_ts is the very first packet, last_ts the very last (i=199),
        # even though pkt_times stops at i=49.
        assert flow["first_ts"] == float("1700000000.000000")
        assert flow["last_ts"] == float("1700000000.000199")
        assert max(flow["pkt_times"]) < flow["last_ts"]


# ---------------------------------------------------------------------------
# Test A3 — flow asymmetry must use the true byte total, not the capped sum
# ---------------------------------------------------------------------------


class TestFlowAsymmetryUsesTrueBytes:
    """detect_flow_asymmetry prefers flow['bytes'] over sum of capped pkt_lens."""

    def test_capped_flow_bytes_field_triggers_detection(self):
        """A 16 MB exfil flow whose capped pkt_lens sum to only 80 KB must still flag."""
        flows = [
            {
                # 20,000 packets x 800 bytes = 16 MB true outbound volume,
                # but only 100 sampled pkt_lens survived the cap (80 KB —
                # far below the 1 MB ASYMMETRY_MIN_BYTES threshold).
                "src": "10.0.0.5",
                "dst": "203.0.113.9",
                "sport": "50000",
                "dport": "443",
                "proto": "tcp",
                "count": 20000,
                "bytes": 20000 * 800,
                "pkt_times": [float(i) for i in range(100)],
                "pkt_lens": [800] * 100,
            },
            {
                # Tiny inbound direction
                "src": "203.0.113.9",
                "dst": "10.0.0.5",
                "sport": "443",
                "dport": "50000",
                "proto": "tcp",
                "count": 10,
                "bytes": 10 * 100,
                "pkt_times": [float(i) for i in range(10)],
                "pkt_lens": [100] * 10,
            },
        ]

        results = detect_flow_asymmetry(flows)
        assert len(results) >= 1, "true 16 MB outbound volume must be detected despite capped pkt_lens"
        top = results[0]
        assert top.outbound_bytes == 16_000_000
        assert top.is_suspicious
        assert top.ratio > 10

    def test_fallback_to_pkt_lens_when_bytes_missing(self):
        """Legacy flows without the bytes field keep the old sum(pkt_lens) path."""
        flows = [
            {"src": "10.0.0.1", "dst": "1.2.3.4", "count": 2000, "pkt_lens": [1000] * 2000},
            {"src": "1.2.3.4", "dst": "10.0.0.1", "count": 10, "pkt_lens": [100] * 10},
        ]
        results = detect_flow_asymmetry(flows)
        assert len(results) >= 1
        assert results[0].outbound_bytes == 2_000_000


# ---------------------------------------------------------------------------
# Test A4 — beacon pkts column shows the true packet total, not sample length
# ---------------------------------------------------------------------------


class TestBeaconPktsShowsTrueCount:
    """rank_beaconing displays flow['count'] in pkts; scoring stays on samples."""

    def _make_flow(self, count: int | None, n_samples: int) -> dict:
        flow = {
            "src": "10.0.0.5",
            "dst": "203.0.113.9",
            "sport": "50000",
            "dport": "80",
            "proto": "tcp",
            "pkt_times": [float(i * 30) for i in range(n_samples)],
            "pkt_lens": [120] * n_samples,
        }
        if count is not None:
            flow["count"] = count
        return flow

    def test_pkts_equals_flow_count_on_capped_flow(self):
        """count=8000 with 5000 sampled timestamps must display pkts == 8000."""
        df = rank_beaconing([self._make_flow(count=8000, n_samples=5000)], top_n=5)
        assert not df.empty
        assert int(df.iloc[0]["pkts"]) == 8000

    def test_pkts_falls_back_to_sample_len_without_count(self):
        """Flows without a count key (legacy/test data) fall back to len(pkt_times)."""
        df = rank_beaconing([self._make_flow(count=None, n_samples=50)], top_n=5)
        assert not df.empty
        assert int(df.iloc[0]["pkts"]) == 50


# ---------------------------------------------------------------------------
# Test B — beacon stability: score is stable across 2000 vs 5000 samples
# ---------------------------------------------------------------------------


class TestBeaconStabilityWithSampleCap:
    """Verify that rank_beaconing scores a periodic flow similarly at 2000 and 5000 samples."""

    def _make_periodic_flows(self, n: int) -> list[dict]:
        return [
            {
                "src": "10.0.0.5",
                "dst": "203.0.113.9",
                "sport": "50000",
                "dport": "80",  # use port 80 (moderate penalty) to keep score visible
                "proto": "tcp",
                "count": n,
                "pkt_times": [float(i * 30) for i in range(n)],
                "pkt_lens": [120] * n,
            }
        ]

    def test_beacon_score_stable_2000_vs_5000(self):
        df_small = rank_beaconing(self._make_periodic_flows(2000), top_n=5)
        df_big = rank_beaconing(self._make_periodic_flows(5000), top_n=5)

        assert not df_small.empty, "rank_beaconing returned empty for 2000-sample flow"
        assert not df_big.empty, "rank_beaconing returned empty for 5000-sample flow"

        score_small = df_small.iloc[0]["score"]
        score_big = df_big.iloc[0]["score"]

        assert abs(score_small - score_big) < 0.05, (
            f"Beacon score diverged too much between 2000 and 5000 samples: "
            f"small={score_small:.4f}, big={score_big:.4f}, delta={abs(score_small - score_big):.4f}"
        )


# ---------------------------------------------------------------------------
# Test C — runner beacon strip: pkt_times/pkt_lens must not appear in records
# ---------------------------------------------------------------------------


class TestRunnerBeaconStrip:
    """Ensure _run_beacon strips pkt_times/pkt_lens from serialized beacon records."""

    def test_beacon_records_have_no_pkt_times_or_pkt_lens(self, monkeypatch, tmp_path):
        """If rank_beaconing were to return a DataFrame with pkt_times/pkt_lens columns,
        runner._run_beacon must strip them before writing to beacon_df_records.
        """
        import app.pipeline.runner as R
        from app.pipeline.progress import CallbackProgress
        from app.pipeline.runner import PipelineOptions, run_pipeline

        pcap = tmp_path / "fake.pcap"
        pcap.write_bytes(b"")

        # Stub all upstream stages
        features = {
            "flows": [
                {
                    "src": "10.0.0.5",
                    "dst": "203.0.113.9",
                    "sport": "50000",
                    "dport": "443",
                    "proto": "tcp",
                    "count": 200,
                    "pkt_times": [float(i) for i in range(200)],
                    "pkt_lens": [120] * 200,
                }
            ],
            "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": [], "macs": []},
        }

        # Return a DataFrame that *includes* pkt_times/pkt_lens columns to simulate
        # a hypothetical future regression where they leak into the output.
        def _fake_rank_beaconing(flows, **kwargs):
            return pd.DataFrame(
                [
                    {
                        "src": "10.0.0.5",
                        "dst": "203.0.113.9",
                        "sport": "50000",
                        "dport": "443",
                        "proto": "tcp",
                        "pkts": 200,
                        "mean_gap": 1.0,
                        "std_gap": 0.0,
                        "cv": 0.0,
                        "entropy": 0.5,
                        "score": 0.85,
                        "dominant_interval": 1.0,
                        "jitter_pct": 0.0,
                        # Deliberately injected to test that the strip guard works:
                        "pkt_times": [float(i) for i in range(200)],
                        "pkt_lens": [120] * 200,
                    }
                ]
            )

        monkeypatch.setattr(R, "count_packets_fast", lambda p: 200)
        monkeypatch.setattr(R, "parse_pcap_pyshark", lambda p, **kw: features)
        monkeypatch.setattr(R, "run_zeek", lambda p, d, phase=None: {})
        monkeypatch.setattr(R, "rank_beaconing", _fake_rank_beaconing)
        monkeypatch.setattr(R, "carve_http_payloads", lambda *a, **kw: [])

        result = run_pipeline(
            pcap_path=str(pcap),
            case_id="strip_test",
            options=PipelineOptions(
                osint_enabled=False,
                llm_enabled=False,
                do_pyshark=True,
                do_zeek=False,
                do_carve=False,
                do_yara=False,
                pre_count=True,
            ),
            progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
        )

        assert result.beacon_df_records, "expected at least one beacon record"
        for rec in result.beacon_df_records:
            assert "pkt_times" not in rec, f"pkt_times leaked into beacon record: {list(rec.keys())}"
            assert "pkt_lens" not in rec, f"pkt_lens leaked into beacon record: {list(rec.keys())}"
