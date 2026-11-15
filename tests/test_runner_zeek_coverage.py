"""Runner wiring: analyzers get full Zeek tables, partial coverage is reported, limit resolution."""

from __future__ import annotations

import json

import pandas as pd
import pytest

from app import config as C
from app.analysis.visibility import build_capture_metrics
from app.pipeline import runner as R
from app.pipeline.progress import CallbackProgress
from app.pipeline.runner import PipelineOptions, resolve_packet_limit, run_pipeline

LATE_DOMAIN = "late-beacon-c2.example.net"


def _dns_row(i: int, query: str | None = None) -> dict:
    """One record shaped like Zeek's JSON dns.log."""
    return {
        "ts": 1700000000.0 + i,
        "uid": f"C{i:06d}",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 50000 + (i % 1000),
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": i % 65535,
        "query": query or f"host{i % 50}.example.com",
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": 1,
        "qtype_name": "A",
        "rcode": 0,
        "rcode_name": "NOERROR",
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": ["93.184.216.34"],
        "TTLs": [300.0],
        "rejected": False,
    }


def _ssl_row(i: int) -> dict:
    return {
        "ts": 1700000000.0 + i,
        "uid": f"S{i:06d}",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 51000 + (i % 1000),
        "id.resp_h": "203.0.113.9",
        "id.resp_p": 443,
        "version": "TLSv12",
        "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "server_name": f"srv{i % 7}.example.com",
        "resumed": False,
        "established": True,
    }


def _features() -> dict:
    """parse_pcap_pyshark output shape (flows + sorted-list artifacts + parse_stats)."""
    return {
        "flows": [
            {
                "src": "10.0.0.5",
                "dst": "203.0.113.9",
                "sport": "50000",
                "dport": "443",
                "proto": "tls",
                "count": 3,
                "bytes": 360,
                "first_ts": 1700000000.0,
                "last_ts": 1700000002.0,
                "pkt_times": [1700000000.0, 1700000001.0, 1700000002.0],
                "pkt_lens": [120, 120, 120],
                "mac_src": "aa:bb:cc:dd:ee:01",
                "mac_dst": "aa:bb:cc:dd:ee:02",
            }
        ],
        "artifacts": {
            "ips": ["10.0.0.5", "203.0.113.9"],
            "domains": [],
            "urls": [],
            "hashes": [],
            "ja3": [],
            "macs": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
        },
        "parse_stats": {
            "lines_read": 3,
            "skipped_lines": 0,
            "packet_limit": 200000,
            "limit_reached": False,
            "timed_out": False,
            "error": None,
        },
    }


def _write_jsonl(path, rows) -> str:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """Run the real runner + real Zeek loader/DNS analyzer against on-disk Zeek logs."""
    monkeypatch.setattr(C, "ZEEK_DIR", tmp_path / "zeek")
    monkeypatch.setattr(C, "CARVE_DIR", tmp_path / "carved")
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00")
    seen: dict = {}

    def fake_tls(pcap_path=None, zeek_tables=None, phase=None):
        seen["tls_tables"] = zeek_tables
        return {"total_certificates": 0, "certificates": []}

    monkeypatch.setattr(R, "count_packets_fast", lambda p: 3)
    monkeypatch.setattr(R, "analyze_certificates", fake_tls)

    def run(logs: dict[str, str], features: dict | None = None, **option_overrides):
        feats = features if features is not None else _features()
        monkeypatch.setattr(R, "run_zeek", lambda p, d, phase=None: dict(logs))

        def fake_parse(path, **kwargs):
            seen["parse_kwargs"] = kwargs
            return feats

        monkeypatch.setattr(R, "parse_pcap_pyshark", fake_parse)
        options = PipelineOptions(osint_enabled=False, llm_enabled=False, do_carve=False, **option_overrides)
        result = run_pipeline(
            pcap_path=str(pcap),
            case_id="coverage_test",
            options=options,
            progress=CallbackProgress(callback=lambda _e: None, total_phases=0),
        )
        return result, seen

    return run, tmp_path


class TestFullTablesReachAnalyzers:
    def test_dns_analysis_sees_rows_beyond_the_display_sample(self, pipeline):
        run, tmp_path = pipeline
        rows = [_dns_row(i) for i in range(4999)] + [_dns_row(4999, LATE_DOMAIN)]
        logs = {
            "dns.log": _write_jsonl(tmp_path / "dns.log", rows),
            "ssl.log": _write_jsonl(tmp_path / "ssl.log", [_ssl_row(i) for i in range(2500)]),
        }

        result, seen = run(logs)

        # Analyzers: every record, including the one at the very end of the capture.
        assert result.dns_analysis["total_records"] == 5000
        assert LATE_DOMAIN in result.features["artifacts"]["domains"]
        assert len(seen["tls_tables"]["ssl.log"]) == 2500
        assert len(seen["tls_tables"]["dns.log"]) == 5000

        # Stored/displayed tables stay a bounded sample.
        assert len(result.zeek_tables["dns.log"]) == C.ZEEK_DISPLAY_ROWS == 2000
        assert len(result.zeek_tables["ssl.log"]) == 2000
        assert isinstance(result.zeek_tables["dns.log"], pd.DataFrame)

        # The sampling is reported, not silent.
        coverage = result.features["coverage"]["zeek"]["dns.log"]
        assert coverage == {
            "total_rows": 5000,
            "loaded_rows": 5000,
            "analyzed_rows": 5000,
            "displayed_rows": 2000,
            "bad_lines": 0,
            "analysis_truncated": False,
            "display_truncated": True,
        }
        limitations = result.capture_metrics["limitations"]
        assert any("leading samples" in lim and "dns.log (2,000 of 5,000)" in lim for lim in limitations)
        assert result.capture_metrics["zeek_coverage"]["ssl.log"]["display_truncated"] is True
        assert "zeek_rows_capped" not in result.warnings  # sampling for display is not a warning

    def test_limitation_survives_a_later_metrics_rebuild(self, pipeline):
        """Callers rebuild capture metrics from features + display tables after OSINT/restore."""
        run, tmp_path = pipeline
        logs = {"dns.log": _write_jsonl(tmp_path / "dns.log", [_dns_row(i) for i in range(2100)])}
        result, _ = run(logs)

        persisted_features = json.loads(json.dumps(result.features))  # SQLite round trip
        rebuilt = build_capture_metrics(
            {
                "features": persisted_features,
                "__total_pkts": result.packet_count,
                "dns_analysis": result.dns_analysis,
                "tls_analysis": result.tls_analysis,
                "zeek_tables": result.zeek_tables,
                "pipeline_warnings": result.warnings,
            }
        )
        assert any("dns.log (2,000 of 2,100)" in lim for lim in rebuilt["limitations"])

    def test_small_logs_report_no_coverage_limitation(self, pipeline):
        run, tmp_path = pipeline
        logs = {"dns.log": _write_jsonl(tmp_path / "dns.log", [_dns_row(i) for i in range(20)])}
        result, _ = run(logs)
        assert len(result.zeek_tables["dns.log"]) == 20
        assert not any("Zeek" in lim for lim in result.capture_metrics["limitations"])
        assert result.warnings == []

    def test_row_cap_guards_memory_and_warns(self, pipeline, monkeypatch):
        run, tmp_path = pipeline
        monkeypatch.setattr(C, "ZEEK_ANALYSIS_MAX_ROWS", 3000)
        rows = [_dns_row(i) for i in range(4999)] + [_dns_row(4999, LATE_DOMAIN)]
        logs = {"dns.log": _write_jsonl(tmp_path / "dns.log", rows)}

        result, seen = run(logs)

        assert len(seen["tls_tables"]["dns.log"]) == 3000
        assert result.dns_analysis["total_records"] == 3000
        assert LATE_DOMAIN not in result.features["artifacts"]["domains"]
        assert "zeek_rows_capped" in result.warnings
        assert any(
            "row cap" in lim and "dns.log (first 3,000 of 5,000 rows)" in lim
            for lim in result.capture_metrics["limitations"]
        )

    def test_bad_zeek_lines_keep_the_log_and_warn(self, pipeline):
        run, tmp_path = pipeline
        path = tmp_path / "dns.log"
        lines = [json.dumps(_dns_row(i)) for i in range(30)]
        lines.insert(10, '{"ts": 1700000010.5, "query": "torn.exa')
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result, _ = run({"dns.log": str(path)})

        assert result.dns_analysis["total_records"] == 30
        assert "zeek_bad_lines" in result.warnings
        assert any(
            "Malformed Zeek log lines were skipped: dns.log (1)" in lim for lim in result.capture_metrics["limitations"]
        )

    def test_extra_zeek_logs_are_exposed_without_touching_existing_keys(self, pipeline):
        run, tmp_path = pipeline
        weird = [{"ts": 1700000000.0, "uid": "C1", "name": "bad_TCP_checksum", "notice": False, "peer": "zeek"}]
        logs = {
            "dns.log": _write_jsonl(tmp_path / "dns.log", [_dns_row(i) for i in range(5)]),
            "weird.log": _write_jsonl(tmp_path / "weird.log", weird),
        }
        result, _ = run(logs)
        assert set(result.zeek_tables) == {"dns.log", "weird.log"}
        assert result.zeek_tables["weird.log"]["name"].tolist() == ["bad_TCP_checksum"]
        assert result.dns_analysis["total_records"] == 5


class TestZeekMemoryBounds:
    def test_default_row_cap_is_200k(self):
        assert C.ZEEK_ANALYSIS_MAX_ROWS == 200_000

    def test_only_analyzer_logs_are_loaded_at_full_size(self, pipeline, monkeypatch):
        run, tmp_path = pipeline
        conn = [
            {
                "ts": 1700000000.0 + i,
                "uid": f"C{i}",
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "203.0.113.9",
                "proto": "tcp",
            }
            for i in range(2600)
        ]
        logs = {
            "dns.log": _write_jsonl(tmp_path / "dns.log", [_dns_row(i) for i in range(2500)]),
            "ssl.log": _write_jsonl(tmp_path / "ssl.log", [_ssl_row(i) for i in range(2300)]),
            "conn.log": _write_jsonl(tmp_path / "conn.log", conn),
        }
        requested: dict[str, int | None] = {}
        real_load = R.load_zeek_any

        def recording_load(path, max_rows=None):
            requested[path.rsplit("/", 1)[-1]] = max_rows
            return real_load(path, max_rows=max_rows)

        monkeypatch.setattr(R, "load_zeek_any", recording_load)

        result, seen = run(logs)

        assert requested == {
            "dns.log": C.ZEEK_ANALYSIS_MAX_ROWS,
            "ssl.log": C.ZEEK_ANALYSIS_MAX_ROWS,
            "conn.log": C.ZEEK_DISPLAY_ROWS,
        }
        assert set(seen["tls_tables"]) == {"dns.log", "ssl.log"}  # nothing else is held in full
        assert len(result.zeek_tables["conn.log"]) == 2000
        # Rows loaded vs rows in the file stay accurate for the display-only log,
        # and sampling it for display is not reported as an analysis row cap.
        assert result.features["coverage"]["zeek"]["conn.log"] == {
            "total_rows": 2600,
            "loaded_rows": 2000,
            "analyzed_rows": 2600,
            "displayed_rows": 2000,
            "bad_lines": 0,
            "analysis_truncated": False,
            "display_truncated": True,
        }
        assert "zeek_rows_capped" not in result.warnings
        limitations = result.capture_metrics["limitations"]
        assert any("leading samples" in lim and "conn.log (2,000 of 2,600)" in lim for lim in limitations)
        assert not any("row cap" in lim for lim in limitations)

    def test_display_sample_is_an_independent_copy_and_full_tables_are_released(self, pipeline, monkeypatch):
        import gc
        import weakref

        run, tmp_path = pipeline
        logs = {"dns.log": _write_jsonl(tmp_path / "dns.log", [_dns_row(i) for i in range(2500)])}
        full_refs: list[weakref.ref] = []
        alive_after_analysis: list[bool] = []

        def fake_tls(pcap_path=None, zeek_tables=None, phase=None):
            full = zeek_tables["dns.log"]
            buffer = full["ts"].to_numpy()
            while isinstance(buffer.base, type(buffer)):
                buffer = buffer.base  # the block the full table's column lives in
            full_refs.extend([weakref.ref(full), weakref.ref(buffer)])  # no strong reference kept
            return {"total_certificates": 0, "certificates": []}

        real_metrics = R.build_capture_metrics

        def metrics_after_analysis(state):
            gc.collect()
            alive_after_analysis.append(any(ref() is not None for ref in full_refs))
            return real_metrics(state)

        monkeypatch.setattr(R, "analyze_certificates", fake_tls)
        monkeypatch.setattr(R, "build_capture_metrics", metrics_after_analysis)

        result, _ = run(logs)

        # Neither the full table nor its column buffers survive: the display sample is an
        # independent copy, not a view that would pin the full table's memory.
        assert alive_after_analysis == [False]
        display = result.zeek_tables["dns.log"]
        assert len(display) == 2000
        assert display["query"].iloc[0] == "host0.example.com"


class TestParserWarnings:
    def test_skipped_lines_and_timeout_surface_as_warnings_and_limitations(self, pipeline, tmp_path):
        run, tmp_path = pipeline
        feats = _features()
        feats["parse_stats"].update({"skipped_lines": 7, "timed_out": True, "error": "tshark timed out after 900s"})
        logs = {"dns.log": _write_jsonl(tmp_path / "dns.log", [_dns_row(i) for i in range(5)])}

        result, _ = run(logs, features=feats)

        assert "pyshark_lines_skipped" in result.warnings
        assert "pyshark_timeout" in result.warnings
        assert "pyshark_pass" in result.stages_run
        assert result.capture_metrics["parse_skipped_lines"] == 7
        limitations = result.capture_metrics["limitations"]
        assert any("skipped 7 malformed tshark line" in lim for lim in limitations)
        assert any("time limit" in lim for lim in limitations)

    def test_features_without_parse_stats_are_still_accepted(self, pipeline):
        """Saved analyses and older callers have no parse_stats/coverage keys."""
        run, tmp_path = pipeline
        feats = _features()
        del feats["parse_stats"]
        result, _ = run({}, features=feats, do_zeek=False)
        assert result.warnings == []
        assert result.capture_metrics["parse_skipped_lines"] == 0
        assert result.capture_metrics["zeek_coverage"] == {}


class TestPacketLimitResolution:
    def test_none_resolves_to_the_config_default(self, monkeypatch):
        monkeypatch.setattr(C, "DEFAULT_PYSHARK_LIMIT", 12345)
        assert resolve_packet_limit(None) == 12345

    def test_zero_and_negative_are_explicitly_unlimited(self):
        assert resolve_packet_limit(0) == 0
        assert resolve_packet_limit(-5) == 0

    def test_positive_values_pass_through(self):
        assert resolve_packet_limit(50) == 50
        assert resolve_packet_limit("750") == 750

    def test_unusable_values_fall_back_to_the_default(self):
        assert resolve_packet_limit("lots") == C.DEFAULT_PYSHARK_LIMIT
        assert resolve_packet_limit(True) == C.DEFAULT_PYSHARK_LIMIT

    @pytest.mark.parametrize(("option", "expected"), [(None, 200000), (0, 0), (5000, 5000)])
    def test_runner_passes_the_resolved_limit_to_the_parser(self, pipeline, option, expected):
        run, _ = pipeline
        _, seen = run({}, do_zeek=False, pyshark_packet_limit=option)
        assert seen["parse_kwargs"]["limit_packets"] == expected
