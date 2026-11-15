"""Zeek log loading: malformed lines, row caps, and the extended log set."""

from __future__ import annotations

import json
import logging
import subprocess
from unittest.mock import patch

from app import config as C
from app.pipeline import zeek as zeek_mod
from app.pipeline.zeek import ATTR_BAD_LINES, ATTR_TOTAL_ROWS, ATTR_TRUNCATED, load_zeek_any


def _dns_row(i: int) -> dict:
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
        "query": f"host{i}.example.com",
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


_ASCII_HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tdns\n"
    "#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\n"
    "#types\ttime\tstring\taddr\taddr\tstring\n"
)


class TestJsonLines:
    def test_one_bad_line_keeps_the_rest(self, tmp_path, caplog):
        path = tmp_path / "dns.log"
        lines = [json.dumps(_dns_row(i)) for i in range(10)]
        lines.insert(4, '{"ts": 1700000004.5, "query": "truncated.exam')  # torn write
        lines.insert(8, "[1, 2, 3]")  # valid JSON, but not a record
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="app.pipeline.zeek"):
            df = load_zeek_any(str(path))

        assert len(df) == 10
        assert df["query"].tolist() == [f"host{i}.example.com" for i in range(10)]
        assert df.attrs[ATTR_BAD_LINES] == 2
        assert df.attrs[ATTR_TOTAL_ROWS] == 12
        assert df.attrs[ATTR_TRUNCATED] is False
        assert any("skipped 2 malformed" in rec.getMessage() for rec in caplog.records)

    def test_corrupt_first_line_does_not_discard_the_log(self, tmp_path):
        path = tmp_path / "dns.log"
        path.write_text("garbage-not-json\n" + json.dumps(_dns_row(1)) + "\n", encoding="utf-8")
        df = load_zeek_any(str(path))
        assert df["query"].tolist() == ["host1.example.com"]
        assert df.attrs[ATTR_BAD_LINES] == 1

    def test_max_rows_caps_memory_but_counts_everything(self, tmp_path):
        path = tmp_path / "dns.log"
        path.write_text("\n".join(json.dumps(_dns_row(i)) for i in range(50)) + "\n", encoding="utf-8")
        df = load_zeek_any(str(path), max_rows=20)
        assert len(df) == 20
        assert df["query"].iloc[-1] == "host19.example.com"  # leading rows, in order
        assert df.attrs[ATTR_TOTAL_ROWS] == 50
        assert df.attrs[ATTR_TRUNCATED] is True

    def test_no_cap_by_default_and_zero_means_no_cap(self, tmp_path):
        path = tmp_path / "dns.log"
        path.write_text("\n".join(json.dumps(_dns_row(i)) for i in range(30)) + "\n", encoding="utf-8")
        assert len(load_zeek_any(str(path))) == 30
        df = load_zeek_any(str(path), max_rows=0)
        assert len(df) == 30 and df.attrs[ATTR_TRUNCATED] is False

    def test_empty_file_gives_empty_frame(self, tmp_path):
        path = tmp_path / "dns.log"
        path.write_text("", encoding="utf-8")
        df = load_zeek_any(str(path))
        assert df.empty and df.attrs[ATTR_TOTAL_ROWS] == 0


class TestAsciiLogs:
    def test_ascii_log_still_loads_and_counts_bad_rows(self, tmp_path):
        path = tmp_path / "dns.log"
        body = (
            "1700000000.1\tC1\t10.0.0.5\t10.0.0.1\ta.example.com\n"
            "1700000001.1\tC2\t10.0.0.5\n"  # short row
            "1700000002.1\tC3\t10.0.0.5\t10.0.0.1\tb.example.com\n"
            "#close\t2024-01-01-00-00-00\n"
        )
        path.write_text(_ASCII_HEADER + body, encoding="utf-8")
        df = load_zeek_any(str(path))
        assert df["query"].tolist() == ["a.example.com", "b.example.com"]
        assert list(df.columns) == ["ts", "uid", "id.orig_h", "id.resp_h", "query"]
        assert df.attrs[ATTR_BAD_LINES] == 1
        assert df.attrs[ATTR_TOTAL_ROWS] == 3

    def test_ascii_log_respects_max_rows(self, tmp_path):
        path = tmp_path / "dns.log"
        body = "".join(f"170000000{i}.1\tC{i}\t10.0.0.5\t10.0.0.1\th{i}.example.com\n" for i in range(9))
        path.write_text(_ASCII_HEADER + body, encoding="utf-8")
        df = load_zeek_any(str(path), max_rows=4)
        assert len(df) == 4 and df.attrs[ATTR_TRUNCATED] is True and df.attrs[ATTR_TOTAL_ROWS] == 9


class TestCollectedLogs:
    def _run(self, tmp_path, present: list[str]) -> dict[str, str]:
        for name in present:
            (tmp_path / name).write_text("{}\n", encoding="utf-8")
        completed = subprocess.CompletedProcess(args=["zeek"], returncode=0, stdout="", stderr="")
        with (
            patch.object(zeek_mod, "find_bin", return_value="/usr/bin/zeek"),
            patch.object(zeek_mod.subprocess, "run", return_value=completed),
        ):
            return zeek_mod.run_zeek("dummy.pcap", str(tmp_path))

    def test_extra_logs_are_collected_under_their_own_names(self, tmp_path):
        present = ["conn.log", "dns.log", "http.log", "ssl.log", "files.log", "notice.log", "weird.log", "x509.log"]
        logs = self._run(tmp_path, present + ["packet_filter.log"])
        assert set(logs) == set(present)  # unknown logs are still ignored
        assert logs["weird.log"] == str(tmp_path / "weird.log")
        # the long-standing four keep their position at the front
        assert list(logs)[:4] == ["conn.log", "dns.log", "http.log", "ssl.log"]

    def test_absent_extras_do_not_appear(self, tmp_path):
        logs = self._run(tmp_path, ["conn.log", "dns.log"])
        assert list(logs) == ["conn.log", "dns.log"]

    def test_core_logs_survive_a_trimmed_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(C, "ZEEK_LOG_NAMES", ("weird.log",))
        logs = self._run(tmp_path, ["conn.log", "ssl.log", "weird.log", "x509.log"])
        assert list(logs) == ["conn.log", "ssl.log", "weird.log"]
