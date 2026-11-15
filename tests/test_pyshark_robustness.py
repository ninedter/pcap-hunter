"""parse_pcap_pyshark: malformed lines, watchdog timeout, stderr handling, return shape."""

from __future__ import annotations

import io
import subprocess
import threading
from unittest.mock import patch

from app import config as C
from app.pipeline import pyshark_pass
from app.pipeline.pyshark_pass import parse_pcap_pyshark

ARTIFACT_KEYS = {"ips", "domains", "urls", "hashes", "ja3", "macs"}


def _line(i: int, *, ts: str | None = None, length: str = "120", src: str = "10.0.0.5") -> str:
    """One tshark `-T fields` line: TSHARK_FIELDS order + frame.len."""
    fields = [
        ts if ts is not None else f"1700000000.{i:06d}",
        src,
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
        length,
    ]
    return "\t".join(fields) + "\n"


class FakePopen:
    """Popen stand-in: iterable stdout, readable stderr, kill/wait bookkeeping."""

    def __init__(self, lines, exit_code=0, stderr_text="", block_event: threading.Event | None = None):
        self._lines = list(lines)
        self._block_event = block_event
        self.stdout = self._gen()
        self.stderr = io.StringIO(stderr_text)
        self.returncode = None
        self._exit_code = exit_code
        self.killed = False

    def _gen(self):
        yield from self._lines
        if self._block_event is not None:
            self._block_event.wait(10)  # a hung tshark: stdout never reaches EOF until killed

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self._exit_code
        return self.returncode

    def terminate(self):
        self.kill()

    def kill(self):
        self.killed = True
        self.returncode = -9
        if self._block_event is not None:
            self._block_event.set()


def _parse(fake: FakePopen, limit=None, popen_spy=None):
    popen = popen_spy if popen_spy is not None else (lambda *a, **k: fake)
    with (
        patch.object(pyshark_pass, "find_bin", return_value="/usr/bin/tshark"),
        patch.object(pyshark_pass.subprocess, "Popen", side_effect=popen),
    ):
        return parse_pcap_pyshark("/dev/null", limit_packets=limit, phase=None, total_packets=None)


class TestMalformedLines:
    def test_bad_number_costs_one_packet_not_the_rest(self):
        lines = [_line(0), _line(1), _line(2, ts="not-a-float"), _line(3, length="12x"), _line(4), _line(5)]
        out = _parse(FakePopen(lines))

        assert len(out["flows"]) == 1
        flow = out["flows"][0]
        assert flow["count"] == 4, "packets after the malformed lines must still be parsed"
        assert flow["bytes"] == 4 * 120
        assert flow["last_ts"] == 1700000000.000005
        assert out["parse_stats"]["skipped_lines"] == 2
        assert out["parse_stats"]["lines_read"] == 6
        assert out["parse_stats"]["error"] is None

    def test_short_line_is_counted_and_blank_line_is_not(self):
        lines = [_line(0), "1700000000.5\t10.0.0.5\n", "\n", _line(1)]
        out = _parse(FakePopen(lines))
        assert out["flows"][0]["count"] == 2
        assert out["parse_stats"]["skipped_lines"] == 1

    def test_comma_joined_numeric_fields_take_the_first_value(self):
        out = _parse(FakePopen([_line(0, ts="1700000000.25,1700000000.75", length="120,60")]))
        assert out["flows"][0]["first_ts"] == 1700000000.25
        assert out["flows"][0]["bytes"] == 120
        assert out["parse_stats"]["skipped_lines"] == 0


class TestReturnShape:
    def _assert_shape(self, out):
        assert set(out) == {"flows", "artifacts", "parse_stats"}
        assert set(out["artifacts"]) == ARTIFACT_KEYS
        assert all(isinstance(v, list) for v in out["artifacts"].values())
        assert {"lines_read", "skipped_lines", "timed_out", "limit_reached", "packet_limit", "error"} <= set(
            out["parse_stats"]
        )

    def test_missing_pcap(self, tmp_path):
        out = parse_pcap_pyshark(str(tmp_path / "nope.pcap"), limit_packets=None, phase=None, total_packets=None)
        self._assert_shape(out)
        assert out["parse_stats"]["error"] == "pcap_not_found"

    def test_missing_tshark(self):
        with patch.object(pyshark_pass, "find_bin", return_value=None):
            out = parse_pcap_pyshark("/dev/null", limit_packets=None, phase=None, total_packets=None)
        self._assert_shape(out)
        assert out["parse_stats"]["error"] == "tshark_not_found"

    def test_popen_failure(self):
        def boom(*a, **k):
            raise OSError("exec format error")

        out = _parse(FakePopen([]), popen_spy=boom)
        self._assert_shape(out)
        assert "exec format error" in out["parse_stats"]["error"]

    def test_success(self):
        out = _parse(FakePopen([_line(0)]))
        self._assert_shape(out)
        assert out["artifacts"]["macs"] == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
        assert out["artifacts"]["ips"] == ["10.0.0.5", "203.0.113.9"]


class TestPacketLimit:
    def _cmd_for(self, limit):
        seen = {}

        def spy(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            return FakePopen([_line(i) for i in range(10)])

        out = _parse(None, limit=limit, popen_spy=spy)
        return seen, out

    def test_positive_limit_is_passed_to_tshark_and_enforced(self):
        seen, out = self._cmd_for(4)
        assert seen["cmd"][-2:] == ["-c", "4"]
        assert out["flows"][0]["count"] == 4
        assert out["parse_stats"]["limit_reached"] is True
        assert out["parse_stats"]["packet_limit"] == 4

    def test_none_and_zero_mean_unlimited_at_this_layer(self):
        for limit in (None, 0, -1):
            seen, out = self._cmd_for(limit)
            assert "-c" not in seen["cmd"], limit
            assert out["flows"][0]["count"] == 10
            assert out["parse_stats"]["packet_limit"] is None
            assert out["parse_stats"]["limit_reached"] is False

    def test_stderr_is_a_pipe_that_gets_drained(self):
        seen, _ = self._cmd_for(None)
        assert seen["kwargs"]["stderr"] == subprocess.PIPE


class TestWatchdogAndStderr:
    def test_hung_tshark_is_killed_and_partial_flows_are_flagged(self, monkeypatch):
        monkeypatch.setattr(C, "PYSHARK_TIMEOUT_SECONDS", 0.2)
        fake = FakePopen([_line(0), _line(1)], block_event=threading.Event())

        out = _parse(fake)

        assert fake.killed is True
        assert out["parse_stats"]["timed_out"] is True
        assert "timed out" in out["parse_stats"]["error"]
        assert out["flows"][0]["count"] == 2  # what was parsed before the timeout is kept

    def test_nonzero_exit_is_reported_with_stderr(self, caplog):
        fake = FakePopen([_line(0)], exit_code=2, stderr_text="tshark: The file appears to be damaged or corrupt.\n")
        with caplog.at_level("ERROR", logger="app.runtime"):
            out = _parse(fake)
        assert out["parse_stats"]["error"] == "tshark exited with code 2"
        assert out["flows"][0]["count"] == 1
        assert any("damaged or corrupt" in rec.getMessage() for rec in caplog.records)

    def test_large_stderr_does_not_block_parsing(self):
        """Real child process: >64KB on stderr before stdout must not deadlock the reader."""
        import sys

        script = (
            "import sys\n"
            "sys.stderr.write('w' * 300000 + '\\n'); sys.stderr.flush()\n"
            "sys.stdout.write(sys.argv[1]); sys.stdout.flush()\n"
        )
        payload = "".join(_line(i) for i in range(3))
        real_popen = subprocess.Popen

        def spawn(cmd, **kwargs):
            return real_popen([sys.executable, "-c", script, payload], **kwargs)

        with (
            patch.object(pyshark_pass, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(pyshark_pass.subprocess, "Popen", side_effect=spawn),
            patch.object(C, "PYSHARK_TIMEOUT_SECONDS", 20),
        ):
            out = parse_pcap_pyshark("/dev/null", limit_packets=None, phase=None, total_packets=None)

        assert out["parse_stats"]["timed_out"] is False
        assert out["flows"][0]["count"] == 3
