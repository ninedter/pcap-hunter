import subprocess
from unittest.mock import patch

from app.pipeline.pyshark_pass import parse_pcap_pyshark


def test_parse_pcap_missing_file():
    result = parse_pcap_pyshark("non_existent.pcap", None, None, None)
    assert result["flows"] == []
    assert len(result["artifacts"]["ips"]) == 0


def test_parse_pcap_invalid_limit():
    # Should handle invalid limit gracefully (log error and continue with None)
    # We need to mock os.path.exists to pass the first check
    with patch("os.path.exists", return_value=True):
        # And mock find_bin to avoid actual tshark call or failure
        with patch("app.pipeline.pyshark_pass.find_bin", return_value=None):
            result = parse_pcap_pyshark("test.pcap", "invalid", None, None)
            # It should return empty result because tshark is not found (mocked None)
            # But importantly, it shouldn't crash on "invalid" limit
            assert result["flows"] == []


def test_parse_pcap_tshark_missing():
    with patch("os.path.exists", return_value=True):
        with patch("app.pipeline.pyshark_pass.find_bin", return_value=None):
            result = parse_pcap_pyshark("test.pcap", 100, None, None)
            assert result["flows"] == []


class TestSubprocessTimeouts:
    def test_run_zeek_passes_timeout(self, tmp_path):
        from app.pipeline import zeek as zeek_mod

        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(kwargs)
            raise subprocess.CalledProcessError(1, cmd, stderr="boom")

        with (
            patch.object(zeek_mod, "find_bin", return_value="/usr/bin/zeek"),
            patch.object(zeek_mod.subprocess, "run", side_effect=fake_run),
        ):
            try:
                zeek_mod.run_zeek("dummy.pcap", str(tmp_path))
            except subprocess.CalledProcessError:
                pass
        assert len(captured) == 2
        assert all(k.get("timeout") == 600 for k in captured)

    def test_run_zeek_timeout_expired_raises(self, tmp_path):
        import pytest

        from app.pipeline import zeek as zeek_mod

        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

        with (
            patch.object(zeek_mod, "find_bin", return_value="/usr/bin/zeek"),
            patch.object(zeek_mod.subprocess, "run", side_effect=fake_run),
        ):
            with pytest.raises(subprocess.TimeoutExpired):
                zeek_mod.run_zeek("dummy.pcap", str(tmp_path))
        # runner.py converts any exception from run_zeek into WARNING_ZEEK_FAILED, so
        # raising TimeoutExpired is the correct contract.

    def test_count_packets_passes_timeout(self):
        from app.pipeline import pcap_count as pc

        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(kwargs)
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

        with (
            patch.object(pc, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(pc.subprocess, "run", side_effect=fake_run),
        ):
            assert pc.count_packets_fast("dummy.pcap") is None
        assert captured and all(k.get("timeout") == 120 for k in captured)
