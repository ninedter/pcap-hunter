"""Streaming-subprocess tests for the carve and TLS-extraction stages.

Both stages run a full-file tshark pass over the PCAP. They must iterate
``proc.stdout`` line by line (``subprocess.Popen``) instead of buffering the
whole output in RAM, and a ``threading.Timer`` watchdog must bound their
wall-clock time (``C.CARVE_TIMEOUT_SECONDS`` / ``C.TLS_EXTRACT_TIMEOUT_SECONDS``).
"""

import hashlib
import io
import subprocess
import time
from unittest.mock import patch

import pytest

from app.pipeline import tls_certs as tls_mod
from app.pipeline.carve import CarveError, carve_http_payloads

# One valid tab-separated carve line: time, tcp.stream, content_type, content_length, body
CARVE_LINE = "1700000000.0\t3\ttext/html\t5\thello\n"


class FakePopen:
    """Minimal Popen stand-in whose stdout is iterable line by line.

    ``line_delay`` makes stdout a generator that sleeps before yielding each
    line, so a short watchdog timeout deterministically fires mid-stream.
    """

    def __init__(self, lines, line_delay=0.0, exit_code=0):
        self._exit_code = exit_code
        if line_delay:

            def _slow():
                for ln in lines:
                    time.sleep(line_delay)
                    yield ln

            self.stdout = _slow()
        else:
            self.stdout = iter(list(lines))
        self.stderr = io.StringIO("")
        self.returncode = None
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self._exit_code
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class FakePhase:
    """PhaseHandle stand-in that records progress and latches should_skip.

    ``skip_after=N`` returns False for the first N ``should_skip()`` calls and
    True afterwards (mirrors the real session-state flag, which stays set).
    """

    def __init__(self, skip_after=None):
        self._skip_after = skip_after
        self._skip_calls = 0
        self.sets = []
        self.done_msgs = []

    def should_skip(self):
        self._skip_calls += 1
        if self._skip_after is None:
            return False
        return self._skip_calls > self._skip_after

    def set(self, pct, msg=""):
        self.sets.append((pct, msg))

    def done(self, msg="Done"):
        self.done_msgs.append(msg)


def _make_der_cert(common_name="evil.example"):
    """Generate a real self-signed DER certificate (production-shape data)."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# carve_http_payloads
# ---------------------------------------------------------------------------


class TestCarveStreaming:
    def test_carve_uses_popen_streaming(self, tmp_path):
        fake = FakePopen([CARVE_LINE])
        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake) as popen_mock,
        ):
            results = carve_http_payloads("dummy.pcap", str(tmp_path))

        assert popen_mock.called
        cmd = popen_mock.call_args[0][0]
        assert cmd[0] == "/usr/bin/tshark"
        assert popen_mock.call_args.kwargs.get("stdout") == subprocess.PIPE
        assert popen_mock.call_args.kwargs.get("text") is True

        assert len(results) == 1
        expected_sha = hashlib.sha256(b"hello").hexdigest()
        r = results[0]
        assert r["time"] == "1700000000.0"
        assert r["tcp_stream"] == "3"
        assert r["content_type"] == "text/html"
        assert r["content_length"] == "5"
        assert r["sha256"] == expected_sha
        carved = tmp_path / f"stream3_{expected_sha[:10]}.bin"
        assert r["path"] == str(carved)
        assert carved.read_bytes() == b"hello"

    def test_carve_empty_output(self, tmp_path):
        fake = FakePopen([])
        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            results = carve_http_payloads("dummy.pcap", str(tmp_path))
        assert results == []

    def test_carve_malformed_lines_skipped(self, tmp_path):
        fake = FakePopen(["too\tfew\tfields\n", "\n", CARVE_LINE])
        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            results = carve_http_payloads("dummy.pcap", str(tmp_path))
        assert len(results) == 1
        assert results[0]["sha256"] == hashlib.sha256(b"hello").hexdigest()

    def test_carve_timeout_raises_carve_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr("app.config.CARVE_TIMEOUT_SECONDS", 0.05)
        fake = FakePopen([CARVE_LINE, CARVE_LINE], line_delay=0.2)
        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            with pytest.raises(CarveError, match="timed out"):
                carve_http_payloads("dummy.pcap", str(tmp_path))
        assert fake.killed

    def test_carve_exec_failure_raises_carve_error(self, tmp_path):
        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", side_effect=OSError("no such binary")),
        ):
            with pytest.raises(CarveError, match="tshark exec failed"):
                carve_http_payloads("dummy.pcap", str(tmp_path))

    def test_carve_early_exit_kills_process(self, tmp_path):
        # should_skip: False at the pre-flight check, True on the first loop iteration.
        phase = FakePhase(skip_after=1)
        fake = FakePopen([CARVE_LINE, CARVE_LINE])
        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            results = carve_http_payloads("dummy.pcap", str(tmp_path), phase=phase)
        assert results == []
        assert fake.killed
        assert phase.done_msgs == ["HTTP carving skipped."]

    def test_carve_progress_monotone_and_capped(self, tmp_path):
        lines = [f"1700000000.{i}\t{i}\ttext/html\t7\tbody{i:03d}\n" for i in range(60)]
        phase = FakePhase()
        fake = FakePopen(lines)
        with (
            patch("app.utils.common.find_bin", return_value="/usr/bin/tshark"),
            patch("subprocess.Popen", return_value=fake),
        ):
            results = carve_http_payloads("dummy.pcap", str(tmp_path), phase=phase)
        assert len(results) == 60
        pcts = [p for p, _ in phase.sets]
        assert pcts == sorted(pcts), "progress must be monotone"
        assert max(pcts) <= 90
        assert phase.done_msgs == ["Carved 60 bodies."]


# ---------------------------------------------------------------------------
# extract_certificates_tshark
# ---------------------------------------------------------------------------


class TestTlsExtractStreaming:
    def _pcap(self, tmp_path):
        pcap = tmp_path / "capture.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
        return pcap

    def test_tls_extract_streams(self, tmp_path):
        fake = FakePopen([])
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", return_value=fake) as popen_mock,
        ):
            certs = tls_mod.extract_certificates_tshark(self._pcap(tmp_path))
        assert certs == []
        assert popen_mock.called
        assert popen_mock.call_args.kwargs.get("stdout") == subprocess.PIPE
        assert popen_mock.call_args.kwargs.get("text") is True

    def test_tls_timeout_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("app.config.TLS_EXTRACT_TIMEOUT_SECONDS", 0.05)
        fake = FakePopen(["not|enough\n", "fields|here\n"], line_delay=0.2)
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", return_value=fake),
        ):
            certs = tls_mod.extract_certificates_tshark(self._pcap(tmp_path))
        assert certs == []
        assert fake.killed

    def test_tls_exec_failure_returns_empty(self, tmp_path):
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", side_effect=OSError("no such binary")),
        ):
            certs = tls_mod.extract_certificates_tshark(self._pcap(tmp_path))
        assert certs == []

    def test_tls_nonzero_rc_without_certs_returns_empty(self, tmp_path):
        fake = FakePopen([], exit_code=2)
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", return_value=fake),
        ):
            certs = tls_mod.extract_certificates_tshark(self._pcap(tmp_path))
        assert certs == []

    @pytest.mark.skipif(not tls_mod.HAS_CRYPTOGRAPHY, reason="cryptography not installed")
    def test_tls_parses_cert_line(self, tmp_path):
        der = _make_der_cert()
        line = f"1|10.0.0.1|93.184.216.34|443|{der.hex()}|evil.example\n"
        fake = FakePopen([line, "\n"])
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", return_value=fake),
        ):
            certs = tls_mod.extract_certificates_tshark(self._pcap(tmp_path))
        assert len(certs) == 1
        cert = certs[0]
        assert cert.fingerprint_sha256 == hashlib.sha256(der).hexdigest()
        assert cert.subject_cn == "evil.example"
        assert cert.is_self_signed
        assert cert.src_ip == "10.0.0.1"
        assert cert.dst_ip == "93.184.216.34"
        assert cert.dst_port == 443
        assert cert.server_name == "evil.example"

    @pytest.mark.skipif(not tls_mod.HAS_CRYPTOGRAPHY, reason="cryptography not installed")
    def test_tls_nonzero_rc_with_certs_keeps_certs(self, tmp_path):
        # tshark sometimes exits non-zero after emitting valid records (e.g. cut-short
        # capture). Parsed certificates must not be discarded.
        der = _make_der_cert()
        line = f"1|10.0.0.1|93.184.216.34|443|{der.hex()}|evil.example\n"
        fake = FakePopen([line], exit_code=2)
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", return_value=fake),
        ):
            certs = tls_mod.extract_certificates_tshark(self._pcap(tmp_path))
        assert len(certs) == 1

    def test_tls_progress_monotone_and_capped(self, tmp_path):
        phase = FakePhase()
        lines = [f"junk-line-{i}\n" for i in range(25)]
        fake = FakePopen(lines)
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", return_value=fake),
        ):
            certs = tls_mod.extract_certificates_tshark(self._pcap(tmp_path), phase=phase)
        assert certs == []
        pcts = [p for p, _ in phase.sets]
        assert pcts == sorted(pcts), "progress must be monotone"
        assert max(pcts) <= 80
