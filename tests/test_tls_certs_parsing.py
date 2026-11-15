"""TLS certificate stage: tshark line parsing, endpoint roles, capture-time validity.

The raw lines below reproduce the shape ``tshark -T fields -E separator=| -E quote=d
-E occurrence=a`` actually emits (verified against tshark 4.6): every non-empty
field is double-quoted, empty fields are bare, and a certificate chain arrives as
one comma-joined field with the leaf first. All values are synthetic.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pandas as pd
import pytest

from app.pipeline import tls_certs as tls_mod
from app.pipeline.tls_certs import (
    TSHARK_CERT_FIELDS,
    Certificate,
    _analyze_certificate,
    _parse_tshark_cert_line,
    _split_tshark_fields,
    analyze_certificates,
    certificate_alerts_from_analysis,
)

pytestmark = pytest.mark.skipif(not tls_mod.HAS_CRYPTOGRAPHY, reason="cryptography not installed")

CAPTURE_EPOCH = 1568538830.860627  # 2019-09-15, the "old capture"
CAPTURE_TIME = datetime.fromtimestamp(CAPTURE_EPOCH, tz=timezone.utc)
SERVER_IP = "203.0.113.10"
CLIENT_IP = "192.168.1.50"


class FakePopen:
    """Minimal Popen stand-in whose stdout is iterable line by line."""

    def __init__(self, lines):
        self.stdout = iter(list(lines))
        self.stderr = io.StringIO("")
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


def make_der_cert(
    common_name: str,
    issuer_name: str | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    organization: str | None = None,
) -> bytes:
    """Generate a real DER certificate (self-signed unless ``issuer_name`` differs)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    subject = x509.Name(attrs)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or CAPTURE_TIME - timedelta(days=90))
        .not_valid_after(not_after or CAPTURE_TIME + timedelta(days=275))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def tshark_line(
    chain: list[bytes],
    *,
    frame: int = 81,
    src: str = SERVER_IP,
    dst: str = CLIENT_IP,
    dstport: int = 49757,
    srcport: int = 443,
    epoch: float = CAPTURE_EPOCH,
    printable: str = "US,Example Trust Services,R3",
    ipv6: tuple[str, str] | None = None,
) -> str:
    """Render one line exactly as tshark does with ``quote=d`` and ``occurrence=a``."""
    values = {
        "frame.number": str(frame),
        "ip.src": "" if ipv6 else src,
        "ip.dst": "" if ipv6 else dst,
        "tcp.dstport": str(dstport),
        "tls.handshake.certificate": ",".join(der.hex() for der in chain),
        "tls.handshake.extensions_server_name": "",  # SNI is in the ClientHello, never in this frame
        "x509sat.uTF8String": "",
        "x509sat.printableString": printable,
        "x509ce.dNSName": "portal.example.net,www.portal.example.net",
        "x509af.utcTime": "2019-06-17 00:00:00 (UTC),2020-06-16 23:59:59 (UTC)",
        "x509af.generalizedTime": "",
        "x509af.serialNumber": "04a1b2c3d4e5f60718293a4b5c6d7e8f9a0b,0a0141420000015385736a0b85eca708",
        "x509af.algorithm.id": "1.2.840.10045.4.3.2,1.2.840.10045.2.1,1.2.840.10045.4.3.2",
        "frame.time_epoch": f"{epoch:.9f}",
        "tcp.srcport": str(srcport),
        "ipv6.src": ipv6[0] if ipv6 else "",
        "ipv6.dst": ipv6[1] if ipv6 else "",
    }
    rendered = []
    for name in TSHARK_CERT_FIELDS:
        value = values[name]
        rendered.append('"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"' if value else "")
    return "|".join(rendered) + "\n"


def run_extract(lines: list[str], tmp_path, **kwargs) -> list[Certificate]:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
    with (
        patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
        patch.object(tls_mod.subprocess, "Popen", return_value=FakePopen(lines)),
    ):
        return tls_mod.extract_certificates_tshark(pcap, **kwargs)


def run_analysis(lines: list[str], tmp_path, **kwargs) -> dict:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
    with (
        patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
        patch.object(tls_mod.subprocess, "Popen", return_value=FakePopen(lines)),
    ):
        return analyze_certificates(pcap_path=pcap, **kwargs)


class TestFieldSplitting:
    def test_quoted_and_empty_fields(self):
        assert _split_tshark_fields('"81"|"203.0.113.10"||"443"') == ["81", "203.0.113.10", "", "443"]

    def test_unquoted_legacy_shape(self):
        assert _split_tshark_fields("1|10.0.0.1|93.184.216.34|443|3082|evil.example") == [
            "1",
            "10.0.0.1",
            "93.184.216.34",
            "443",
            "3082",
            "evil.example",
        ]

    def test_separator_and_escaped_quote_inside_quoted_field(self):
        line = '"1"|"Acme | Widgets \\"Global\\" Ltd,R3"|"x"'
        assert _split_tshark_fields(line) == ["1", 'Acme | Widgets "Global" Ltd,R3', "x"]

    def test_command_requests_the_fields_the_parser_indexes(self, tmp_path):
        pcap = tmp_path / "capture.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
        with (
            patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
            patch.object(tls_mod.subprocess, "Popen", return_value=FakePopen([])) as popen_mock,
        ):
            tls_mod.extract_certificates_tshark(pcap)
        cmd = popen_mock.call_args[0][0]
        requested = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-e"]
        assert requested == list(TSHARK_CERT_FIELDS)
        assert {"frame.time_epoch", "tcp.srcport"} <= set(requested)


class TestRealisticLines:
    def test_quoted_chain_line_parses_leaf(self, tmp_path):
        leaf = make_der_cert("portal.example.net", issuer_name="Example Trust R3")
        intermediate = make_der_cert("Example Trust R3", issuer_name="Example Root X1")
        certs = run_extract([tshark_line([leaf, intermediate])], tmp_path)

        assert len(certs) == 1, "quoted, comma-joined chain must not be dropped"
        cert = certs[0]
        assert cert.fingerprint_sha256 == hashlib.sha256(leaf).hexdigest()
        assert cert.subject_cn == "portal.example.net"
        assert cert.chain_length == 2
        assert cert.is_self_signed is False

    def test_separator_inside_organisation_field_does_not_shift_columns(self, tmp_path):
        leaf = make_der_cert("portal.example.net", issuer_name="Example Trust R3")
        line = tshark_line([leaf], printable='US,Acme | Widgets "Global" Ltd,R3')
        cert = run_extract([line], tmp_path)[0]
        assert cert.dst_port == 443
        assert cert.observed_at == CAPTURE_TIME

    def test_server_endpoint_is_reported_as_dst(self, tmp_path):
        """The Certificate frame travels server -> client; dst_* must be the server."""
        leaf = make_der_cert("portal.example.net", issuer_name="Example Trust R3")
        cert = run_extract([tshark_line([leaf])], tmp_path)[0]
        assert cert.dst_ip == SERVER_IP
        assert cert.dst_port == 443  # not the client's ephemeral 49757
        assert cert.src_ip == CLIENT_IP
        assert cert.cert_role == "server"

    def test_server_on_non_standard_port(self, tmp_path):
        leaf = make_der_cert("c2.example.net")
        cert = run_extract([tshark_line([leaf], srcport=8443, dstport=51000)], tmp_path)[0]
        assert (cert.dst_ip, cert.dst_port, cert.src_ip) == (SERVER_IP, 8443, CLIENT_IP)

    def test_client_certificate_keeps_server_as_dst(self, tmp_path):
        """Mutual TLS: the client's Certificate frame travels towards the server port."""
        client_cert = make_der_cert("device-0042", issuer_name="Corp Device CA")
        line = tshark_line([client_cert], src=CLIENT_IP, dst=SERVER_IP, srcport=49757, dstport=443)
        cert = run_extract([line], tmp_path)[0]
        assert cert.cert_role == "client"
        assert (cert.dst_ip, cert.dst_port, cert.src_ip) == (SERVER_IP, 443, CLIENT_IP)

    def test_ipv6_endpoints(self, tmp_path):
        leaf = make_der_cert("portal.example.net", issuer_name="Example Trust R3")
        line = tshark_line([leaf], ipv6=("2001:db8::10", "fd00::50"))
        cert = run_extract([line], tmp_path)[0]
        assert (cert.dst_ip, cert.src_ip) == ("2001:db8::10", "fd00::50")

    def test_line_without_certificate_is_skipped(self):
        assert _parse_tshark_cert_line('"5"|"203.0.113.10"|"192.168.1.50"|"49757"||') is None
        assert _parse_tshark_cert_line("junk-line-1") is None

    def test_unparseable_lines_are_reported_not_silent(self, tmp_path, caplog):
        good = tshark_line([make_der_cert("portal.example.net", issuer_name="Example Trust R3")])
        bad = '"9"|"203.0.113.10"|"192.168.1.50"|"49757"|"not-hex-at-all"|\n'
        with caplog.at_level("WARNING", logger="app.pipeline.tls_certs"):
            certs = run_extract([good, bad], tmp_path)
        assert len(certs) == 1
        assert "Could not parse 1 of 2" in caplog.text


class TestValidityReference:
    def test_old_capture_certificate_is_not_expired(self, tmp_path):
        """Valid at capture time (2019), long expired by the wall clock."""
        leaf = make_der_cert("portal.example.net", issuer_name="Example Trust R3")
        cert = run_extract([tshark_line([leaf])], tmp_path)[0]
        assert cert.not_after < datetime.now(timezone.utc)
        assert cert.is_expired is False
        assert cert.validity_reference == "capture"
        assert cert.days_until_expiry == 274
        assert "expired" not in cert.risk_reasons

    def test_expired_at_capture_time_is_expired(self, tmp_path):
        leaf = make_der_cert(
            "old.example.net",
            issuer_name="Example Trust R3",
            not_before=CAPTURE_TIME - timedelta(days=400),
            not_after=CAPTURE_TIME - timedelta(days=35),
        )
        cert = run_extract([tshark_line([leaf])], tmp_path)[0]
        assert cert.is_expired is True

    def test_explicit_reference_time_overrides_frame_time(self, tmp_path):
        leaf = make_der_cert("portal.example.net", issuer_name="Example Trust R3")
        later = CAPTURE_TIME + timedelta(days=1000)
        cert = run_extract([tshark_line([leaf])], tmp_path, reference_time=later)[0]
        assert cert.is_expired is True
        assert cert.validity_reference == "explicit"

    def test_not_yet_valid_uses_capture_time(self, tmp_path):
        leaf = make_der_cert(
            "future.example.net",
            issuer_name="Example Trust R3",
            not_before=CAPTURE_TIME + timedelta(days=10),
            not_after=CAPTURE_TIME + timedelta(days=100),
        )
        cert = run_extract([tshark_line([leaf])], tmp_path)[0]
        assert cert.is_not_yet_valid is True

    def test_falls_back_to_now_without_any_reference(self):
        cert = Certificate(
            serial="1",
            subject_cn="a.example",
            subject_o="",
            issuer_cn="Example CA",
            issuer_o="",
            not_before=CAPTURE_TIME - timedelta(days=90),
            not_after=CAPTURE_TIME + timedelta(days=275),
            fingerprint_sha256="aa",
            fingerprint_sha1="bb",
        )
        _analyze_certificate(cert)
        assert cert.validity_reference == "now"
        assert cert.is_expired is True


class TestCertificateAlerts:
    def test_analysis_keeps_counter_alerts_and_adds_certificate_alerts(self, tmp_path):
        self_signed = make_der_cert("c2.example.net")
        expired = make_der_cert(
            "old.example.net",
            issuer_name="Example Trust R3",
            not_before=CAPTURE_TIME - timedelta(days=400),
            not_after=CAPTURE_TIME - timedelta(days=35),
        )
        healthy = make_der_cert("portal.example.net", issuer_name="Example Trust R3")
        lines = [
            tshark_line([self_signed], src="203.0.113.10"),
            tshark_line([self_signed], src="203.0.113.11", frame=90),  # same cert, second server
            tshark_line([expired], src="198.51.100.7", frame=120),
            tshark_line([healthy], src="198.51.100.8", frame=150),
        ]
        result = run_analysis(lines, tmp_path)

        # Existing consumers (UI) read ``alerts`` as a dict of counters - unchanged.
        # (Both flagged certs are also "high risk": "example" in the CN adds the
        # suspicious-CN-pattern score on top of self-signed / expired.)
        assert result["alerts"] == {"self_signed_count": 1, "expired_count": 1, "high_risk_count": 2}
        assert result["total_certificates"] == 3

        alerts = result["certificate_alerts"]
        assert {(a["type"], a["dst_ip"]) for a in alerts} == {
            ("self_signed", "203.0.113.10"),
            ("self_signed", "203.0.113.11"),
            ("expired", "198.51.100.7"),
        }
        first = next(a for a in alerts if a["dst_ip"] == "203.0.113.10")
        assert first["cert"] == "c2.example.net"
        assert first["dst_port"] == 443
        assert first["fingerprint_sha256"] == hashlib.sha256(self_signed).hexdigest()
        assert first["timestamp"] == CAPTURE_TIME.isoformat()
        assert certificate_alerts_from_analysis(result) == alerts

        cert_row = next(c for c in result["certificates"] if c["subject_cn"] == "c2.example.net")
        assert cert_row["dst_ip"] == cert_row["server_ip"] == "203.0.113.10"
        assert cert_row["server_ips"] == ["203.0.113.10", "203.0.113.11"]
        assert cert_row["client_ip"] == CLIENT_IP
        assert cert_row["validity_reference"] == "capture"

    def test_server_name_is_borrowed_from_zeek_ssl_log(self, tmp_path):
        leaf = make_der_cert("*.example.net", issuer_name="Example Trust R3")
        ssl_log = pd.DataFrame(
            [
                {
                    "id.orig_h": CLIENT_IP,
                    "id.resp_h": SERVER_IP,
                    "id.resp_p": 443,
                    "server_name": "portal.example.net",
                    "subject": "CN=*.example.net",
                    "issuer": "CN=Example Trust R3",
                    "validation_status": "ok",
                }
            ]
        )
        result = run_analysis([tshark_line([leaf])], tmp_path, zeek_tables={"ssl.log": ssl_log})
        assert result["certificates"][0]["server_name"] == "portal.example.net"

    def test_zeek_only_alerts(self):
        ssl_log = pd.DataFrame(
            [
                {
                    "id.orig_h": CLIENT_IP,
                    "id.resp_h": SERVER_IP,
                    "id.resp_p": 8443,
                    "server_name": "c2.example.net",
                    "subject": "CN=c2.example.net",
                    "issuer": "CN=c2.example.net",
                    "validation_status": "self signed certificate",
                }
            ]
        )
        result = analyze_certificates(zeek_tables={"ssl.log": ssl_log})
        assert result["certificate_alerts"] == [
            {
                "type": "self_signed",
                "severity": "medium",
                "cert": "c2.example.net",
                "dst_ip": SERVER_IP,
                "dst_port": 8443,
                "server_name": "c2.example.net",
                "fingerprint_sha256": "",
                "timestamp": None,
                "source": "zeek",
            }
        ]

    def test_helper_handles_every_saved_shape(self):
        assert certificate_alerts_from_analysis(None) == []
        assert certificate_alerts_from_analysis({}) == []
        assert certificate_alerts_from_analysis({"skipped": True}) == []

        # Analysis saved before ``certificate_alerts`` existed: counters only, and
        # certificates whose dst_ip was the client - nothing may be derived.
        legacy = {
            "alerts": {"self_signed_count": 1, "expired_count": 1, "high_risk_count": 0},
            "certificates": [
                {"subject_cn": "c2.example.net", "dst_ip": CLIENT_IP, "dst_port": 49757, "is_self_signed": True}
            ],
        }
        assert certificate_alerts_from_analysis(legacy) == []

        # Callers that always passed a list of alert objects
        listed = {"alerts": [{"type": "expired", "cert": "x", "dst_ip": "198.51.100.7"}, "junk"]}
        assert certificate_alerts_from_analysis(listed) == [{"type": "expired", "cert": "x", "dst_ip": "198.51.100.7"}]

        # Batch aggregate: new-shape certificates but no certificate_alerts key
        aggregate = {
            "alerts": {"self_signed_count": 1},
            "certificates": [
                {
                    "subject_cn": "c2.example.net",
                    "dst_ip": SERVER_IP,
                    "dst_port": 443,
                    "server_ip": SERVER_IP,
                    "server_port": 443,
                    "server_ips": [SERVER_IP],
                    "is_self_signed": True,
                    "fingerprint_sha256": "ab" * 32,
                }
            ],
        }
        derived = certificate_alerts_from_analysis(aggregate)
        assert [(a["type"], a["dst_ip"], a["cert"]) for a in derived] == [("self_signed", SERVER_IP, "c2.example.net")]
