"""SSL/TLS Certificate extraction and analysis.

Extracts X.509 certificates from PCAP files and analyzes them for:
- Certificate validity
- Self-signed detection
- Expired/not-yet-valid certificates
- Suspicious certificate patterns
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from app import config as C
from app.pipeline.state import PhaseHandle
from app.utils.common import find_bin

# Optional: Use cryptography library for robust certificate parsing
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

logger = logging.getLogger(__name__)

# --- Constants ---
MAX_SANS_DISPLAY = 10
MAX_ZEEK_SSL_ENTRIES = 100
MAX_CERTIFICATES_DISPLAY = 100
WEAK_RSA_KEY_BITS = 2048
WEAK_EC_KEY_BITS = 256
HIGH_RISK_SCORE_THRESHOLD = 0.5
LONG_VALIDITY_DAYS = 3650  # 10 years
EXPIRY_WARNING_DAYS = 30
MAX_CERTIFICATE_ALERTS = 200
MAX_SERVER_IPS_PER_CERT = 20
WELL_KNOWN_PORT_MAX = 1023

# tshark fields, in output order. New fields are appended so the leading six keep
# the positions older saved command lines / fixtures used.
TSHARK_CERT_FIELDS = (
    "frame.number",
    "ip.src",
    "ip.dst",
    "tcp.dstport",
    "tls.handshake.certificate",
    "tls.handshake.extensions_server_name",
    "x509sat.uTF8String",
    "x509sat.printableString",
    "x509ce.dNSName",
    "x509af.utcTime",
    "x509af.generalizedTime",
    "x509af.serialNumber",
    "x509af.algorithm.id",
    "frame.time_epoch",
    "tcp.srcport",
    "ipv6.src",
    "ipv6.dst",
)
_FIELD_INDEX = {name: idx for idx, name in enumerate(TSHARK_CERT_FIELDS)}


@dataclass
class Certificate:
    """Parsed X.509 certificate data."""

    # Core fields
    serial: str
    subject_cn: str
    subject_o: str
    issuer_cn: str
    issuer_o: str
    not_before: datetime | None
    not_after: datetime | None
    fingerprint_sha256: str
    fingerprint_sha1: str

    # Extended fields
    sans: list[str] = field(default_factory=list)
    key_type: str = ""
    key_bits: int = 0
    signature_algorithm: str = ""
    version: int = 3

    # Analysis results
    is_self_signed: bool = False
    is_expired: bool = False
    is_not_yet_valid: bool = False
    days_until_expiry: int | None = None
    risk_score: float = 0.0
    risk_reasons: list[str] = field(default_factory=list)

    # Connection info. ``dst_ip``/``dst_port`` are the TLS *server* endpoint and
    # ``src_ip`` the client, whichever direction the Certificate frame travelled.
    server_name: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0

    # Capture context
    observed_at: datetime | None = None  # frame time of the Certificate message
    validity_reference: str = ""  # "capture", "explicit" or "now" - what expiry was judged against
    cert_role: str = "server"  # "client" for a client certificate (mutual TLS)
    chain_length: int = 1


def parse_datetime(dt_str: str) -> datetime | None:
    """Parse various datetime formats from certificate fields."""
    if not dt_str or dt_str == "-":
        return None

    # Common formats from tshark
    formats = [
        "%b %d %H:%M:%S %Y GMT",
        "%Y-%m-%d %H:%M:%S",
        "%Y%m%d%H%M%SZ",
        "%b %d %H:%M:%S %Y",
    ]

    dt_str = dt_str.strip()
    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    logger.debug("Failed to parse datetime: %s", dt_str)
    return None


def _split_tshark_fields(line: str, separator: str = "|") -> list[str]:
    """Split one ``tshark -T fields -E quote=d`` output line into raw field values.

    tshark wraps every non-empty field in double quotes (empty fields stay bare),
    backslash-escapes embedded quotes, and a quoted field may legally contain the
    separator (an organisation name with ``|`` in it). Unquoted lines, as produced
    without ``-E quote``, split the same way.

    Args:
        line: One output line, without the trailing newline.
        separator: Field separator passed to ``-E separator=``.

    Returns:
        Field values with the surrounding quotes and escapes removed.
    """
    fields: list[str] = []
    buf: list[str] = []
    in_quotes = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_quotes:
            if ch == "\\" and i + 1 < n:
                nxt = line[i + 1]
                buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
                i += 2
                continue
            if ch == '"':
                if i + 1 < n and line[i + 1] == '"':  # doubled quote (older tshark)
                    buf.append('"')
                    i += 2
                    continue
                in_quotes = False
            else:
                buf.append(ch)
        elif ch == '"' and not buf:
            in_quotes = True
        elif ch == separator:
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    fields.append("".join(buf))
    return fields


def _first_occurrence(value: str) -> str:
    """First value of a field that ``-E occurrence=a`` joined with commas."""
    return value.split(",", 1)[0].strip() if value else ""


def _parse_port(value: str) -> int:
    """Parse a port field (first occurrence); 0 when absent or malformed."""
    first = _first_occurrence(value)
    return int(first) if first.isdigit() else 0


def _parse_epoch(value: str) -> datetime | None:
    """Parse ``frame.time_epoch`` (first occurrence) into an aware UTC datetime."""
    first = _first_occurrence(value)
    if not first:
        return None
    try:
        return datetime.fromtimestamp(float(first), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _parse_tshark_cert_line(line: str) -> dict[str, Any] | None:
    """Parse one tshark certificate line into endpoint and DER fields.

    The display filter matches the frame *carrying* the Certificate handshake
    message, which the server sends to the client: the frame's source address
    and source port are the TLS server, and ``tcp.dstport`` is the client's
    ephemeral port. A Certificate frame travelling towards a well-known port is
    a client certificate (mutual TLS), and its endpoints are kept the other way
    round so ``server_ip``/``server_port`` always describe the server.

    ``-E occurrence=a`` joins a certificate chain into one comma-separated field
    (leaf first); only the leaf is returned, with the chain length.

    Args:
        line: One raw output line (quoted or unquoted fields).

    Returns:
        Dict with ``cert_der`` (bytes), ``chain_length``, ``server_ip``,
        ``server_port``, ``client_ip``, ``cert_role``, ``server_name`` and
        ``observed_at``; None when the line carries no certificate.

    Raises:
        ValueError: If the certificate field is not valid hex.
    """
    parts = _split_tshark_fields(line)
    if len(parts) < 5:
        return None

    def get(name: str) -> str:
        idx = _FIELD_INDEX[name]
        return parts[idx] if idx < len(parts) else ""

    chain = [c for c in (h.strip() for h in get("tls.handshake.certificate").split(",")) if c]
    if not chain:
        return None
    cert_der = bytes.fromhex(chain[0].replace(":", "").replace(" ", ""))

    sender_ip = _first_occurrence(get("ip.src")) or _first_occurrence(get("ipv6.src"))
    receiver_ip = _first_occurrence(get("ip.dst")) or _first_occurrence(get("ipv6.dst"))
    sender_port = _parse_port(get("tcp.srcport"))
    receiver_port = _parse_port(get("tcp.dstport"))

    # Towards a well-known port from a non-well-known (or unreported) one: the
    # sender is the client presenting its own certificate.
    from_client = 0 < receiver_port <= WELL_KNOWN_PORT_MAX and not 0 < sender_port <= WELL_KNOWN_PORT_MAX
    if from_client:
        server_ip, server_port, client_ip, role = receiver_ip, receiver_port, sender_ip, "client"
    else:
        server_ip, server_port, client_ip, role = sender_ip, sender_port, receiver_ip, "server"

    return {
        "cert_der": cert_der,
        "chain_length": len(chain),
        "server_ip": server_ip,
        "server_port": server_port,
        "client_ip": client_ip,
        "cert_role": role,
        "server_name": _first_occurrence(get("tls.handshake.extensions_server_name")),
        "observed_at": _parse_epoch(get("frame.time_epoch")),
    }


def extract_certificates_tshark(
    pcap_path: str | Path,
    phase: PhaseHandle | None = None,
    reference_time: datetime | None = None,
) -> list[Certificate]:
    """
    Extract certificates from PCAP using tshark.

    Args:
        pcap_path: Path to PCAP file
        phase: PhaseHandle for progress updates
        reference_time: Moment to judge certificate validity against. Defaults to
            each certificate's own frame time, so an old capture is not reported
            as full of expired certificates.

    Returns:
        List of Certificate objects (leaf certificates, one per Certificate frame)
    """
    tshark = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark:
        logger.error("tshark not found")
        return []

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        logger.error("PCAP file not found: %s", pcap_path)
        return []

    if phase:
        phase.set(10, "Extracting TLS certificates...")

    field_args = []
    for f in TSHARK_CERT_FIELDS:
        field_args.extend(["-e", f])

    cmd = [
        tshark,
        "-r",
        str(pcap_path),
        "-Y",
        "tls.handshake.certificate",
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        *field_args,
    ]

    try:
        # Stream stdout line by line: each line can carry hex-encoded DER
        # certificates, so buffering the full output is the largest allocation
        # in the pipeline on TLS-heavy captures.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        logger.error("Failed to run tshark: %s", e)
        return []

    timed_out = threading.Event()

    def _kill() -> None:
        timed_out.set()
        proc.kill()

    watchdog = threading.Timer(C.TLS_EXTRACT_TIMEOUT_SECONDS, _kill)
    watchdog.start()

    # Drain stderr on a daemon thread so a chatty tshark can't fill the OS pipe
    # buffer and stall the stdout loop; the collected text feeds the rc!=0 warning.
    stderr_lines: list[str] = []

    def _drain_stderr() -> None:
        try:
            for err_line in proc.stderr:
                stderr_lines.append(err_line)
        except (OSError, ValueError):  # pragma: no cover - pipe closed during kill
            pass

    stderr_thread: threading.Thread | None = None
    if proc.stderr is not None:
        stderr_thread = threading.Thread(target=_drain_stderr, name="tls-stderr-drain", daemon=True)
        stderr_thread.start()

    certificates = []
    parse_failures = 0
    i = -1
    try:
        for raw_line in proc.stdout:
            i += 1
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            if phase and i % 10 == 0:
                # Total line count is unknown while streaming: capped monotone progression.
                phase.set(min(70, 10 + i // 10), f"Processing certificate {i + 1}...")

            try:
                parsed = _parse_tshark_cert_line(line)
                if parsed is None:
                    continue
                cert_bytes = parsed["cert_der"]

                # Calculate fingerprints
                sha256_fp = hashlib.sha256(cert_bytes).hexdigest()
                sha1_fp = hashlib.sha1(cert_bytes).hexdigest()

                # Extract certificate details using cryptography library (with openssl fallback)
                cert_info = _parse_cert_with_cryptography(cert_bytes)

                cert = Certificate(
                    serial=cert_info.get("serial", ""),
                    subject_cn=cert_info.get("subject_cn", ""),
                    subject_o=cert_info.get("subject_o", ""),
                    issuer_cn=cert_info.get("issuer_cn", ""),
                    issuer_o=cert_info.get("issuer_o", ""),
                    not_before=cert_info.get("not_before"),
                    not_after=cert_info.get("not_after"),
                    fingerprint_sha256=sha256_fp,
                    fingerprint_sha1=sha1_fp,
                    sans=cert_info.get("sans", []),
                    key_type=cert_info.get("key_type", ""),
                    key_bits=cert_info.get("key_bits", 0),
                    signature_algorithm=cert_info.get("sig_alg", ""),
                    server_name=parsed["server_name"],
                    src_ip=parsed["client_ip"],
                    dst_ip=parsed["server_ip"],
                    dst_port=parsed["server_port"],
                    observed_at=parsed["observed_at"],
                    cert_role=parsed["cert_role"],
                    chain_length=parsed["chain_length"],
                )

                # Analyze certificate
                _analyze_certificate(cert, reference_time=reference_time)
                certificates.append(cert)

            except Exception as e:
                # A line tshark emitted for a Certificate frame that we cannot
                # parse is lost evidence, not noise: count it and say so below.
                parse_failures += 1
                logger.debug("Failed to parse certificate line: %s", e)
                continue

        # Watchdog is still armed here, so a child that closed stdout but
        # refuses to exit is killed rather than hanging the pool thread.
        proc.wait()
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    # The process is dead here (waited or killed), so stderr has hit EOF and the
    # drain thread is finishing; the timeout is a guard against pathological pipes.
    if stderr_thread is not None:
        stderr_thread.join(timeout=5)

    if timed_out.is_set():
        logger.error("tshark timed out during certificate extraction")
        return []

    # A killed process exits non-zero and tshark sometimes writes warnings to
    # stderr with rc=0, so only treat a non-zero rc as failure when it produced
    # no parseable certificates at all.
    if proc.returncode != 0 and not certificates:
        logger.warning("tshark returned %s: %s", proc.returncode, "".join(stderr_lines).strip())
        return []

    if parse_failures:
        logger.warning(
            "Could not parse %d of %d tshark certificate line(s)", parse_failures, parse_failures + len(certificates)
        )

    if phase:
        phase.set(80, f"Found {len(certificates)} certificates")

    return certificates


def _parse_cert_with_cryptography(cert_der: bytes) -> dict[str, Any]:
    """
    Parse certificate details using the cryptography library.

    Args:
        cert_der: DER-encoded certificate bytes

    Returns:
        Dictionary with parsed certificate fields
    """
    result: dict[str, Any] = {}

    if not HAS_CRYPTOGRAPHY:
        return _parse_cert_with_openssl_fallback(cert_der)

    try:
        cert = x509.load_der_x509_certificate(cert_der)

        # Extract subject attributes
        subject_attrs = {attr.oid._name: attr.value for attr in cert.subject}
        result["subject_cn"] = subject_attrs.get("commonName", "")
        result["subject_o"] = subject_attrs.get("organizationName", "")

        # Extract issuer attributes
        issuer_attrs = {attr.oid._name: attr.value for attr in cert.issuer}
        result["issuer_cn"] = issuer_attrs.get("commonName", "")
        result["issuer_o"] = issuer_attrs.get("organizationName", "")

        # Serial number
        result["serial"] = format(cert.serial_number, "x")

        # Validity dates (already timezone-aware in cryptography >= 42.0)
        try:
            result["not_before"] = cert.not_valid_before_utc
            result["not_after"] = cert.not_valid_after_utc
        except AttributeError:
            # Fallback for older cryptography versions
            result["not_before"] = cert.not_valid_before.replace(tzinfo=timezone.utc)
            result["not_after"] = cert.not_valid_after.replace(tzinfo=timezone.utc)

        # Key info
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            result["key_type"] = "RSA"
            result["key_bits"] = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            result["key_type"] = "EC"
            result["key_bits"] = public_key.key_size

        # Signature algorithm
        result["sig_alg"] = cert.signature_algorithm_oid._name

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            result["sans"] = list(dns_names)
        except x509.ExtensionNotFound:
            result["sans"] = []

    except ValueError as e:
        logger.debug("Invalid certificate format: %s, falling back to openssl", e)
        return _parse_cert_with_openssl_fallback(cert_der)
    except TypeError as e:
        logger.debug("Certificate data type error: %s, falling back to openssl", e)
        return _parse_cert_with_openssl_fallback(cert_der)
    except Exception as e:
        logger.warning("Unexpected certificate parsing error: %s", e)
        return _parse_cert_with_openssl_fallback(cert_der)

    return result


def _parse_cert_with_openssl_fallback(cert_der: bytes) -> dict[str, Any]:
    """
    Fallback: Parse certificate details using openssl subprocess.

    Args:
        cert_der: DER-encoded certificate bytes

    Returns:
        Dictionary with parsed certificate fields
    """
    result: dict[str, Any] = {}

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
            input=cert_der,
            capture_output=True,
            timeout=10,
        )

        if proc.returncode != 0:
            return result

        text = proc.stdout.decode("utf-8", errors="ignore")

        # Parse Subject
        subject_match = re.search(r"Subject: (.+)", text)
        if subject_match:
            subject = subject_match.group(1)
            cn_match = re.search(r"CN\s*=\s*([^,/]+)", subject)
            o_match = re.search(r"O\s*=\s*([^,/]+)", subject)
            result["subject_cn"] = cn_match.group(1).strip() if cn_match else ""
            result["subject_o"] = o_match.group(1).strip() if o_match else ""

        # Parse Issuer
        issuer_match = re.search(r"Issuer: (.+)", text)
        if issuer_match:
            issuer = issuer_match.group(1)
            cn_match = re.search(r"CN\s*=\s*([^,/]+)", issuer)
            o_match = re.search(r"O\s*=\s*([^,/]+)", issuer)
            result["issuer_cn"] = cn_match.group(1).strip() if cn_match else ""
            result["issuer_o"] = o_match.group(1).strip() if o_match else ""

        # Parse Serial
        serial_match = re.search(r"Serial Number:\s*\n?\s*([0-9a-fA-F:]+)", text)
        if serial_match:
            result["serial"] = serial_match.group(1).replace(":", "").lower()

        # Parse Validity
        not_before_match = re.search(r"Not Before:\s*(.+)", text)
        not_after_match = re.search(r"Not After\s*:\s*(.+)", text)
        if not_before_match:
            result["not_before"] = parse_datetime(not_before_match.group(1))
        if not_after_match:
            result["not_after"] = parse_datetime(not_after_match.group(1))

        # Parse Key info
        key_match = re.search(r"Public Key Algorithm:\s*(\w+)", text)
        if key_match:
            result["key_type"] = key_match.group(1)

        bits_match = re.search(r"(?:Public-Key|RSA Public-Key):\s*\((\d+) bit\)", text)
        if bits_match:
            result["key_bits"] = int(bits_match.group(1))

        # Parse Signature Algorithm
        sig_match = re.search(r"Signature Algorithm:\s*(\S+)", text)
        if sig_match:
            result["sig_alg"] = sig_match.group(1)

        # Parse SANs
        san_match = re.search(r"Subject Alternative Name:\s*\n(.+?)(?:\n\s*\n|\Z)", text, re.DOTALL)
        if san_match:
            san_text = san_match.group(1)
            dns_names = re.findall(r"DNS:([^,\s]+)", san_text)
            result["sans"] = dns_names

    except Exception as e:
        logger.debug("OpenSSL parsing failed: %s", e)

    return result


def _analyze_certificate(cert: Certificate, reference_time: datetime | None = None) -> None:
    """
    Analyze certificate for security issues.

    Updates cert.risk_score and cert.risk_reasons in place.

    Args:
        cert: Certificate to analyze.
        reference_time: Moment validity is judged against. Defaults to the frame
            time the certificate was observed at (``cert.observed_at``); wall-clock
            time is used only when neither is available.
    """
    if reference_time is not None:
        now = reference_time if reference_time.tzinfo else reference_time.replace(tzinfo=timezone.utc)
        cert.validity_reference = "explicit"
    elif cert.observed_at is not None:
        now = cert.observed_at
        cert.validity_reference = "capture"
    else:
        now = datetime.now(timezone.utc)
        cert.validity_reference = "now"
    reasons = []
    score = 0.0

    # Check self-signed
    if cert.subject_cn and cert.issuer_cn:
        if cert.subject_cn.lower() == cert.issuer_cn.lower():
            cert.is_self_signed = True
            score += 0.3
            reasons.append("self-signed")
    elif cert.subject_o and cert.issuer_o:
        if cert.subject_o.lower() == cert.issuer_o.lower():
            cert.is_self_signed = True
            score += 0.3
            reasons.append("self-signed")

    # Check validity period
    if cert.not_after:
        if cert.not_after < now:
            cert.is_expired = True
            score += 0.4
            reasons.append("expired")
        else:
            cert.days_until_expiry = (cert.not_after - now).days
            if cert.days_until_expiry < EXPIRY_WARNING_DAYS:
                score += 0.1
                reasons.append(f"expires in {cert.days_until_expiry} days")

    if cert.not_before and cert.not_before > now:
        cert.is_not_yet_valid = True
        score += 0.4
        reasons.append("not yet valid")

    # Check validity duration (very long = suspicious)
    if cert.not_before and cert.not_after:
        duration = (cert.not_after - cert.not_before).days
        if duration > LONG_VALIDITY_DAYS:
            score += 0.2
            reasons.append(f"unusually long validity ({duration} days)")

    # Check weak key
    if cert.key_bits > 0:
        if cert.key_type.lower() == "rsa" and cert.key_bits < WEAK_RSA_KEY_BITS:
            score += 0.3
            reasons.append(f"weak {cert.key_type} key ({cert.key_bits} bits)")
        elif cert.key_type.lower() in ("ec", "ecdsa") and cert.key_bits < WEAK_EC_KEY_BITS:
            score += 0.3
            reasons.append(f"weak {cert.key_type} key ({cert.key_bits} bits)")

    # Check weak signature algorithm
    weak_sigs = ["md5", "sha1"]
    if cert.signature_algorithm and any(weak in cert.signature_algorithm.lower() for weak in weak_sigs):
        score += 0.2
        reasons.append(f"weak signature ({cert.signature_algorithm})")

    # Check suspicious CN patterns
    if cert.subject_cn:
        cn_lower = cert.subject_cn.lower()
        # IP address as CN
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cn_lower):
            score += 0.1
            reasons.append("IP address as CN")
        # Wildcard without domain
        if cn_lower == "*":
            score += 0.3
            reasons.append("wildcard-only CN")
        # Common malware patterns
        suspicious_patterns = ["localhost", "test", "example", "selfsigned", "dummy"]
        if any(p in cn_lower for p in suspicious_patterns):
            score += 0.2
            reasons.append("suspicious CN pattern")

    cert.risk_score = min(score, 1.0)
    cert.risk_reasons = reasons


def extract_from_zeek_ssl(zeek_tables: dict[str, pd.DataFrame]) -> list[dict[str, Any]]:
    """
    Extract certificate info from Zeek ssl.log.

    This provides less detail than full extraction but is faster.

    Args:
        zeek_tables: Dictionary of Zeek log DataFrames

    Returns:
        List of certificate summary dicts
    """
    ssl_df = zeek_tables.get("ssl.log")
    if ssl_df is None or ssl_df.empty:
        return []

    certs = []
    # to_dict("records") is much faster than iterrows(); the body only uses
    # row.get(...), which behaves identically on dicts (NaN values still
    # stringify to "nan" and non-numeric ports still raise into the except).
    for row in ssl_df.to_dict(orient="records"):
        try:
            cert = {
                "src": str(row.get("id.orig_h", row.get("id_orig_h", ""))),
                "dst": str(row.get("id.resp_h", row.get("id_resp_h", ""))),
                "port": int(row.get("id.resp_p", row.get("id_resp_p", 0))),
                "server_name": str(row.get("server_name", "")),
                "subject": str(row.get("subject", "")),
                "issuer": str(row.get("issuer", "")),
                "not_valid_before": str(row.get("not_valid_before", "")),
                "not_valid_after": str(row.get("not_valid_after", "")),
                "validation_status": str(row.get("validation_status", "")),
                "version": str(row.get("version", "")),
                "cipher": str(row.get("cipher", "")),
                "curve": str(row.get("curve", "")),
            }

            # Check for issues
            issues = []
            validation = cert["validation_status"]
            if validation and validation != "-":
                if "self signed" in validation.lower():
                    issues.append("self-signed")
                if "expired" in validation.lower():
                    issues.append("expired")
                if "unable to verify" in validation.lower():
                    issues.append("unverified")

            cert["issues"] = issues
            cert["has_issues"] = len(issues) > 0

            if cert["subject"] and cert["subject"] != "-":
                certs.append(cert)

        except Exception as e:
            logger.debug("Failed to parse SSL log row: %s", e)
            continue

    return certs


def _certificate_alerts_for(cert: dict[str, Any]) -> list[dict[str, Any]]:
    """Build per-server alert dicts for one serialised certificate.

    Args:
        cert: Certificate dict as emitted under ``certificates`` by
            ``analyze_certificates`` (must carry the ``server_ip`` key).

    Returns:
        One alert per (alert type, server IP).
    """
    if cert.get("cert_role") == "client":
        return []  # a client certificate says nothing about the server endpoint

    kinds: list[tuple[str, str]] = []
    if cert.get("is_self_signed"):
        kinds.append(("self_signed", "medium"))
    if cert.get("is_expired"):
        kinds.append(("expired", "low"))
    if cert.get("is_not_yet_valid"):
        kinds.append(("not_yet_valid", "medium"))
    if not kinds:
        return []

    label = cert.get("subject_cn") or cert.get("server_name") or str(cert.get("fingerprint_sha256", ""))[:16]
    server_ips = cert.get("server_ips") or [cert.get("server_ip") or cert.get("dst_ip") or ""]
    alerts = []
    for alert_type, severity in kinds:
        for ip in server_ips:
            alerts.append(
                {
                    "type": alert_type,
                    "severity": severity,
                    "cert": label or "unknown",
                    "dst_ip": ip,
                    "dst_port": cert.get("server_port", cert.get("dst_port", 0)),
                    "server_name": cert.get("server_name", ""),
                    "fingerprint_sha256": cert.get("fingerprint_sha256", ""),
                    "timestamp": cert.get("observed_at") or None,
                    "source": "tshark",
                }
            )
    return alerts


def certificate_alerts_from_analysis(tls_analysis: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return per-certificate alerts from any generation of TLS analysis dict.

    ``analyze_certificates`` keeps ``alerts`` as a dict of counters (the UI reads
    it that way) and publishes the per-certificate list under
    ``certificate_alerts``. Analyses persisted before that key existed, and batch
    aggregates that only carry ``certificates``, are handled here so correlation,
    the narrator and the ATT&CK mapper all read one shape:

    1. ``certificate_alerts`` when present.
    2. A list-shaped ``alerts`` (callers that always passed alert objects).
    3. Otherwise derived from ``certificates`` entries that carry ``server_ip``.
       Entries without it predate the server/client endpoint fix - their
       ``dst_ip`` is the *client* and their expiry was judged against the wall
       clock - so nothing is derived from them.

    Args:
        tls_analysis: TLS analysis dict, or None.

    Returns:
        List of alert dicts with at least ``type``, ``dst_ip`` and ``cert``.
    """
    if not isinstance(tls_analysis, dict):
        return []

    explicit = tls_analysis.get("certificate_alerts")
    if isinstance(explicit, list):
        return [a for a in explicit if isinstance(a, dict)]

    legacy = tls_analysis.get("alerts")
    if isinstance(legacy, list):
        return [a for a in legacy if isinstance(a, dict)]

    derived: list[dict[str, Any]] = []
    for cert in tls_analysis.get("certificates") or []:
        if isinstance(cert, dict) and "server_ip" in cert:
            derived.extend(_certificate_alerts_for(cert))
    return derived[:MAX_CERTIFICATE_ALERTS]


def _zeek_certificate_alerts(zeek_certs: list[dict[str, Any]], seen: set[tuple[str, str]]) -> list[dict[str, Any]]:
    """Alerts from Zeek ssl.log validation results not already covered by tshark.

    Args:
        zeek_certs: Entries from ``extract_from_zeek_ssl``.
        seen: ``(alert type, server ip)`` pairs already alerted; updated in place.

    Returns:
        Additional alert dicts (Zeek judges expiry against capture time).
    """
    alerts = []
    for entry in zeek_certs:
        dst = entry.get("dst", "")
        for issue, alert_type, severity in (("self-signed", "self_signed", "medium"), ("expired", "expired", "low")):
            if issue not in entry.get("issues", []) or not dst or (alert_type, dst) in seen:
                continue
            seen.add((alert_type, dst))
            server_name = entry.get("server_name", "")
            alerts.append(
                {
                    "type": alert_type,
                    "severity": severity,
                    "cert": server_name
                    if server_name and server_name not in ("-", "nan")
                    else entry.get("subject", ""),
                    "dst_ip": dst,
                    "dst_port": entry.get("port", 0),
                    "server_name": server_name,
                    "fingerprint_sha256": "",
                    "timestamp": None,
                    "source": "zeek",
                }
            )
    return alerts


def analyze_certificates(
    pcap_path: str | Path | None = None,
    zeek_tables: dict[str, pd.DataFrame] | None = None,
    phase: PhaseHandle | None = None,
    reference_time: datetime | None = None,
) -> dict[str, Any]:
    """
    Comprehensive certificate analysis.

    Args:
        pcap_path: Path to PCAP file (for full extraction)
        zeek_tables: Zeek log tables (for quick extraction)
        phase: PhaseHandle for progress updates
        reference_time: Moment to judge certificate validity against; defaults to
            each certificate's frame time in the capture.

    Returns:
        Dictionary with certificate analysis results. ``alerts`` holds aggregate
        counters; ``certificate_alerts`` holds one dict per (alert type, server)
        for consumers that need the endpoint (see
        ``certificate_alerts_from_analysis``). In ``certificates``, ``dst_ip`` /
        ``dst_port`` (duplicated as ``server_ip`` / ``server_port``) are the TLS
        server and ``client_ip`` the client.
    """
    if phase and phase.should_skip():
        phase.done("Certificate analysis skipped.")
        return {"skipped": True}

    if phase:
        phase.set(5, "Starting certificate analysis...")

    # Try full extraction from PCAP first
    certificates = []
    if pcap_path:
        certificates = extract_certificates_tshark(pcap_path, phase, reference_time=reference_time)

    # Fall back to Zeek ssl.log if no full extraction
    zeek_certs = []
    if zeek_tables:
        if phase:
            phase.set(85, "Extracting from Zeek ssl.log...")
        zeek_certs = extract_from_zeek_ssl(zeek_tables)

    # The Certificate frame never carries the SNI (that is in the ClientHello), so
    # borrow the server name Zeek recorded for the same server endpoint.
    zeek_names = {
        (z["dst"], z["port"]): z["server_name"]
        for z in zeek_certs
        if z.get("server_name") and z["server_name"] not in ("-", "nan")
    }

    # Deduplicate by fingerprint, remembering every server that presented it
    unique_certs = []
    seen_fingerprints = set()
    servers_by_fp: dict[str, list[str]] = {}
    for c in certificates:
        if not c.server_name:
            c.server_name = zeek_names.get((c.dst_ip, c.dst_port), "")
        servers = servers_by_fp.setdefault(c.fingerprint_sha256, [])
        if c.cert_role == "server" and c.dst_ip and c.dst_ip not in servers and len(servers) < MAX_SERVER_IPS_PER_CERT:
            servers.append(c.dst_ip)
        if c.fingerprint_sha256 not in seen_fingerprints:
            unique_certs.append(c)
            seen_fingerprints.add(c.fingerprint_sha256)

    # Build summary
    self_signed_count = sum(1 for c in unique_certs if c.is_self_signed)
    expired_count = sum(1 for c in unique_certs if c.is_expired)
    not_yet_valid_count = sum(1 for c in unique_certs if c.is_not_yet_valid)
    high_risk_count = sum(1 for c in unique_certs if c.risk_score >= HIGH_RISK_SCORE_THRESHOLD)

    cert_dicts = [
        {
            "subject_cn": c.subject_cn,
            "subject_o": c.subject_o,
            "issuer_cn": c.issuer_cn,
            "issuer_o": c.issuer_o,
            "serial": c.serial,
            "not_before": c.not_before.isoformat() if c.not_before else "",
            "not_after": c.not_after.isoformat() if c.not_after else "",
            "fingerprint_sha256": c.fingerprint_sha256,
            "fingerprint_sha1": c.fingerprint_sha1,
            "sans": c.sans[:MAX_SANS_DISPLAY],
            "key_type": c.key_type,
            "key_bits": c.key_bits,
            "signature_algorithm": c.signature_algorithm,
            "server_name": c.server_name,
            "dst_ip": c.dst_ip,
            "dst_port": c.dst_port,
            "is_self_signed": c.is_self_signed,
            "is_expired": c.is_expired,
            "is_not_yet_valid": c.is_not_yet_valid,
            "days_until_expiry": c.days_until_expiry,
            "risk_score": c.risk_score,
            "risk_reasons": c.risk_reasons,
            # Explicit endpoint roles (dst_ip/dst_port above are the server too)
            "server_ip": c.dst_ip,
            "server_port": c.dst_port,
            "client_ip": c.src_ip,
            "server_ips": list(servers_by_fp.get(c.fingerprint_sha256, [])),
            "cert_role": c.cert_role,
            "chain_length": c.chain_length,
            "observed_at": c.observed_at.isoformat() if c.observed_at else "",
            "validity_reference": c.validity_reference,
        }
        for c in unique_certs
    ]

    certificate_alerts: list[dict[str, Any]] = []
    for cert_dict in cert_dicts:
        certificate_alerts.extend(_certificate_alerts_for(cert_dict))
    alerted = {(a["type"], a["dst_ip"]) for a in certificate_alerts}
    certificate_alerts.extend(_zeek_certificate_alerts(zeek_certs, alerted))

    result = {
        "total_certificates": len(unique_certs),
        "unique_fingerprints": len(seen_fingerprints),
        "self_signed": self_signed_count,
        "expired": expired_count,
        "not_yet_valid": not_yet_valid_count,
        "high_risk": high_risk_count,
        "certificates": cert_dicts,
        "zeek_ssl_summary": {
            "total": len(zeek_certs),
            "with_issues": sum(1 for c in zeek_certs if c.get("has_issues")),
            "entries": zeek_certs[:MAX_ZEEK_SSL_ENTRIES],
        },
        "alerts": {
            "self_signed_count": self_signed_count,
            "expired_count": expired_count,
            "high_risk_count": high_risk_count,
        },
        "certificate_alerts": certificate_alerts[:MAX_CERTIFICATE_ALERTS],
    }

    if phase:
        alerts = result["alerts"]
        alert_msgs = []
        if alerts["self_signed_count"]:
            alert_msgs.append(f"{alerts['self_signed_count']} self-signed")
        if alerts["expired_count"]:
            alert_msgs.append(f"{alerts['expired_count']} expired")
        if alerts["high_risk_count"]:
            alert_msgs.append(f"{alerts['high_risk_count']} high-risk")

        summary = f"Found {len(unique_certs)} certificates"
        if zeek_certs:
            summary += f", {len(zeek_certs)} SSL connections"
        if alert_msgs:
            summary += f". Alerts: {', '.join(alert_msgs)}"
        phase.done(summary)

    return result
