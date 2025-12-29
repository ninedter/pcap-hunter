"""Tests for TLS certificate extraction and analysis."""

from datetime import datetime, timedelta, timezone

import pandas as pd

from app.pipeline.tls_certs import (
    Certificate,
    _analyze_certificate,
    analyze_certificates,
    extract_from_zeek_ssl,
    parse_datetime,
)


class TestParseDatetime:
    """Test datetime parsing."""

    def test_empty_string(self):
        assert parse_datetime("") is None
        assert parse_datetime("-") is None

    def test_utc_format(self):
        result = parse_datetime("Jan 15 12:30:45 2024 GMT")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_iso_format(self):
        result = parse_datetime("2024-01-15 12:30:45")
        assert result is not None
        assert result.year == 2024

    def test_compact_format(self):
        result = parse_datetime("20240115123045Z")
        assert result is not None
        assert result.year == 2024

    def test_invalid_format(self):
        result = parse_datetime("not a date")
        assert result is None


class TestCertificateAnalysis:
    """Test certificate security analysis."""

    def test_self_signed_detection(self):
        cert = Certificate(
            serial="1234",
            subject_cn="example.com",
            subject_o="Example Inc",
            issuer_cn="example.com",  # Same as subject = self-signed
            issuer_o="Example Inc",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
        )
        _analyze_certificate(cert)
        assert cert.is_self_signed is True
        assert "self-signed" in cert.risk_reasons

    def test_expired_detection(self):
        cert = Certificate(
            serial="1234",
            subject_cn="example.com",
            subject_o="Example Inc",
            issuer_cn="CA",
            issuer_o="CA Inc",
            not_before=datetime.now(timezone.utc) - timedelta(days=365),
            not_after=datetime.now(timezone.utc) - timedelta(days=30),  # Expired
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
        )
        _analyze_certificate(cert)
        assert cert.is_expired is True
        assert "expired" in cert.risk_reasons

    def test_not_yet_valid_detection(self):
        cert = Certificate(
            serial="1234",
            subject_cn="example.com",
            subject_o="Example Inc",
            issuer_cn="CA",
            issuer_o="CA Inc",
            not_before=datetime.now(timezone.utc) + timedelta(days=30),  # Future
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
        )
        _analyze_certificate(cert)
        assert cert.is_not_yet_valid is True
        assert "not yet valid" in cert.risk_reasons

    def test_expiry_soon_warning(self):
        cert = Certificate(
            serial="1234",
            subject_cn="example.com",
            subject_o="Example Inc",
            issuer_cn="CA",
            issuer_o="CA Inc",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=15),  # Expires soon
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
        )
        _analyze_certificate(cert)
        assert cert.days_until_expiry is not None
        assert cert.days_until_expiry < 30
        assert any("expires in" in r for r in cert.risk_reasons)

    def test_weak_key_detection(self):
        cert = Certificate(
            serial="1234",
            subject_cn="example.com",
            subject_o="Example Inc",
            issuer_cn="CA",
            issuer_o="CA Inc",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
            key_type="RSA",
            key_bits=1024,  # Weak key
        )
        _analyze_certificate(cert)
        assert "weak" in " ".join(cert.risk_reasons).lower()

    def test_weak_signature_detection(self):
        cert = Certificate(
            serial="1234",
            subject_cn="example.com",
            subject_o="Example Inc",
            issuer_cn="CA",
            issuer_o="CA Inc",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
            signature_algorithm="sha1WithRSAEncryption",  # Weak
        )
        _analyze_certificate(cert)
        assert any("weak signature" in r for r in cert.risk_reasons)

    def test_suspicious_cn_ip(self):
        cert = Certificate(
            serial="1234",
            subject_cn="192.168.1.1",  # IP as CN
            subject_o="",
            issuer_cn="CA",
            issuer_o="CA Inc",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
        )
        _analyze_certificate(cert)
        assert "IP address as CN" in cert.risk_reasons

    def test_valid_certificate(self):
        cert = Certificate(
            serial="1234",
            subject_cn="example.com",
            subject_o="Example Inc",
            issuer_cn="DigiCert",  # Different issuer
            issuer_o="DigiCert Inc",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            fingerprint_sha256="abc123",
            fingerprint_sha1="def456",
            key_type="RSA",
            key_bits=2048,
            signature_algorithm="sha256WithRSAEncryption",
        )
        _analyze_certificate(cert)
        assert cert.is_self_signed is False
        assert cert.is_expired is False
        assert cert.risk_score < 0.3


class TestExtractFromZeekSSL:
    """Test extraction from Zeek ssl.log."""

    def test_empty_tables(self):
        result = extract_from_zeek_ssl({})
        assert result == []

    def test_empty_ssl_log(self):
        result = extract_from_zeek_ssl({"ssl.log": pd.DataFrame()})
        assert result == []

    def test_basic_extraction(self):
        df = pd.DataFrame([
            {
                "id.orig_h": "192.168.1.1",
                "id.resp_h": "1.2.3.4",
                "id.resp_p": 443,
                "server_name": "example.com",
                "subject": "CN=example.com,O=Example Inc",
                "issuer": "CN=DigiCert,O=DigiCert Inc",
                "validation_status": "ok",
                "version": "TLSv12",
                "cipher": "TLS_AES_256_GCM_SHA384",
            }
        ])
        result = extract_from_zeek_ssl({"ssl.log": df})
        assert len(result) == 1
        assert result[0]["server_name"] == "example.com"
        assert result[0]["has_issues"] is False

    def test_self_signed_detection(self):
        df = pd.DataFrame([
            {
                "id.orig_h": "192.168.1.1",
                "id.resp_h": "1.2.3.4",
                "id.resp_p": 443,
                "server_name": "evil.com",
                "subject": "CN=evil.com",
                "issuer": "CN=evil.com",
                "validation_status": "self signed certificate",
                "version": "TLSv12",
                "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
            }
        ])
        result = extract_from_zeek_ssl({"ssl.log": df})
        assert len(result) == 1
        assert result[0]["has_issues"] is True
        assert "self-signed" in result[0]["issues"]


class TestAnalyzeCertificates:
    """Test comprehensive certificate analysis."""

    def test_skipped_analysis(self):
        class MockPhase:
            def should_skip(self):
                return True
            def done(self, msg):
                pass

        result = analyze_certificates(phase=MockPhase())
        assert result.get("skipped") is True

    def test_zeek_ssl_only(self):
        df = pd.DataFrame([
            {
                "id.orig_h": "192.168.1.1",
                "id.resp_h": "1.2.3.4",
                "id.resp_p": 443,
                "server_name": "example.com",
                "subject": "CN=example.com",
                "issuer": "CN=CA",
                "validation_status": "ok",
                "version": "TLSv12",
                "cipher": "TLS_AES_256_GCM_SHA384",
            }
        ])
        result = analyze_certificates(zeek_tables={"ssl.log": df})

        assert "zeek_ssl_summary" in result
        assert result["zeek_ssl_summary"]["total"] == 1

    def test_empty_analysis(self):
        result = analyze_certificates()
        assert result["total_certificates"] == 0
