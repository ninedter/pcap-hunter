"""Tests for DNS analysis module."""

import pandas as pd
import pytest

from app.pipeline.dns_analysis import (
    DNSRecord,
    calculate_entropy,
    calculate_consonant_ratio,
    calculate_digit_ratio,
    detect_dga,
    detect_fast_flux,
    detect_tunneling,
    extract_domain_parts,
    is_whitelisted_domain,
    parse_dns_log,
    analyze_dns,
)


class TestEntropyCalculation:
    """Test entropy calculation."""

    def test_empty_string(self):
        assert calculate_entropy("") == 0.0

    def test_single_char(self):
        # Single repeated char has 0 entropy
        assert calculate_entropy("aaaa") == 0.0

    def test_uniform_distribution(self):
        # "ab" has 1 bit entropy (2 equally likely chars)
        entropy = calculate_entropy("ab")
        assert pytest.approx(entropy, rel=0.01) == 1.0

    def test_high_entropy(self):
        # Random-looking string should have higher entropy
        random_str = "x7k2m9p4q1"
        normal_str = "example"
        assert calculate_entropy(random_str) > calculate_entropy(normal_str)


class TestConsonantRatio:
    """Test consonant ratio calculation."""

    def test_all_consonants(self):
        assert calculate_consonant_ratio("bcdfg") == 1.0

    def test_all_vowels(self):
        assert calculate_consonant_ratio("aeiou") == 0.0

    def test_mixed(self):
        # "hello" = h, l, l (3 consonants) / 5 letters = 0.6
        assert pytest.approx(calculate_consonant_ratio("hello"), rel=0.01) == 0.6

    def test_with_numbers(self):
        # Numbers are ignored
        assert calculate_consonant_ratio("abc123") == pytest.approx(2/3, rel=0.01)

    def test_empty_string(self):
        assert calculate_consonant_ratio("") == 0.0


class TestDigitRatio:
    """Test digit ratio calculation."""

    def test_all_digits(self):
        assert calculate_digit_ratio("12345") == 1.0

    def test_no_digits(self):
        assert calculate_digit_ratio("hello") == 0.0

    def test_mixed(self):
        # "abc123" = 3 digits / 6 chars = 0.5
        assert calculate_digit_ratio("abc123") == 0.5

    def test_empty_string(self):
        assert calculate_digit_ratio("") == 0.0


class TestDomainParts:
    """Test domain part extraction."""

    def test_simple_domain(self):
        subdomain, name, tld = extract_domain_parts("example.com")
        assert subdomain == ""
        assert name == "example"
        assert tld == "com"

    def test_with_subdomain(self):
        subdomain, name, tld = extract_domain_parts("www.example.com")
        assert subdomain == "www"
        assert name == "example"
        assert tld == "com"

    def test_multi_part_tld(self):
        subdomain, name, tld = extract_domain_parts("example.co.uk")
        assert subdomain == ""
        assert name == "example"
        assert tld == "co.uk"

    def test_deep_subdomain(self):
        subdomain, name, tld = extract_domain_parts("a.b.c.example.com")
        assert subdomain == "a.b.c"
        assert name == "example"
        assert tld == "com"


class TestWhitelistCheck:
    """Test whitelist domain checking."""

    def test_cdn_domain(self):
        assert is_whitelisted_domain("d1234.cloudfront.net") is True
        assert is_whitelisted_domain("s3.amazonaws.com") is True

    def test_dmarc_record(self):
        assert is_whitelisted_domain("_dmarc.example.com") is True

    def test_normal_domain(self):
        assert is_whitelisted_domain("evil.com") is False


class TestDGADetection:
    """Test DGA detection."""

    def test_normal_domain(self):
        result = detect_dga("google.com")
        assert result.is_dga is False
        assert result.score < 0.5

    def test_dga_like_domain(self):
        # Random-looking domain with high entropy
        result = detect_dga("xk7m2p9q4.com")
        assert result.score > 0.3  # Should have elevated score

    def test_whitelisted_domain(self):
        result = detect_dga("d1234abcd.cloudfront.net")
        assert result.score < 0.5  # Whitelist reduces score

    def test_long_domain(self):
        result = detect_dga("verylongdomainnamethatsuspicious.com")
        assert "long name" in result.reason or result.score > 0.1


class TestTunnelingDetection:
    """Test DNS tunneling detection."""

    def test_no_records(self):
        result = detect_tunneling([], "example.com")
        assert result.is_tunneling is False
        assert result.query_volume == 0

    def test_normal_queries(self):
        records = [
            DNSRecord(ts=1.0, src="192.168.1.1", dst="8.8.8.8", query="www.example.com", qtype="A"),
            DNSRecord(ts=2.0, src="192.168.1.1", dst="8.8.8.8", query="mail.example.com", qtype="A"),
        ]
        result = detect_tunneling(records, "example.com")
        assert result.is_tunneling is False

    def test_suspicious_many_subdomains(self):
        # Create many unique subdomains (like data exfiltration)
        records = [
            DNSRecord(ts=float(i), src="192.168.1.1", dst="8.8.8.8",
                     query=f"unique{i}long{i}data.tunnel.com", qtype="TXT")
            for i in range(100)
        ]
        result = detect_tunneling(records, "tunnel.com")
        assert result.unique_subdomains >= 50
        assert result.score > 0.3


class TestFastFluxDetection:
    """Test fast flux detection."""

    def test_no_records(self):
        result = detect_fast_flux([], "example.com")
        assert result.is_fast_flux is False

    def test_single_ip(self):
        records = [
            DNSRecord(ts=1.0, src="192.168.1.1", dst="8.8.8.8",
                     query="example.com", qtype="A", answers=["1.2.3.4"], ttls=[300]),
        ]
        result = detect_fast_flux(records, "example.com")
        assert result.is_fast_flux is False
        assert result.unique_ips == 1

    def test_many_ips_low_ttl(self):
        # Multiple IPs with low TTL = suspicious
        records = [
            DNSRecord(ts=float(i), src="192.168.1.1", dst="8.8.8.8",
                     query="fastflux.com", qtype="A",
                     answers=[f"1.2.3.{i}"], ttls=[30])
            for i in range(20)
        ]
        result = detect_fast_flux(records, "fastflux.com")
        assert result.unique_ips > 5
        assert result.min_ttl < 60


class TestParseDNSLog:
    """Test parsing Zeek dns.log DataFrame."""

    def test_empty_dataframe(self):
        df = pd.DataFrame()
        records = parse_dns_log(df)
        assert records == []

    def test_basic_parsing(self):
        df = pd.DataFrame([
            {
                "ts": 1234567890.0,
                "id.orig_h": "192.168.1.1",
                "id.resp_h": "8.8.8.8",
                "query": "example.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
                "answers": "1.2.3.4",
                "TTLs": "300",
            }
        ])
        records = parse_dns_log(df)
        assert len(records) == 1
        assert records[0].query == "example.com"
        assert records[0].qtype == "A"

    def test_skip_empty_query(self):
        df = pd.DataFrame([
            {
                "ts": 1234567890.0,
                "id.orig_h": "192.168.1.1",
                "id.resp_h": "8.8.8.8",
                "query": "-",
                "qtype_name": "A",
            }
        ])
        records = parse_dns_log(df)
        assert records == []


class TestAnalyzeDNS:
    """Test comprehensive DNS analysis."""

    def test_empty_zeek_tables(self):
        result = analyze_dns({})
        assert result.get("error") == "No DNS log data"

    def test_empty_dns_log(self):
        result = analyze_dns({"dns.log": pd.DataFrame()})
        assert result.get("error") == "No DNS log data"

    def test_basic_analysis(self):
        df = pd.DataFrame([
            {
                "ts": 1234567890.0,
                "id.orig_h": "192.168.1.1",
                "id.resp_h": "8.8.8.8",
                "query": "example.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
            },
            {
                "ts": 1234567891.0,
                "id.orig_h": "192.168.1.1",
                "id.resp_h": "8.8.8.8",
                "query": "google.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
            },
        ])
        result = analyze_dns({"dns.log": df})

        assert result["total_records"] == 2
        assert result["unique_domains"] == 2
        assert "query_types" in result
        assert "dga_detections" in result
        assert "alerts" in result
