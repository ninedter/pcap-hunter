"""Regression tests for the DNS detection heuristics.

Covers the registrable-domain helper shared by grouping and indexing, DGA
scoring of the right label with length-normalised entropy, tunneling under
multi-part public suffixes, fast-flux counting across responses, and the query
velocity observation window.
"""

from __future__ import annotations

import math

import pandas as pd
import pytest

from app.pipeline.dns_analysis import (
    DNSRecord,
    analyze_dns,
    analyze_query_velocity,
    calculate_entropy,
    detect_dga,
    detect_fast_flux,
    detect_tunneling,
    extract_domain_parts,
    normalized_entropy,
    registrable_domain,
    split_registrable_domain,
)

RANDOM_NAMES = [
    "xkqjzvbnmwpl.com",
    "www.xkqjzvbnmwpl.com",
    "qwrtzpsdfg.co.uk",
    "gfhtrwqzxpbvn.info",
    "lkjhgfdsazxcvbnm.net",
    "a3f9c1e7b2d84f60.biz",
    "zx9kq2vw7jp4mt.org",
]

BENIGN_NAMES = [
    "google.com",
    "www.google.com",
    "microsoft.com",
    "login.microsoftonline.com",
    "cloudflare.com",
    "wikipedia.org",
    "en.wikipedia.org",
    "my-awesome-company-website.com",
    "international-business-machines.com",
    "northwestern-mutual-insurance.com",
    "best-pizza-in-new-york-city.com",
    # CDN / SaaS hostnames with hex or numbered ids
    "d1a2b3c4e5f6a7.cloudfront.net",
    "a1b2c3d4e5f6.cdn.example.com",
    "8f3a9c2b1d7e.img.examplecdn.com",
    "e4578.dscb.akamaiedge.net",
    "r3---sn-ab5l6nzr.googlevideo.com",
    "ec2-52-1-2-3.compute-1.amazonaws.com",
    "scontent-lax3-1.xx.fbcdn.net",
]


def _dns_log(rows: list[dict]) -> pd.DataFrame:
    """Build a dns.log frame with the columns Zeek emits."""
    return pd.DataFrame(
        [
            {
                "ts": r["ts"],
                "id.orig_h": r.get("src", "192.168.1.50"),
                "id.resp_h": "192.168.1.1",
                "query": r["query"],
                "qtype_name": r.get("qtype", "A"),
                "rcode_name": "NOERROR",
                "answers": r.get("answers", "-"),
                "TTLs": r.get("ttls", "-"),
            }
            for r in rows
        ]
    )


class TestRegistrableDomain:
    """One helper decides the base domain for grouping AND indexing."""

    @pytest.mark.parametrize(
        ("fqdn", "expected"),
        [
            ("x.example.co.uk", "example.co.uk"),
            ("a.b.shop.com.au", "shop.com.au"),
            ("mail.corp.co.jp", "corp.co.jp"),
            ("www.loja.com.br", "loja.com.br"),
            ("api.site.com.tw", "site.com.tw"),
            ("www.example.com", "example.com"),
            ("EXAMPLE.COM.", "example.com"),
        ],
    )
    def test_multi_part_and_plain_suffixes(self, fqdn, expected):
        assert registrable_domain(fqdn) == expected

    @pytest.mark.parametrize(
        ("fqdn", "expected"),
        [
            # Short second-level names are registrable domains, not public suffixes
            ("www.abc.com", "abc.com"),
            ("links.t.co", "t.co"),
            ("go.bit.ly", "bit.ly"),
            ("api.x.com", "x.com"),
            ("a.b.c.fb.me", "fb.me"),
        ],
    )
    def test_short_names_are_not_treated_as_tlds(self, fqdn, expected):
        assert registrable_domain(fqdn) == expected

    def test_split_returns_subdomain_name_suffix(self):
        assert split_registrable_domain("a.b.example.co.uk") == ("a.b", "example", "co.uk")
        assert split_registrable_domain("www.abc.com") == ("www", "abc", "com")
        assert split_registrable_domain("localhost") == ("", "localhost", "")
        # A bare public suffix has no registrable label above it
        assert split_registrable_domain("co.uk") == ("", "co", "uk")

    def test_extract_domain_parts_is_the_same_helper(self):
        for name in ("x.example.co.uk", "links.t.co", "www.abc.com", "example.com"):
            assert extract_domain_parts(name) == split_registrable_domain(name)


class TestDGAScoring:
    def test_registrable_label_is_scored_not_www(self):
        result = detect_dga("www.xkqjzvbnmwpl.com")
        assert result.analyzed_label == "xkqjzvbnmwpl"
        assert result.length == len("xkqjzvbnmwpl")
        assert result.is_dga is True
        # Same verdict with or without the host label
        assert result.score == detect_dga("xkqjzvbnmwpl.com").score

    def test_normalized_entropy_is_reachable_for_short_labels(self):
        label = "xkqjzvbnmwpl"  # 12 distinct characters
        # Raw entropy is capped by log2(len) and can never exceed 4.0 here...
        assert calculate_entropy(label) == pytest.approx(math.log2(12))
        assert calculate_entropy(label) < 4.0
        # ...while the normalised value saturates
        assert normalized_entropy(label) == pytest.approx(1.0)
        assert normalized_entropy("aaaaaaaa") == 0.0
        assert normalized_entropy("") == 0.0
        assert "high entropy" in detect_dga(f"{label}.com").reason

    @pytest.mark.parametrize("domain", RANDOM_NAMES)
    def test_random_names_are_flagged(self, domain):
        result = detect_dga(domain)
        assert result.is_dga is True, f"{domain}: {result.score} ({result.reason})"

    @pytest.mark.parametrize("domain", BENIGN_NAMES)
    def test_benign_names_are_not_listed(self, domain):
        result = detect_dga(domain)
        # Below the *listing* threshold, not merely below the confirmation one
        assert result.score <= 0.3, f"{domain}: {result.score} ({result.reason})"
        assert result.is_dga is False

    def test_random_subdomain_scores_lower_than_random_registrable_label(self):
        sub = detect_dga("xkqjzvbnmwpl.duckdns.org")
        reg = detect_dga("xkqjzvbnmwpl.org")
        assert sub.analyzed_label == "xkqjzvbnmwpl"
        assert "subdomain label" in sub.reason
        assert 0.3 < sub.score < reg.score

    def test_multi_part_suffix_scores_registrable_label(self):
        result = detect_dga("www.qwrtzpsdfg.co.uk")
        assert result.analyzed_label == "qwrtzpsdfg"
        assert result.is_dga is True

    def test_analyze_dns_emits_new_dga_keys(self):
        rows = [{"ts": 1700000000.0 + i, "query": d} for i, d in enumerate(["www.xkqjzvbnmwpl.com", "google.com"])]
        result = analyze_dns({"dns.log": _dns_log(rows)})
        detections = {d["domain"]: d for d in result["dga_detections"]}
        assert "google.com" not in detections
        hit = detections["www.xkqjzvbnmwpl.com"]
        assert hit["is_dga"] is True
        assert hit["analyzed_label"] == "xkqjzvbnmwpl"
        assert hit["normalized_entropy"] == pytest.approx(1.0)
        assert hit["first_seen"] == 1700000000.0
        assert result["alerts"]["dga_count"] == 1
        assert result["first_record_ts"] == 1700000000.0


class TestTunnelingGrouping:
    @staticmethod
    def _tunnel_rows(base: str, count: int = 150) -> list[dict]:
        return [
            {
                "ts": 1700000000.0 + i,
                "query": f"{i:04d}aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVkIGRhdGE{i:04d}.{base}",
                "qtype": "TXT",
            }
            for i in range(count)
        ]

    @pytest.mark.parametrize("base", ["example.co.uk", "payload.com.au", "abc.com", "t.co", "x.com"])
    def test_tunneling_detected_under_multi_part_and_short_bases(self, base):
        result = analyze_dns({"dns.log": _dns_log(self._tunnel_rows(base))})
        detections = {d["domain"]: d for d in result["tunneling_detections"]}
        assert base in detections, f"grouping and index disagreed for {base}: {list(detections)}"
        hit = detections[base]
        assert hit["reason"] != "no data"
        assert hit["query_volume"] == 150
        assert hit["unique_subdomains"] == 150
        assert hit["is_tunneling"] is True
        assert hit["first_seen"] == 1700000000.0
        assert hit["last_seen"] == 1700000149.0
        assert result["alerts"]["tunneling_count"] == 1

    def test_suffix_match_respects_label_boundary(self):
        records = [
            DNSRecord(ts=1.0, src="10.0.0.5", dst="10.0.0.1", query="a.example.com", qtype="A"),
            DNSRecord(ts=2.0, src="10.0.0.5", dst="10.0.0.1", query="a.notexample.com", qtype="A"),
        ]
        result = detect_tunneling(records, "example.com")
        assert result.query_volume == 1
        assert result.unique_subdomains == 1


class TestFastFlux:
    @staticmethod
    def _answer(ts: float, ips: list[str], domain: str = "flux.example.net", ttl: int = 30) -> DNSRecord:
        return DNSRecord(
            ts=ts, src="10.0.0.5", dst="10.0.0.1", query=domain, qtype="A", answers=ips, ttls=[ttl] * len(ips)
        )

    def test_round_robin_reordering_is_not_a_change(self):
        pool = ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"]
        records = [self._answer(float(i * 10), pool[i % 4 :] + pool[: i % 4]) for i in range(12)]
        result = detect_fast_flux(records, "flux.example.net")
        assert result.unique_ips == 4
        assert result.ip_changes == 0
        assert result.is_fast_flux is False

    def test_single_large_answer_counts_no_changes(self):
        result = detect_fast_flux(
            [self._answer(1.0, [f"198.51.100.{i}" for i in range(1, 13)])],
            "flux.example.net",
        )
        assert result.unique_ips == 12
        assert result.ip_changes == 0

    def test_new_addresses_across_responses_are_changes(self):
        records = [self._answer(float(i * 5), [f"203.0.113.{i * 2 + 1}", f"203.0.113.{i * 2 + 2}"]) for i in range(10)]
        result = detect_fast_flux(records, "flux.example.net")
        assert result.unique_ips == 20
        assert result.ip_changes == 9
        assert result.is_fast_flux is True

    def test_cdn_whitelist_applies(self):
        def build(domain):
            return [
                self._answer(float(i * 5), [f"203.0.113.{i * 2 + 1}", f"203.0.113.{i * 2 + 2}"], domain)
                for i in range(10)
            ]

        cdn = detect_fast_flux(build("d111abcdef8.cloudfront.net"), "d111abcdef8.cloudfront.net")
        other = detect_fast_flux(build("flux.example.net"), "flux.example.net")
        assert other.is_fast_flux is True
        assert cdn.is_fast_flux is False
        assert cdn.score < other.score
        assert "whitelisted" in cdn.reason


class TestQueryVelocityWindow:
    def test_sub_second_burst_is_not_a_sustained_rate(self):
        # 10 queries in 0.09 s used to be reported as ~110 qps
        records = [
            DNSRecord(ts=1700000000.0 + i * 0.01, src="10.0.0.5", dst="10.0.0.1", query=f"h{i}.example.com", qtype="A")
            for i in range(10)
        ]
        assert analyze_query_velocity(records) == []

    def test_sustained_rate_is_flagged_and_reports_window(self):
        records = [
            DNSRecord(ts=1700000000.0 + i * 0.01, src="10.0.0.5", dst="10.0.0.1", query=f"h{i}.example.com", qtype="A")
            for i in range(2000)
        ]
        result = analyze_query_velocity(records)
        assert len(result) == 1
        assert result[0]["is_suspicious"] is True
        assert result[0]["qps"] == pytest.approx(100, rel=0.01)
        assert result[0]["window_sec"] == pytest.approx(result[0]["duration_sec"])

    def test_short_heavy_burst_is_rated_over_the_minimum_window(self):
        # 600 lookups in one second: rated as 120 qps over the 5 s window, not 600
        records = [
            DNSRecord(ts=1700000000.0 + i / 600, src="10.0.0.5", dst="10.0.0.1", query=f"h{i}.example.com", qtype="A")
            for i in range(600)
        ]
        result = analyze_query_velocity(records)
        assert result[0]["qps"] == pytest.approx(120, rel=0.01)
        assert result[0]["window_sec"] == 5.0
        assert result[0]["duration_sec"] == pytest.approx(1.0, abs=0.1)
