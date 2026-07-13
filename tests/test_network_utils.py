"""Tests for the network utilities module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.utils.network_utils import (
    _validate_domain,
    bulk_resolve_ips,
    is_enrichable_domain,
    is_public_ipv4,
    is_safe_webhook_url,
    pick_top_public_ips,
    resolve_ip,
)


class TestIsPublicIPv4:
    def test_public_ip(self):
        assert is_public_ipv4("8.8.8.8") is True

    def test_private_10(self):
        assert is_public_ipv4("10.0.0.1") is False

    def test_private_192(self):
        assert is_public_ipv4("192.168.1.1") is False

    def test_loopback(self):
        assert is_public_ipv4("127.0.0.1") is False

    def test_invalid_string(self):
        assert is_public_ipv4("not-an-ip") is False

    def test_empty(self):
        assert is_public_ipv4("") is False

    def test_none(self):
        assert is_public_ipv4(None) is False

    def test_ipv6(self):
        assert is_public_ipv4("::1") is False

    def test_lru_cached(self):
        """is_public_ipv4 is lru_cache-decorated and stays correct on repeat calls."""
        is_public_ipv4.cache_clear()
        assert is_public_ipv4("8.8.8.8") is True
        assert is_public_ipv4("10.0.0.1") is False
        info = is_public_ipv4.cache_info()
        assert info.currsize >= 2
        # Repeat calls hit the cache and return the same results
        assert is_public_ipv4("8.8.8.8") is True
        assert is_public_ipv4("10.0.0.1") is False
        assert is_public_ipv4.cache_info().hits > info.hits


class TestValidateDomain:
    def test_valid_domain(self):
        assert _validate_domain("example.com") is True

    def test_valid_subdomain(self):
        assert _validate_domain("sub.example.com") is True

    def test_empty(self):
        assert _validate_domain("") is False

    def test_no_dot(self):
        assert _validate_domain("localhost") is False

    def test_too_long(self):
        assert _validate_domain("a" * 254) is False

    def test_special_chars(self):
        assert _validate_domain("evil;rm -rf /") is False

    def test_hyphen_ok(self):
        assert _validate_domain("my-host.example.com") is True


class TestIsEnrichableDomain:
    """is_enrichable_domain must keep internal/private hostnames out of third-party
    OSINT submissions (VirusTotal, OTX) while still allowing public domains through."""

    @pytest.mark.parametrize("d", ["evil.com", "sub.example.org", "cdn.cloudflare.net"])
    def test_accepts_public_domains(self, d):
        assert is_enrichable_domain(d) is True

    @pytest.mark.parametrize(
        "d",
        [
            "dc01.internal.corp",  # private TLD
            "printer.local",  # private TLD
            "host.lan",  # private TLD
            "server.home",  # private TLD
            "box.intranet",  # private TLD
            "vm.test",  # private TLD
            "site.invalid",  # private TLD
            "1.2.3.4",  # IP-shaped, not a domain
            "10.0.0.1.in-addr.arpa",  # reverse-lookup junk
            "1.0.0.0.ip6.arpa",  # reverse-lookup junk (IPv6)
            "localhost",  # no dot, private TLD
            "workstation",  # single-label name, no dot
            "_dmarc",  # underscore + no dot
        ],
    )
    def test_rejects_internal_and_malformed(self, d):
        assert is_enrichable_domain(d) is False

    def test_rejects_underscore_domain(self):
        # Underscored labels (e.g. DKIM/DMARC records) are not enrichable hostnames.
        assert is_enrichable_domain("under_score.example.com") is False

    def test_rejects_empty(self):
        assert is_enrichable_domain("") is False

    def test_rejects_none(self):
        assert is_enrichable_domain(None) is False


class TestResolveIP:
    @patch("app.utils.network_utils.socket.gethostbyaddr")
    def test_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
        result = resolve_ip("8.8.8.8")
        assert result == "dns.google"

    @patch("app.utils.network_utils.socket.gethostbyaddr")
    def test_failure_returns_none(self, mock_gethostbyaddr):
        import socket

        mock_gethostbyaddr.side_effect = socket.herror("not found")
        result = resolve_ip("192.0.2.1")
        assert result is None


class TestBulkResolveIPs:
    def test_empty_list(self):
        assert bulk_resolve_ips([]) == {}

    @patch("app.utils.network_utils.resolve_ip")
    def test_resolves_in_parallel(self, mock_resolve):
        mock_resolve.side_effect = lambda ip, **kw: f"host-{ip}" if ip == "1.1.1.1" else None
        result = bulk_resolve_ips(["1.1.1.1", "2.2.2.2"], use_cache=False)
        assert result == {"1.1.1.1": "host-1.1.1.1"}

    @patch("app.utils.network_utils.resolve_ip")
    def test_deduplicates_ips(self, mock_resolve):
        mock_resolve.return_value = "host.local"
        result = bulk_resolve_ips(["1.1.1.1", "1.1.1.1", "1.1.1.1"], use_cache=False)
        assert len(result) == 1
        # resolve_ip should only be called once (dedup)
        assert mock_resolve.call_count == 1

    @patch("app.utils.network_utils.resolve_ip")
    def test_exception_handling(self, mock_resolve):
        mock_resolve.side_effect = Exception("network error")
        result = bulk_resolve_ips(["1.1.1.1"], use_cache=False)
        assert result == {}


def test_pick_top_public_ips_ranks_by_packet_volume():
    features = {
        "flows": [
            {"src": "8.8.8.8", "dst": "10.0.0.1", "count": 100},
            {"src": "1.1.1.1", "dst": "10.0.0.1", "count": 5},
        ],
        "artifacts": {"ips": ["8.8.8.8", "1.1.1.1", "10.0.0.1"]},
    }
    assert pick_top_public_ips(features, 1) == ["8.8.8.8"]
    # n <= 0 -> all public ips from artifacts
    assert set(pick_top_public_ips(features, 0)) == {"8.8.8.8", "1.1.1.1"}


class TestIsSafeWebhookUrl:
    """SSRF guard for the API v2 completion-webhook feature (Task 4.4).

    hardened_session does NOT block private IPs, so this guard is the only
    SSRF protection — the "public URL" and "unresolvable host" cases mock
    socket.getaddrinfo so the suite never depends on real DNS/network access.
    """

    def test_rejects_non_http_scheme(self):
        assert is_safe_webhook_url("ftp://example.com/hook") is False

    def test_rejects_missing_host(self):
        assert is_safe_webhook_url("http:///hook") is False

    def test_rejects_empty_string(self):
        assert is_safe_webhook_url("") is False

    def test_rejects_private_10(self):
        assert is_safe_webhook_url("http://10.0.0.5/hook") is False

    def test_rejects_loopback(self):
        assert is_safe_webhook_url("http://127.0.0.1/hook") is False

    def test_rejects_link_local(self):
        assert is_safe_webhook_url("http://169.254.169.254/hook") is False

    def test_rejects_localhost_hostname(self):
        # "localhost" resolves via the hosts file/nsswitch without hitting
        # the network, so this is safe to assert without mocking.
        assert is_safe_webhook_url("http://localhost/hook") is False

    def test_rejects_unresolvable_host(self, monkeypatch):
        import socket as socket_mod

        def boom(host, port, *args, **kwargs):
            raise socket_mod.gaierror("nodename nor servname provided")

        monkeypatch.setattr("app.utils.network_utils.socket.getaddrinfo", boom)
        assert is_safe_webhook_url("https://does-not-exist.invalid/hook") is False

    def test_accepts_public_https_url(self, monkeypatch):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(2, 1, 6, "", ("93.184.216.34", 0))]

        monkeypatch.setattr("app.utils.network_utils.socket.getaddrinfo", fake_getaddrinfo)
        assert is_safe_webhook_url("https://example.com/hook") is True

    def test_rejects_when_any_resolved_ip_is_private(self, monkeypatch):
        """DNS-rebinding-style bypass: if ANY resolved address is private, refuse."""

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (2, 1, 6, "", ("93.184.216.34", 0)),
                (2, 1, 6, "", ("10.0.0.9", 0)),
            ]

        monkeypatch.setattr("app.utils.network_utils.socket.getaddrinfo", fake_getaddrinfo)
        assert is_safe_webhook_url("https://rebinding.example/hook") is False

    def test_rejects_ipv4_multicast(self, monkeypatch):
        """ipaddress.is_global is (surprisingly) True for IPv4 multicast — must be rejected explicitly."""

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(2, 1, 6, "", ("239.255.255.250", 0))]

        monkeypatch.setattr("app.utils.network_utils.socket.getaddrinfo", fake_getaddrinfo)
        assert is_safe_webhook_url("http://multicast.example/hook") is False

    def test_rejects_ipv6_link_local_multicast(self, monkeypatch):
        """ipaddress.is_global is also True for some IPv6 multicast ranges (e.g. ff02::1)."""

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(10, 1, 6, "", ("ff02::1", 0, 0, 0))]

        monkeypatch.setattr("app.utils.network_utils.socket.getaddrinfo", fake_getaddrinfo)
        assert is_safe_webhook_url("http://[ff02::1]/hook") is False

    def test_rejects_ipv6_unspecified(self, monkeypatch):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(10, 1, 6, "", ("::", 0, 0, 0))]

        monkeypatch.setattr("app.utils.network_utils.socket.getaddrinfo", fake_getaddrinfo)
        assert is_safe_webhook_url("http://[::]/hook") is False

    def test_accepts_public_ipv6_url(self, monkeypatch):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0))]

        monkeypatch.setattr("app.utils.network_utils.socket.getaddrinfo", fake_getaddrinfo)
        assert is_safe_webhook_url("https://public-v6.example/hook") is True

    @pytest.mark.parametrize(
        "url",
        [
            "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6 loopback
            "http://2130706433/",  # decimal-encoded 127.0.0.1
            "http://0x7f000001/",  # hex-encoded 127.0.0.1
            "http://100.64.0.1/",  # CGNAT shared address space (100.64.0.0/10)
            "http://240.0.0.1/",  # reserved (240.0.0.0/4)
        ],
    )
    def test_rejects_known_ssrf_bypass_vectors(self, url):
        """Lock the guard against classic SSRF encoding/range bypasses across
        Python versions -- these use the real resolver (getaddrinfo handles the
        IP literals / integer forms without network access)."""
        assert is_safe_webhook_url(url) is False
