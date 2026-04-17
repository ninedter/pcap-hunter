"""Tests for the network utilities module."""

from __future__ import annotations

from unittest.mock import patch

from app.utils.network_utils import (
    _validate_domain,
    bulk_resolve_ips,
    is_public_ipv4,
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
