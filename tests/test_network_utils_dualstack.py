"""Dual-stack public-IP detection and bounded reverse DNS."""

from __future__ import annotations

import socket
import threading
import time
from unittest.mock import patch

import pytest

from app.utils import network_utils
from app.utils.network_utils import is_public_ip, is_public_ipv4, pick_top_public_ips, resolve_ip


class TestIsPublicIp:
    @pytest.mark.parametrize(
        "addr",
        ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111", "::ffff:8.8.8.8"],
    )
    def test_public_addresses(self, addr):
        assert is_public_ip(addr) is True

    @pytest.mark.parametrize(
        "addr",
        [
            "10.0.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",  # CGNAT
            "224.0.0.251",  # mDNS multicast
            "::1",
            "fe80::1",  # link-local
            "fd00::1",  # unique local
            "2001:db8::1",  # documentation
            "ff02::fb",  # multicast
            "::ffff:10.0.0.1",  # mapped private
            "not-an-ip",
            "",
            None,
        ],
    )
    def test_non_public_addresses(self, addr):
        assert is_public_ip(addr) is False

    def test_ipv4_only_helper_is_unchanged(self):
        assert is_public_ipv4("8.8.8.8") is True
        assert is_public_ipv4("2001:4860:4860::8888") is False


def _flow(src: str, dst: str, count: int) -> dict:
    """Flow dict in the shape parse_pcap_pyshark produces."""
    return {
        "src": src,
        "dst": dst,
        "sport": "50000",
        "dport": "443",
        "proto": "tls",
        "count": count,
        "bytes": count * 120,
        "first_ts": 1700000000.0,
        "last_ts": 1700000000.0 + count,
        "pkt_times": [1700000000.0 + i for i in range(min(count, 5))],
        "pkt_lens": [120] * min(count, 5),
        "mac_src": "aa:bb:cc:dd:ee:01",
        "mac_dst": "aa:bb:cc:dd:ee:02",
    }


class TestPickTopPublicIps:
    FEATURES = {
        "flows": [
            _flow("fd00::5", "2001:4860:4860::8888", 900),
            _flow("10.0.0.5", "8.8.8.8", 300),
            _flow("10.0.0.5", "1.1.1.1", 100),
            _flow("fe80::1", "ff02::fb", 5000),
        ],
        "artifacts": {
            "ips": ["1.1.1.1", "10.0.0.5", "2001:4860:4860::8888", "8.8.8.8", "fd00::5", "fe80::1", "ff02::fb"],
            "domains": [],
            "urls": [],
            "hashes": [],
            "ja3": [],
            "macs": [],
        },
    }

    def test_ipv6_talker_is_ranked_not_dropped(self):
        assert pick_top_public_ips(self.FEATURES, 2) == ["2001:4860:4860::8888", "8.8.8.8"]

    def test_all_public_ips_when_n_is_zero(self):
        assert set(pick_top_public_ips(self.FEATURES, 0)) == {"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"}


class TestResolveIp:
    def test_does_not_touch_the_process_wide_socket_timeout(self):
        sentinel = 123.0
        before = socket.getdefaulttimeout()
        socket.setdefaulttimeout(sentinel)
        seen: list[float | None] = []

        def fake(ip):
            seen.append(socket.getdefaulttimeout())
            return ("dns.google", [], [ip])

        try:
            with patch.object(network_utils.socket, "gethostbyaddr", side_effect=fake):
                assert resolve_ip("8.8.8.8", timeout=0.5) == "dns.google"
            assert seen == [sentinel]
            assert socket.getdefaulttimeout() == sentinel
        finally:
            socket.setdefaulttimeout(before)

    def test_slow_lookup_is_bounded_by_timeout(self):
        release = threading.Event()

        def slow(ip):
            release.wait(5)
            return ("slow.example", [], [ip])

        try:
            with patch.object(network_utils.socket, "gethostbyaddr", side_effect=slow):
                start = time.monotonic()
                assert resolve_ip("203.0.113.7", timeout=0.2) is None
                elapsed = time.monotonic() - start
        finally:
            release.set()
        assert elapsed < 2.0, f"resolve_ip blocked for {elapsed:.2f}s despite a 0.2s timeout"

    def test_errors_and_root_ptr_return_none(self):
        with patch.object(network_utils.socket, "gethostbyaddr", side_effect=socket.gaierror("nope")):
            assert resolve_ip("203.0.113.8") is None
        with patch.object(network_utils.socket, "gethostbyaddr", return_value=(".", [], ["192.0.2.1"])):
            assert resolve_ip("192.0.2.1") is None

    def test_ipv6_lookup(self):
        with patch.object(network_utils.socket, "gethostbyaddr", return_value=("dns.google.", [], [])):
            assert resolve_ip("2001:4860:4860::8888") == "dns.google"
