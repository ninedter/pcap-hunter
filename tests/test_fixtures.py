"""Smoke tests for shared test fixtures.

These tests catch the "someone committed a zero-byte or corrupted fixture"
failure mode. They do not validate the *content* of the fixture — that's the
responsibility of the tests that consume it.
"""

from __future__ import annotations

import pathlib

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
DEMO_PCAP = pathlib.Path(__file__).parent.parent / "pcaps" / "demo.pcap"


def test_tiny_pcap_exists():
    pcap = FIXTURE_DIR / "tiny.pcap"
    assert pcap.exists(), f"missing fixture: {pcap}. Regenerate via: python {FIXTURE_DIR}/_make_tiny.py"
    assert pcap.stat().st_size > 100, "fixture is suspiciously small; regenerate"


def test_tiny_pcap_has_valid_magic():
    """First 4 bytes match a known pcap or pcapng magic."""
    pcap = FIXTURE_DIR / "tiny.pcap"
    head = pcap.read_bytes()[:4]
    valid_magics = {
        b"\xd4\xc3\xb2\xa1",  # pcap classic, little-endian
        b"\xa1\xb2\xc3\xd4",  # pcap classic, byte-swapped
        b"\x4d\x3c\xb2\xa1",  # pcap nanosecond
        b"\xa1\xb2\x3c\x4d",  # pcap nanosecond, byte-swapped
        b"\x0a\x0d\x0d\x0a",  # pcapng
    }
    assert head in valid_magics, f"unexpected magic bytes: {head!r}"


def test_demo_pcap_exists():
    assert DEMO_PCAP.exists(), f"missing fixture: {DEMO_PCAP}. Regenerate via: python pcaps/_make_demo.py"
    assert DEMO_PCAP.stat().st_size > 100, "demo pcap is suspiciously small; regenerate"


def test_demo_pcap_has_valid_magic():
    """First 4 bytes match a known pcap or pcapng magic."""
    head = DEMO_PCAP.read_bytes()[:4]
    valid_magics = {
        b"\xd4\xc3\xb2\xa1",  # pcap classic, little-endian
        b"\xa1\xb2\xc3\xd4",  # pcap classic, byte-swapped
        b"\x4d\x3c\xb2\xa1",  # pcap nanosecond
        b"\xa1\xb2\x3c\x4d",  # pcap nanosecond, byte-swapped
        b"\x0a\x0d\x0d\x0a",  # pcapng
    }
    assert head in valid_magics, f"unexpected magic bytes: {head!r}"
