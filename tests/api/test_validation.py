# tests/api/test_validation.py
"""Tests for PCAP magic-byte validation."""

from app.api.validation import is_valid_pcap_magic


def test_pcap_classic_magic():
    assert is_valid_pcap_magic(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20) is True


def test_pcap_swapped_magic():
    assert is_valid_pcap_magic(b"\xa1\xb2\xc3\xd4" + b"\x00" * 20) is True


def test_pcapng_magic():
    assert is_valid_pcap_magic(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20) is True


def test_nanosecond_magic():
    assert is_valid_pcap_magic(b"\x4d\x3c\xb2\xa1" + b"\x00" * 20) is True


def test_nanosecond_swapped_magic():
    assert is_valid_pcap_magic(b"\xa1\xb2\x3c\x4d" + b"\x00" * 20) is True


def test_rejects_arbitrary_bytes():
    assert is_valid_pcap_magic(b"PK\x03\x04" + b"\x00" * 20) is False
    assert is_valid_pcap_magic(b"") is False
    assert is_valid_pcap_magic(b"\x00") is False
