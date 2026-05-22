"""Validation helpers for inbound API uploads."""

from __future__ import annotations

# pcap classic, pcap classic byte-swapped, pcap nanosecond, pcapng
PCAP_MAGICS: tuple[bytes, ...] = (
    b"\xd4\xc3\xb2\xa1",  # classic
    b"\xa1\xb2\xc3\xd4",  # classic byte-swapped
    b"\x4d\x3c\xb2\xa1",  # nanosecond
    b"\xa1\xb2\x3c\x4d",  # nanosecond byte-swapped
    b"\x0a\x0d\x0d\x0a",  # pcapng (block type for SHB)
)


def is_valid_pcap_magic(prefix: bytes) -> bool:
    """Return True if prefix begins with a known pcap or pcapng magic."""
    if len(prefix) < 4:
        return False
    head = prefix[:4]
    return any(head == m for m in PCAP_MAGICS)
