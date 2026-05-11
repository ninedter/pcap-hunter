"""Generate ``tests/fixtures/tiny.pcap`` deterministically.

Run once locally to regenerate the fixture if it's lost or needs to evolve:

    python tests/fixtures/_make_tiny.py

The committed ``tiny.pcap`` is small (a few hundred bytes), self-contained, and
contains synthetic Ethernet/IP/TCP traffic between two RFC 1918 IPs. It is the
exclusive fixture used by ``tests/test_pipeline_runner.py`` (Task 4b onward) to
exercise the headless pipeline runner end-to-end.

Tests must NOT import this module — they read the committed ``tiny.pcap`` file
directly. This module is a developer tool, not test code.
"""

from __future__ import annotations

import pathlib

import scapy.all as scapy

FIXTURE_PATH = pathlib.Path(__file__).parent / "tiny.pcap"
PACKET_COUNT = 20
# Pinned epoch for deterministic record timestamps: 2026-01-01T00:00:00 UTC.
BASE_EPOCH = 1767225600


def build_packets() -> list:
    """Return a deterministic list of 20 Ethernet/IP/TCP SYN packets.

    Both Ethernet MACs and packet timestamps are pinned so that regenerating
    the fixture produces byte-identical output, no matter where or when the
    script runs.
    """
    pkts = []
    for i in range(PACKET_COUNT):
        pkt = (
            scapy.Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
            / scapy.IP(src="10.0.0.1", dst="10.0.0.2")
            / scapy.TCP(sport=12345 + i, dport=80, flags="S")
        )
        pkt.time = BASE_EPOCH + i  # one packet per second, deterministic
        pkts.append(pkt)
    return pkts


def main() -> None:
    pkts = build_packets()
    scapy.wrpcap(str(FIXTURE_PATH), pkts)
    size = FIXTURE_PATH.stat().st_size
    print(f"wrote {FIXTURE_PATH} ({size} bytes, {len(pkts)} packets)")


if __name__ == "__main__":
    main()
