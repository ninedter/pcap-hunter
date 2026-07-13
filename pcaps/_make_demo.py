"""Generate ``pcaps/demo.pcap`` deterministically.

Run once locally to regenerate the fixture if it's lost or needs to evolve:

    python pcaps/_make_demo.py

The committed ``demo.pcap`` is small (a few KB, dozens of packets) and
entirely SYNTHETIC — license-clean by construction. It exists so a first-run
user has something to load via the "Load demo capture" button instead of
facing an empty app, and so that loading it actually exercises real
detection paths in the pipeline:

- DNS query/response pairs (UDP/53): two normal-looking domains plus one
  digit-heavy, all-consonant DGA-looking domain that
  ``app.pipeline.dns_analysis.detect_dga`` scores above its confirmation
  threshold (via the digit-ratio / consonant-ratio / no-vowel bonuses).
- A minimal TLS ClientHello (TCP/443) with an SNI extension, for protocol
  variety.
- Two HTTP GET requests (TCP/80): one with a normal browser User-Agent, one
  with a scripting-tool User-Agent (``python-requests``) that
  ``app.pipeline`` HTTP heuristics flag as suspicious.
- A periodic TCP beacon (13 packets, exactly 30s apart) to a well-known C2
  port (4444, see ``app.config.C2_SUSPECT_PORTS``) so
  ``app.pipeline.beacon.rank_beaconing`` has a clear candidate.

All destination IPs are from documentation/test ranges (RFC 5737
TEST-NET-3 ``203.0.113.0/24`` and TEST-NET-2 ``198.51.100.0/24``) — publicly
reserved for exactly this purpose, never routed on the real Internet — so
the capture is obviously synthetic and safe to publish. The source is an
RFC 1918 client. Ethernet MACs and every packet timestamp are pinned (like
``tests/fixtures/_make_tiny.py``) so regenerating the fixture produces
byte-identical output, no matter where or when the script runs.

The DGA domain resolves (in the synthetic DNS response) to the same IP the
beacon later targets, and the second "normal" domain resolves to the TLS
server IP — a small, deliberate narrative thread for anyone poking at the
demo data, not something the pipeline depends on.

Tests must NOT import this module — they read the committed ``demo.pcap``
file directly. This module is a developer tool, not test code.
"""

from __future__ import annotations

import pathlib
import struct

import scapy.all as scapy

FIXTURE_PATH = pathlib.Path(__file__).parent / "demo.pcap"

# Pinned epoch for deterministic record timestamps: 2026-01-01T00:00:00 UTC
# (same anchor as tests/fixtures/_make_tiny.py).
BASE_EPOCH = 1767225600

# --- Deterministic L2/L3 addressing ---
CLIENT_MAC = "00:00:00:00:00:01"
SERVER_MAC = "00:00:00:00:00:02"
CLIENT_IP = "10.0.0.50"  # RFC 1918

# Documentation/test-net destinations (RFC 5737) — never routed publicly.
DNS_SERVER_IP = "203.0.113.53"
NORMAL_HTTP_IP = "198.51.100.10"
TLS_SERVER_IP = "203.0.113.50"
SUSPICIOUS_HTTP_IP = "203.0.113.10"
BEACON_IP = "203.0.113.99"
BEACON_PORT = 4444  # in app.config.C2_SUSPECT_PORTS

# --- Domains ---
DOMAIN_NORMAL_1 = "www.example.com"
DOMAIN_NORMAL_2 = "vault.example.net"
# Digit-heavy, all-consonant-alpha synthetic name — not a real
# registered domain. Scores well above app.pipeline.dns_analysis's DGA
# confirmation threshold (0.5) via digit-ratio + consonant-ratio + no-vowels
# heuristics.
DOMAIN_DGA = "x7k2p9qz3v.com"


def _eth_ip(src_ip: str, dst_ip: str):
    """Return an Ether/IP layer stack with MACs pinned by direction."""
    if src_ip == CLIENT_IP:
        return scapy.Ether(src=CLIENT_MAC, dst=SERVER_MAC) / scapy.IP(src=src_ip, dst=dst_ip)
    return scapy.Ether(src=SERVER_MAC, dst=CLIENT_MAC) / scapy.IP(src=src_ip, dst=dst_ip)


def _dns_pair(ts: float, query_id: int, domain: str, resolved_ip: str, sport: int) -> list:
    """Build a DNS query + response packet pair for ``domain``."""
    query = (
        _eth_ip(CLIENT_IP, DNS_SERVER_IP)
        / scapy.UDP(sport=sport, dport=53)
        / scapy.DNS(id=query_id, rd=1, qd=scapy.DNSQR(qname=domain))
    )
    query.time = ts

    response = (
        _eth_ip(DNS_SERVER_IP, CLIENT_IP)
        / scapy.UDP(sport=53, dport=sport)
        / scapy.DNS(
            id=query_id,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=scapy.DNSQR(qname=domain),
            an=scapy.DNSRR(rrname=domain, type="A", ttl=300, rdata=resolved_ip),
        )
    )
    response.time = ts + 0.05

    return [query, response]


def _tcp_http_exchange(
    ts: float, client_ip: str, server_ip: str, sport: int, dport: int, req_bytes: bytes, resp_bytes: bytes
) -> list:
    """Build a minimal SYN/SYN-ACK/ACK + PSH request/response TCP exchange."""
    cli_seq = 1000
    srv_seq = 2000
    pkts = []

    syn = _eth_ip(client_ip, server_ip) / scapy.TCP(sport=sport, dport=dport, flags="S", seq=cli_seq)
    syn.time = ts
    pkts.append(syn)

    synack = _eth_ip(server_ip, client_ip) / scapy.TCP(
        sport=dport, dport=sport, flags="SA", seq=srv_seq, ack=cli_seq + 1
    )
    synack.time = ts + 0.01
    pkts.append(synack)

    ack = _eth_ip(client_ip, server_ip) / scapy.TCP(
        sport=sport, dport=dport, flags="A", seq=cli_seq + 1, ack=srv_seq + 1
    )
    ack.time = ts + 0.02
    pkts.append(ack)

    request = (
        _eth_ip(client_ip, server_ip)
        / scapy.TCP(sport=sport, dport=dport, flags="PA", seq=cli_seq + 1, ack=srv_seq + 1)
        / scapy.Raw(load=req_bytes)
    )
    request.time = ts + 0.03
    pkts.append(request)

    response = (
        _eth_ip(server_ip, client_ip)
        / scapy.TCP(sport=dport, dport=sport, flags="PA", seq=srv_seq + 1, ack=cli_seq + 1 + len(req_bytes))
        / scapy.Raw(load=resp_bytes)
    )
    response.time = ts + 0.04
    pkts.append(response)

    final_ack = _eth_ip(client_ip, server_ip) / scapy.TCP(
        sport=sport,
        dport=dport,
        flags="A",
        seq=cli_seq + 1 + len(req_bytes),
        ack=srv_seq + 1 + len(resp_bytes),
    )
    final_ack.time = ts + 0.05
    pkts.append(final_ack)

    return pkts


def _build_tls_client_hello(sni: str) -> bytes:
    """Build a minimal, well-formed TLS 1.2 ClientHello record with an SNI extension.

    Not a real handshake (no key share, only two cipher suites) — just enough
    structure for a dissector to recognize it as a TLS ClientHello carrying a
    server name, for protocol variety in the demo capture.
    """
    sni_bytes = sni.encode()
    server_name_entry = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes  # type=host_name(0)
    server_name_list = struct.pack(">H", len(server_name_entry)) + server_name_entry
    ext_server_name = struct.pack(">HH", 0x0000, len(server_name_list)) + server_name_list
    extensions = ext_server_name

    cipher_suites = bytes([0xC0, 0x2F, 0xC0, 0x30, 0x00, 0x9C, 0x00, 0x9D])
    random_bytes = bytes(range(32))  # deterministic filler, not real randomness

    body = (
        b"\x03\x03"  # client_version: TLS 1.2
        + random_bytes
        + b"\x00"  # session_id length: 0
        + struct.pack(">H", len(cipher_suites))
        + cipher_suites
        + b"\x01\x00"  # compression methods: length 1, method null(0)
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body  # handshake type 1 = ClientHello
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake  # content type 22 = Handshake


def _tls_hello_exchange(ts: float, client_ip: str, server_ip: str, sport: int, dport: int, sni: str) -> list:
    """Build a minimal SYN/SYN-ACK/ACK + ClientHello TCP exchange."""
    cli_seq = 3000
    srv_seq = 4000
    pkts = []

    syn = _eth_ip(client_ip, server_ip) / scapy.TCP(sport=sport, dport=dport, flags="S", seq=cli_seq)
    syn.time = ts
    pkts.append(syn)

    synack = _eth_ip(server_ip, client_ip) / scapy.TCP(
        sport=dport, dport=sport, flags="SA", seq=srv_seq, ack=cli_seq + 1
    )
    synack.time = ts + 0.01
    pkts.append(synack)

    ack = _eth_ip(client_ip, server_ip) / scapy.TCP(
        sport=sport, dport=dport, flags="A", seq=cli_seq + 1, ack=srv_seq + 1
    )
    ack.time = ts + 0.02
    pkts.append(ack)

    hello_bytes = _build_tls_client_hello(sni)
    hello = (
        _eth_ip(client_ip, server_ip)
        / scapy.TCP(sport=sport, dport=dport, flags="PA", seq=cli_seq + 1, ack=srv_seq + 1)
        / scapy.Raw(load=hello_bytes)
    )
    hello.time = ts + 0.03
    pkts.append(hello)

    return pkts


def _beacon_packets(
    start_ts: float, count: int, interval: float, client_ip: str, server_ip: str, sport: int, dport: int
) -> list:
    """Build ``count`` small TCP packets at an exact ``interval`` — a periodic beacon."""
    pkts = []
    seq = 5000
    for i in range(count):
        payload = f"chk-in-{i:02d}".encode()
        pkt = (
            _eth_ip(client_ip, server_ip)
            / scapy.TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=1)
            / scapy.Raw(load=payload)
        )
        pkt.time = start_ts + i * interval
        seq += len(payload)
        pkts.append(pkt)
    return pkts


def build_packets() -> list:
    """Return a deterministic, chronologically ordered list of demo packets."""
    pkts: list = []

    # DNS: two normal lookups, one DGA-looking lookup.
    pkts += _dns_pair(BASE_EPOCH + 0, 1, DOMAIN_NORMAL_1, NORMAL_HTTP_IP, sport=40001)
    pkts += _dns_pair(BASE_EPOCH + 1, 2, DOMAIN_NORMAL_2, TLS_SERVER_IP, sport=40002)
    pkts += _dns_pair(BASE_EPOCH + 2, 3, DOMAIN_DGA, BEACON_IP, sport=40003)

    # TLS: minimal ClientHello with SNI, for protocol variety.
    pkts += _tls_hello_exchange(BASE_EPOCH + 5, CLIENT_IP, TLS_SERVER_IP, sport=50001, dport=443, sni=DOMAIN_NORMAL_2)

    # HTTP: suspicious tool User-Agent hitting a hardcoded IP (no prior DNS lookup).
    suspicious_req = (
        b"GET /gate.php?id=1 HTTP/1.1\r\n"
        b"Host: 203.0.113.10\r\n"
        b"User-Agent: python-requests/2.31.0\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n"
    )
    suspicious_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
    pkts += _tcp_http_exchange(
        BASE_EPOCH + 10, CLIENT_IP, SUSPICIOUS_HTTP_IP, 51000, 80, suspicious_req, suspicious_resp
    )

    # HTTP: normal browser User-Agent to the site the client actually resolved.
    normal_req = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        b"Accept: text/html\r\n"
        b"Connection: close\r\n\r\n"
    )
    normal_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!"
    pkts += _tcp_http_exchange(BASE_EPOCH + 15, CLIENT_IP, NORMAL_HTTP_IP, 51001, 80, normal_req, normal_resp)

    # Beacon: 13 packets, exactly 30s apart, to a well-known C2 port.
    pkts += _beacon_packets(
        BASE_EPOCH + 20,
        count=13,
        interval=30.0,
        client_ip=CLIENT_IP,
        server_ip=BEACON_IP,
        sport=55000,
        dport=BEACON_PORT,
    )

    pkts.sort(key=lambda p: p.time)
    return pkts


def main() -> None:
    pkts = build_packets()
    scapy.wrpcap(str(FIXTURE_PATH), pkts)
    size = FIXTURE_PATH.stat().st_size
    print(f"wrote {FIXTURE_PATH} ({size} bytes, {len(pkts)} packets)")


if __name__ == "__main__":
    main()
