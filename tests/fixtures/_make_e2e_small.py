"""Generate ``tests/fixtures/e2e_small.pcap`` deterministically.

Run once locally to regenerate the fixture if it's lost or needs to evolve:

    python tests/fixtures/_make_e2e_small.py

The committed ``e2e_small.pcap`` is the default capture for
``tests/test_e2e_pipeline.py``. It is fully synthetic (RFC 1918 clients,
RFC 5737 documentation servers, RFC 2606 example domains) and small enough
to commit, but richer than ``tiny.pcap`` so the end-to-end assertions mean
something:

* DNS queries and answers for four example domains (Zeek ``dns.log``)
* one complete HTTP/1.1 GET with a response body (Zeek ``http.log``, carving)
* twelve short TCP sessions to distinct external hosts on port 443
* ten evenly spaced UDP datagrams to one host (periodic, beacon-shaped)

It deliberately contains no TLS handshake, so TLS-certificate assertions
still need a real capture (see ``PCAP_HUNTER_E2E_PCAP`` in the test module).

Every MAC, IP ID, DNS ID, TCP sequence number and timestamp is pinned, so
regenerating produces byte-identical output wherever and whenever it runs.
If you change the traffic, update ``FIXTURE_PACKET_COUNT`` and
``FIXTURE_EXTERNAL_IPS`` in ``tests/test_e2e_pipeline.py`` to match.

Tests must NOT import this module — they read the committed file directly.
"""

from __future__ import annotations

import pathlib

import scapy.all as scapy

FIXTURE_PATH = pathlib.Path(__file__).parent / "e2e_small.pcap"
# Pinned epoch for deterministic record timestamps: 2026-01-01T00:00:00 UTC.
BASE_EPOCH = 1767225600

CLIENT_MAC = "00:00:00:00:00:10"
GATEWAY_MAC = "00:00:00:00:00:01"
CLIENT_IP = "10.0.0.5"
RESOLVER_IP = "10.0.0.53"
WEB_SERVER_IP = "192.0.2.10"
BEACON_IP = "203.0.113.50"

DNS_ANSWERS = {
    "example.com": WEB_SERVER_IP,
    "example.org": "192.0.2.20",
    "example.net": "192.0.2.30",
    "www.example.com": WEB_SERVER_IP,
}
SHORT_SESSION_IPS = [f"198.51.100.{i}" for i in range(1, 7)] + [f"203.0.113.{i}" for i in range(1, 7)]

HTTP_REQUEST = (
    b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pcap-hunter-fixture/1.0\r\nAccept: */*\r\n\r\n"
)
HTTP_BODY = b"<html><body><h1>PCAP Hunter synthetic fixture</h1></body></html>\n"
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nServer: fixture\r\nContent-Type: text/html\r\nContent-Length: "
    + str(len(HTTP_BODY)).encode()
    + b"\r\nConnection: close\r\n\r\n"
    + HTTP_BODY
)


class _Builder:
    """Accumulates packets with pinned IP IDs and timestamps."""

    def __init__(self) -> None:
        self.packets: list = []
        self._ip_id = 1

    def add(self, offset: float, src: str, dst: str, l4) -> None:
        outbound = src.startswith("10.") and not dst.startswith("10.")
        inbound = dst.startswith("10.") and not src.startswith("10.")
        if outbound or (src == CLIENT_IP and not inbound):
            eth = scapy.Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        else:
            eth = scapy.Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
        pkt = eth / scapy.IP(src=src, dst=dst, id=self._ip_id, ttl=64, flags="DF") / l4
        self._ip_id += 1
        pkt.time = BASE_EPOCH + offset
        self.packets.append(pkt)

    def tcp_session(
        self, start: float, server: str, sport: int, dport: int, request: bytes = b"", response: bytes = b""
    ) -> None:
        """Add a complete TCP session: handshake, optional payloads, orderly close."""
        c_seq, s_seq = 1000, 5000
        step = 0.01

        def client(i: int, flags: str, seq: int, ack: int, payload: bytes = b"") -> None:
            tcp = scapy.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=65535)
            self.add(start + i * step, CLIENT_IP, server, tcp / payload if payload else tcp)

        def srv(i: int, flags: str, seq: int, ack: int, payload: bytes = b"") -> None:
            tcp = scapy.TCP(sport=dport, dport=sport, flags=flags, seq=seq, ack=ack, window=65535)
            self.add(start + i * step, server, CLIENT_IP, tcp / payload if payload else tcp)

        client(0, "S", c_seq, 0)
        srv(1, "SA", s_seq, c_seq + 1)
        c_seq, s_seq = c_seq + 1, s_seq + 1
        client(2, "A", c_seq, s_seq)
        i = 3
        if request:
            client(i, "PA", c_seq, s_seq, request)
            c_seq += len(request)
            srv(i + 1, "A", s_seq, c_seq)
            i += 2
        if response:
            srv(i, "PA", s_seq, c_seq, response)
            s_seq += len(response)
            client(i + 1, "A", c_seq, s_seq)
            i += 2
        client(i, "FA", c_seq, s_seq)
        srv(i + 1, "FA", s_seq, c_seq + 1)
        client(i + 2, "A", c_seq + 1, s_seq + 1)


def build_packets() -> list:
    """Return the deterministic packet list, ordered by timestamp."""
    b = _Builder()

    # DNS: one query + one answer per domain.
    for n, (name, addr) in enumerate(DNS_ANSWERS.items()):
        t = n * 0.5
        sport = 40000 + n
        question = scapy.DNSQR(qname=name, qtype="A")
        query = scapy.UDP(sport=sport, dport=53) / scapy.DNS(id=0x1000 + n, rd=1, qd=question)
        answer = scapy.UDP(sport=53, dport=sport) / scapy.DNS(
            id=0x1000 + n, qr=1, rd=1, ra=1, qd=question, an=scapy.DNSRR(rrname=name, type="A", ttl=300, rdata=addr)
        )
        b.add(t, CLIENT_IP, RESOLVER_IP, query)
        b.add(t + 0.02, RESOLVER_IP, CLIENT_IP, answer)

    # One complete HTTP exchange.
    b.tcp_session(5.0, WEB_SERVER_IP, 49200, 80, request=HTTP_REQUEST, response=HTTP_RESPONSE)

    # Twelve short sessions to distinct external hosts.
    for n, server in enumerate(SHORT_SESSION_IPS):
        b.tcp_session(10.0 + n, server, 50000 + n, 443)

    # Ten evenly spaced UDP datagrams to one host (60 s apart).
    for n in range(10):
        b.add(30.0 + 60.0 * n, CLIENT_IP, BEACON_IP, scapy.UDP(sport=51000, dport=8080) / (b"ping-%02d" % n))

    return sorted(b.packets, key=lambda p: float(p.time))


def main() -> None:
    pkts = build_packets()
    scapy.wrpcap(str(FIXTURE_PATH), pkts)
    size = FIXTURE_PATH.stat().st_size
    print(f"wrote {FIXTURE_PATH} ({size} bytes, {len(pkts)} packets)")


if __name__ == "__main__":
    main()
