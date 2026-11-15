"""Exfiltration direction: flow asymmetry and ATT&CK data-transfer / suspect-port mapping.

Flows use the directional shape ``parse_pcap_pyshark`` emits (``bytes`` is what
``src`` sent to ``dst``); the reverse direction is a separate flow.
"""

from __future__ import annotations

import pytest

from app.analysis.flow_analysis import (
    DIRECTION_EXTERNAL,
    DIRECTION_INBOUND,
    DIRECTION_INTERNAL,
    DIRECTION_OUTBOUND,
    DIRECTION_UNKNOWN,
    classify_direction,
    detect_flow_asymmetry,
    is_internal_address,
)
from app.threat_intel.attack_mapping import ATTACKMapper

CLIENT = "192.168.1.50"
# Globally routable addresses: documentation ranges (203.0.113.0/24 etc.) are not
# "public" to ``ipaddress`` and would be classified as internal.
SERVER = "93.184.216.34"
EXFIL_TECHNIQUES = {"T1048", "T1041"}


def _flow(src: str, dst: str, sport: int, dport: int, count: int, total_bytes: int, first_ts: float = 1700000000.0):
    return {
        "src": src,
        "dst": dst,
        "sport": str(sport),
        "dport": str(dport),
        "proto": "tcp",
        "count": count,
        "bytes": total_bytes,
        "first_ts": first_ts,
        "last_ts": first_ts + 30.0,
        "pkt_times": [first_ts + i * 0.01 for i in range(min(count, 50))],
        "pkt_lens": [total_bytes // max(count, 1)] * min(count, 50),
        "mac_src": "aa:bb:cc:00:00:01",
        "mac_dst": "aa:bb:cc:00:00:02",
    }


def _download(first: str = "request") -> list[dict]:
    """Internal client downloads 10 MB from a public server."""
    request = _flow(CLIENT, SERVER, 50123, 443, 400, 40_000)
    response = _flow(SERVER, CLIENT, 443, 50123, 7_000, 10_000_000)
    return [request, response] if first == "request" else [response, request]


def _upload(first: str = "request") -> list[dict]:
    """Internal client uploads 12 MB to a public server."""
    upload = _flow(CLIENT, SERVER, 50124, 443, 8_500, 12_000_000)
    acks = _flow(SERVER, CLIENT, 443, 50124, 900, 60_000)
    return [upload, acks] if first == "request" else [acks, upload]


class TestAddressScope:
    @pytest.mark.parametrize(
        "ip", ["10.1.2.3", "172.16.5.5", "192.168.1.50", "127.0.0.1", "169.254.1.1", "100.64.0.9", "fd00::5", "fe80::1"]
    )
    def test_internal(self, ip):
        assert is_internal_address(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"])
    def test_public(self, ip):
        assert is_internal_address(ip) is False

    @pytest.mark.parametrize("ip", ["", "not-an-ip", "224.0.0.251", "ff02::fb", "0.0.0.0"])
    def test_not_a_unicast_host(self, ip):
        assert is_internal_address(ip) is None

    def test_documentation_ranges_are_not_public(self):
        """Same notion of "public" as ``app.utils.network_utils.is_public_ipv4`` (``is_global``)."""
        assert is_internal_address("203.0.113.10") is True

    def test_classify_direction(self):
        assert classify_direction("192.168.1.50", "8.8.8.8") == DIRECTION_OUTBOUND
        assert classify_direction("8.8.8.8", "192.168.1.50") == DIRECTION_INBOUND
        assert classify_direction("10.0.0.1", "10.0.0.2") == DIRECTION_INTERNAL
        assert classify_direction("8.8.8.8", "1.1.1.1") == DIRECTION_EXTERNAL
        assert classify_direction("fd00::5", "2001:4860:4860::8888") == DIRECTION_OUTBOUND
        assert classify_direction("192.168.1.50", "224.0.0.251") == DIRECTION_UNKNOWN


class TestFlowAsymmetryOrientation:
    @pytest.mark.parametrize("first", ["request", "response"])
    def test_upload_is_found_whichever_direction_was_seen_first(self, first):
        results = detect_flow_asymmetry(_upload(first))
        assert len(results) == 1
        top = results[0]
        assert (top.src, top.dst) == (CLIENT, SERVER)
        assert top.direction == DIRECTION_OUTBOUND
        assert top.outbound_bytes == 12_000_000
        assert top.inbound_bytes == 60_000
        assert top.ratio == pytest.approx(200.0)
        assert top.is_suspicious is True
        assert top.to_dict()["direction"] == DIRECTION_OUTBOUND

    @pytest.mark.parametrize("first", ["request", "response"])
    def test_download_is_never_reported(self, first):
        assert detect_flow_asymmetry(_download(first)) == []

    def test_internal_staging_transfer_is_kept_and_labelled(self):
        flows = [
            _flow("10.0.0.5", "10.0.0.200", 50200, 445, 20_000, 25_000_000),
            _flow("10.0.0.200", "10.0.0.5", 445, 50200, 2_000, 150_000),
        ]
        results = detect_flow_asymmetry(flows)
        assert [(r.src, r.dst, r.direction) for r in results] == [("10.0.0.5", "10.0.0.200", DIRECTION_INTERNAL)]

    def test_public_to_public_is_kept_and_labelled(self):
        flows = [_flow("185.100.87.1", SERVER, 50300, 443, 9_000, 12_000_000)]
        results = detect_flow_asymmetry(flows)
        assert [r.direction for r in results] == [DIRECTION_EXTERNAL]

    def test_ipv6_exfil(self):
        flows = [_flow("fd00::5", "2606:4700:4700::1111", 50400, 443, 9_000, 12_000_000)]
        results = detect_flow_asymmetry(flows)
        assert [(r.direction, r.is_suspicious) for r in results] == [(DIRECTION_OUTBOUND, True)]


class TestAttackMappingDataTransfer:
    @pytest.mark.parametrize("first", ["request", "response"])
    def test_download_is_not_exfiltration(self, first):
        mapping = ATTACKMapper().map_analysis(features={"flows": _download(first)})
        assert not EXFIL_TECHNIQUES & {t.technique_id for t in mapping.techniques}
        assert "exfiltration" not in mapping.tactics_summary

    def test_upload_to_public_destination_maps_exfiltration(self):
        mapping = ATTACKMapper().map_analysis(features={"flows": _upload()})
        techniques = {t.technique_id: t for t in mapping.techniques}
        assert EXFIL_TECHNIQUES <= set(techniques)
        evidence = techniques["T1048"].evidence[0]
        assert SERVER in evidence and CLIENT in evidence and "12.0 MB" in evidence
        assert "192.168" not in evidence.split(" from ")[0]  # destination named is the public one

    def test_internal_transfer_is_not_exfiltration(self):
        flows = [_flow("10.0.0.5", "10.0.0.200", 50200, 445, 20_000, 25_000_000)]
        mapping = ATTACKMapper().map_analysis(features={"flows": flows})
        assert not EXFIL_TECHNIQUES & {t.technique_id for t in mapping.techniques}

    def test_outbound_bytes_are_summed_across_connections_to_one_destination(self):
        flows = [_flow(CLIENT, SERVER, 50500 + i, 443, 3_000, 4_000_000) for i in range(3)]
        mapping = ATTACKMapper().map_analysis(features={"flows": flows})
        assert EXFIL_TECHNIQUES <= {t.technique_id for t in mapping.techniques}


class TestSuspectPorts:
    @staticmethod
    def _t1571(mapping):
        return next((t for t in mapping.techniques if t.technique_id == "T1571"), None)

    @pytest.mark.parametrize("port", [8888, 5555, 9999])
    def test_single_packet_does_not_map(self, port):
        flows = [_flow(CLIENT, SERVER, 50600, port, 1, 74)]
        assert self._t1571(ATTACKMapper().map_analysis(features={"flows": flows})) is None

    def test_sustained_use_maps_with_low_confidence_when_alone(self):
        flows = [_flow(CLIENT, SERVER, 50600, 8888, 40, 6_000)]
        match = self._t1571(ATTACKMapper().map_analysis(features={"flows": flows}))
        assert match is not None
        assert match.confidence == pytest.approx(0.4)
        assert "8888" in match.evidence[0] and "no corroborating signal" in match.evidence[0]

    def test_repeated_small_connections_map(self):
        flows = [_flow(CLIENT, SERVER, 50600 + i, 8888, 3, 200) for i in range(3)]
        match = self._t1571(ATTACKMapper().map_analysis(features={"flows": flows}))
        assert match is not None
        assert "9 packets in 3 flow(s)" in match.evidence[0]

    def test_confidence_rises_when_destination_also_beacons(self):
        flows = [_flow(CLIENT, SERVER, 50600, 8888, 40, 6_000)]
        beacon = {"src": CLIENT, "dst": SERVER, "dport": "8888", "proto": "tcp", "score": 0.55}
        match = self._t1571(ATTACKMapper().map_analysis(features={"flows": flows}, beacon_results=[beacon]))
        assert match.confidence == pytest.approx(0.7)

    def test_confidence_is_moderate_with_unrelated_corroboration(self):
        flows = [_flow(CLIENT, SERVER, 50600, 8888, 40, 6_000), *_upload()]
        match = self._t1571(ATTACKMapper().map_analysis(features={"flows": flows}))
        assert match.confidence == pytest.approx(0.55)

    def test_reply_to_ephemeral_port_is_not_a_suspect_port(self):
        """443 -> client port 8888 is a reply whose ephemeral port collided with the list."""
        flows = [_flow(SERVER, CLIENT, 443, 8888, 500, 600_000)]
        assert self._t1571(ATTACKMapper().map_analysis(features={"flows": flows})) is None

    def test_flows_beyond_the_first_thousand_are_counted(self):
        noise = [_flow(CLIENT, "151.101.1.69", 40000 + i, 443, 5, 400) for i in range(1200)]
        flows = [*noise, _flow(CLIENT, SERVER, 50600, 31337, 40, 6_000)]
        assert self._t1571(ATTACKMapper().map_analysis(features={"flows": flows})) is not None
