"""Cross-stage integration: real stage output shapes through correlation, narrator, ATT&CK.

Every input below is produced by calling the real stage function
(``analyze_dns``, ``analyze_certificates``, ``rank_beaconing``,
``detect_flow_asymmetry``, ``YARAScanResult.to_dict`` / ``scan_carved``) on small
synthetic data, never by hand-writing a dict that "looks like" stage output.
That is what catches a producer and a consumer disagreeing about a shape - the
TLS ``alerts`` counter dict being iterated as a list of alert objects went
unnoticed for exactly that reason.
"""

from __future__ import annotations

import io
import random
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pandas as pd
import pytest

from app.analysis.correlation import CorrelationResult, CorrelationSignal, correlate_indicators
from app.analysis.flow_analysis import detect_flow_asymmetry
from app.analysis.narrator import AttackNarrator
from app.pipeline import tls_certs as tls_mod
from app.pipeline import yara_scan as yara_mod
from app.pipeline.beacon import rank_beaconing
from app.pipeline.dns_analysis import analyze_dns
from app.pipeline.tls_certs import TSHARK_CERT_FIELDS, analyze_certificates
from app.pipeline.yara_scan import YARAMatch, YARAScanResult, _carve_context, scan_carved_files
from app.threat_intel.attack_mapping import ATTACKMapper

pytestmark = pytest.mark.skipif(not tls_mod.HAS_CRYPTOGRAPHY, reason="cryptography not installed")

T0 = 1568538830.0  # 2019-09-15, an old capture
CAPTURE_TIME = datetime.fromtimestamp(T0, tz=timezone.utc)
CLIENT = "192.168.1.50"
# Globally routable addresses (documentation ranges are not "public" to ipaddress)
C2_IP = "93.184.216.34"
EXFIL_IP = "185.100.87.1"
BENIGN_IP = "151.101.1.69"
TUNNEL_BASE = "updates-cdn.co.uk"
DGA_DOMAIN = "www.xkqjzvbnmwpl.com"


class FakePopen:
    """Minimal Popen stand-in whose stdout is iterable line by line."""

    def __init__(self, lines):
        self.stdout = iter(list(lines))
        self.stderr = io.StringIO("")
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


def _flow(src, dst, sport, dport, start, count=6, total_bytes=2435) -> dict:
    """Flow in the shape ``parse_pcap_pyshark`` emits.

    Short flows are a handshake-sized burst; bulk flows get bursty, irregular
    packet timing like a real transfer (evenly spaced packets would themselves
    look like a beacon).
    """
    samples = min(count, 300)
    if count <= 10:
        pkt_times = [start + i * 0.04 for i in range(samples)]
    else:
        rng = random.Random(f"{src}-{dst}-{sport}")
        pkt_times, t = [], start
        for _ in range(samples):
            t += rng.expovariate(1 / 0.02)
            pkt_times.append(t)
    return {
        "src": src,
        "dst": dst,
        "sport": str(sport),
        "dport": str(dport),
        "proto": "tcp",
        "count": count,
        "bytes": total_bytes,
        "first_ts": pkt_times[0],
        "last_ts": pkt_times[-1],
        "pkt_times": pkt_times,
        "pkt_lens": [total_bytes // count] * samples,
        "mac_src": "aa:bb:cc:00:00:01",
        "mac_dst": "aa:bb:cc:00:00:02",
    }


def _self_signed_der(common_name: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(CAPTURE_TIME - timedelta(days=30))
        .not_valid_after(CAPTURE_TIME + timedelta(days=335))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _tshark_cert_line(der: bytes, server_ip: str, client_ip: str, epoch: float) -> str:
    """One line as tshark emits it with ``-E separator=| -E quote=d -E occurrence=a``."""
    values = {
        "frame.number": "81",
        "ip.src": server_ip,  # the Certificate frame travels server -> client
        "ip.dst": client_ip,
        "tcp.dstport": "49757",
        "tls.handshake.certificate": der.hex(),
        "x509sat.printableString": "c2-panel.net",
        "x509af.utcTime": "2019-08-16 09:13:50 (UTC),2020-08-15 09:13:50 (UTC)",
        "x509af.serialNumber": "04a1b2c3d4e5f6",
        "x509af.algorithm.id": "1.2.840.10045.4.3.2,1.2.840.10045.2.1,1.2.840.10045.4.3.2",
        "frame.time_epoch": f"{epoch:.9f}",
        "tcp.srcport": "443",
    }
    return "|".join(f'"{values[name]}"' if values.get(name) else "" for name in TSHARK_CERT_FIELDS) + "\n"


def _yara_results_from_dataclasses(carve_item: dict) -> dict:
    """YARA stage output assembled from the real result dataclasses."""
    match = YARAMatch(
        rule_name="Suspicious_Dropper",
        rule_tags=["malware"],
        meta={"author": "test"},
        strings=[(0, "$a", b"MZ")],
        file_path=carve_item["path"],
        file_hash=carve_item["sha256"],
    )
    scan = YARAScanResult(file_path=carve_item["path"], file_hash=carve_item["sha256"], file_size=4096, matches=[match])
    entry = scan.to_dict()
    entry.update(_carve_context(carve_item))
    return {
        "scanned": 1,
        "matched": 1,
        "errors": 0,
        "results": [entry],
        "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "clean": 0},
        "yara_available": True,
        "rule_count": 1,
    }


@pytest.fixture
def stage_outputs(tmp_path):
    """Run each real stage on synthetic input and return its untouched output."""
    # --- flows: a reconnecting beacon, a large upload, and an ordinary download
    flows = [_flow(CLIENT, C2_IP, 49152 + i, 443, T0 + i * 60.0) for i in range(25)]
    flows += [
        _flow(CLIENT, EXFIL_IP, 50900, 443, T0 + 100, count=9000, total_bytes=14_000_000),
        _flow(EXFIL_IP, CLIENT, 443, 50900, T0 + 100.01, count=900, total_bytes=60_000),
        _flow(CLIENT, BENIGN_IP, 50901, 443, T0 + 200, count=400, total_bytes=40_000),
        _flow(BENIGN_IP, CLIENT, 443, 50901, T0 + 200.01, count=8000, total_bytes=11_000_000),
    ]

    # --- DNS: tunneling under a multi-part suffix, one DGA name, ordinary lookups
    dns_rows = [
        {
            "ts": T0 + 10 + i,
            "query": f"{i:04d}aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVkIGRhdGE{i:04d}.{TUNNEL_BASE}",
            "qtype_name": "TXT",
        }
        for i in range(150)
    ]
    dns_rows += [
        {"ts": T0 + 5, "query": DGA_DOMAIN, "qtype_name": "A"},
        {"ts": T0 + 6, "query": "www.google.com", "qtype_name": "A"},
        {"ts": T0 + 7, "query": "en.wikipedia.org", "qtype_name": "A"},
    ]
    dns_log = pd.DataFrame(
        [
            {
                "id.orig_h": CLIENT,
                "id.resp_h": "192.168.1.1",
                "rcode_name": "NOERROR",
                "answers": "-",
                "TTLs": "-",
                **row,
            }
            for row in dns_rows
        ]
    )
    dns_analysis = analyze_dns({"dns.log": dns_log})

    # --- TLS: a self-signed certificate served by the beacon destination
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
    line = _tshark_cert_line(_self_signed_der("c2-panel.net"), C2_IP, CLIENT, T0 + 0.5)
    with (
        patch.object(tls_mod, "find_bin", return_value="/usr/bin/tshark"),
        patch.object(tls_mod.subprocess, "Popen", return_value=FakePopen([line])),
    ):
        tls_analysis = analyze_certificates(pcap_path=pcap)

    # --- YARA: carve item exactly as carve_http_payloads emits it (no endpoint IPs)
    carve_item = {
        "time": f"{T0 + 300:.6f}",
        "tcp_stream": "7",
        "content_type": "application/octet-stream",
        "content_length": "4096",
        "sha256": "0123456789" + "a" * 54,
        "path": str(tmp_path / "stream7_0123456789.bin"),
    }

    beacon_df = rank_beaconing(flows, top_n=20)
    return {
        "features": {
            "flows": flows,
            "artifacts": {
                "ips": sorted({CLIENT, C2_IP, EXFIL_IP, BENIGN_IP}),
                "domains": sorted({r["query"] for r in dns_rows}),
                "urls": [],
                "hashes": [],
                "ja3": [],
                "macs": [],
            },
        },
        "dns_analysis": dns_analysis,
        "tls_analysis": tls_analysis,
        "beacon_df": beacon_df,
        "beacon_records": beacon_df.to_dict("records"),
        "yara_results": _yara_results_from_dataclasses(carve_item),
        "carve_item": carve_item,
        "asymmetry": detect_flow_asymmetry(flows),
    }


def _correlate(out: dict, **overrides) -> dict[str, CorrelationResult]:
    kwargs = {
        "features": out["features"],
        "osint": {},
        "beacon_df": out["beacon_df"],
        "dns_analysis": out["dns_analysis"],
        "tls_analysis": out["tls_analysis"],
        "yara_results": out["yara_results"],
        "asymmetry_results": out["asymmetry"],
    }
    kwargs.update(overrides)
    results = correlate_indicators(**kwargs)
    assert all(isinstance(r, CorrelationResult) for r in results)
    assert all(isinstance(s, CorrelationSignal) for r in results for s in r.signals)
    return {r.indicator: r for r in results}


def _signal_names(result: CorrelationResult) -> set[str]:
    return {s.name for s in result.signals}


class TestStageOutputsAreWhatConsumersExpect:
    def test_stage_shapes(self, stage_outputs):
        tls = stage_outputs["tls_analysis"]
        assert isinstance(tls["alerts"], dict), "UI reads TLS alerts as a dict of counters"
        assert tls["alerts"]["self_signed_count"] == 1
        assert [(a["type"], a["dst_ip"]) for a in tls["certificate_alerts"]] == [("self_signed", C2_IP)]
        # Valid at capture time, expired by today's clock
        assert tls["alerts"]["expired_count"] == 0

        dns = stage_outputs["dns_analysis"]
        assert [t["domain"] for t in dns["tunneling_detections"] if t["is_tunneling"]] == [TUNNEL_BASE]
        assert [d["domain"] for d in dns["dga_detections"] if d["is_dga"]] == [DGA_DOMAIN]

        beacons = stage_outputs["beacon_df"]
        assert beacons.iloc[0]["dst"] == C2_IP
        assert beacons.iloc[0]["aggregation"] == "connection"

        assert [(a.src, a.dst) for a in stage_outputs["asymmetry"]] == [(CLIENT, EXFIL_IP)]


class TestCorrelation:
    def test_tls_and_beacon_signals_reach_the_same_ip(self, stage_outputs):
        results = _correlate(stage_outputs)
        c2 = results[C2_IP]
        assert {"beacon_score", "self_signed_cert"} <= _signal_names(c2)
        tls_signal = next(s for s in c2.signals if s.name == "self_signed_cert")
        assert tls_signal.source == "tls"
        # Two independent signals outrank either alone
        beacon_only = _correlate(stage_outputs, tls_analysis={})[C2_IP]
        assert c2.composite_score > beacon_only.composite_score

    def test_expired_signal_absent_for_cert_valid_at_capture_time(self, stage_outputs):
        assert "expired_cert" not in _signal_names(_correlate(stage_outputs)[C2_IP])

    def test_tunneling_reaches_the_base_domain_without_flooding(self, stage_outputs):
        results = _correlate(stage_outputs)
        assert TUNNEL_BASE not in stage_outputs["features"]["artifacts"]["domains"]
        assert "dns_tunneling" in _signal_names(results[TUNNEL_BASE])
        # 150 encoded query names under the base do not become 150 result rows
        assert [name for name in results if name.endswith("." + TUNNEL_BASE)] == []

    def test_tunneling_matches_queried_fqdn_by_suffix_when_otherwise_implicated(self, stage_outputs):
        fqdn = next(d for d in stage_outputs["features"]["artifacts"]["domains"] if d.endswith("." + TUNNEL_BASE))
        osint = {
            "domains": {
                fqdn: {
                    "vt": {
                        "data": {
                            "attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 60, "undetected": 8}}
                        }
                    }
                }
            }
        }
        result = _correlate(stage_outputs, osint=osint)[fqdn]
        assert {"vt_detections", "dns_tunneling"} <= _signal_names(result)

    def test_unrelated_domain_with_shared_ending_does_not_match(self, stage_outputs):
        features = dict(stage_outputs["features"])
        features["artifacts"] = {**features["artifacts"], "domains": [f"evil{TUNNEL_BASE}"]}
        results = _correlate(stage_outputs, features=features)
        assert f"evil{TUNNEL_BASE}" not in results

    def test_dga_signal_matches_real_detection(self, stage_outputs):
        assert "dga_domain" in _signal_names(_correlate(stage_outputs)[DGA_DOMAIN])

    def test_flow_asymmetry_signal_targets_the_upload_destination_only(self, stage_outputs):
        results = _correlate(stage_outputs)
        assert "flow_asymmetry" in _signal_names(results[EXFIL_IP])
        assert BENIGN_IP not in results  # a download source carries no signal at all

    def test_yara_without_endpoints_degrades_loudly(self, stage_outputs, caplog):
        """carve output has no IPs today: no signal, and a warning that says why."""
        assert "src_ip" not in stage_outputs["yara_results"]["results"][0]
        with caplog.at_level("WARNING", logger="app.analysis.correlation"):
            results = _correlate(stage_outputs)
        assert not any("yara_match" in _signal_names(r) for r in results.values())
        assert "1 YARA-matched file(s) carry no src_ip/dst_ip" in caplog.text

    def test_yara_signal_attaches_once_carve_records_endpoints(self, stage_outputs, caplog):
        """Shape the YARA stage emits as soon as carve items carry src_ip/dst_ip."""
        carve_item = {**stage_outputs["carve_item"], "src_ip": C2_IP, "dst_ip": CLIENT}
        yara_results = _yara_results_from_dataclasses(carve_item)
        assert yara_results["results"][0]["src_ip"] == C2_IP
        with caplog.at_level("WARNING", logger="app.analysis.correlation"):
            results = _correlate(stage_outputs, yara_results=yara_results)
        assert "yara_match" in _signal_names(results[C2_IP])
        assert "YARA-matched" not in caplog.text

    def test_old_saved_tls_shape_is_tolerated(self, stage_outputs):
        """Analyses persisted before ``certificate_alerts`` existed are re-read from SQLite."""
        legacy = {k: v for k, v in stage_outputs["tls_analysis"].items() if k != "certificate_alerts"}
        legacy["certificates"] = [
            {k: v for k, v in cert.items() if k not in ("server_ip", "server_port", "server_ips", "client_ip")}
            for cert in legacy["certificates"]
        ]
        results = _correlate(stage_outputs, tls_analysis=legacy)
        assert "self_signed_cert" not in _signal_names(results[C2_IP])
        assert "beacon_score" in _signal_names(results[C2_IP])

    def test_empty_beacon_frame_is_quiet(self, stage_outputs, caplog):
        with caplog.at_level("WARNING", logger="app.analysis.correlation"):
            _correlate(stage_outputs, beacon_df=pd.DataFrame(), yara_results=None)
        assert caplog.text == ""


class TestNarrator:
    def test_timeline_from_real_stage_outputs(self, stage_outputs):
        timeline = AttackNarrator().create_timeline(
            features=stage_outputs["features"],
            dns_analysis=stage_outputs["dns_analysis"],
            yara_results=stage_outputs["yara_results"],
            beacon_results=stage_outputs["beacon_records"],
            tls_analysis=stage_outputs["tls_analysis"],
        )
        by_type = {e.event_type: e for e in timeline}
        assert set(by_type) == {"c2_beacon", "yara_match", "dga_detection", "dns_tunneling", "tls_anomaly"}

        # Every event carries a time observed in the 2019 capture - none is "now"
        for event in timeline:
            assert event.time_observed is True, event.event_type
            assert event.timestamp.tzinfo is not None
            assert CAPTURE_TIME <= event.timestamp <= CAPTURE_TIME + timedelta(hours=1), event.event_type

        assert by_type["tls_anomaly"].description == "Self-signed certificate for c2-panel.net"
        assert by_type["tls_anomaly"].dest_ip == C2_IP
        assert by_type["c2_beacon"].dest_ip == C2_IP
        assert by_type["c2_beacon"].timestamp == CAPTURE_TIME
        assert by_type["dns_tunneling"].iocs == [TUNNEL_BASE]
        assert "stream7_0123456789.bin" in by_type["yara_match"].description

    def test_basic_narrative_from_real_stage_outputs(self, stage_outputs):
        mapping = ATTACKMapper().map_analysis(
            features=stage_outputs["features"],
            dns_analysis=stage_outputs["dns_analysis"],
            tls_analysis=stage_outputs["tls_analysis"],
            yara_results=stage_outputs["yara_results"],
            beacon_results=stage_outputs["beacon_records"],
        )
        narrative = AttackNarrator().generate_narrative(
            features=stage_outputs["features"],
            dns_analysis=stage_outputs["dns_analysis"],
            tls_analysis=stage_outputs["tls_analysis"],
            yara_results=stage_outputs["yara_results"],
            beacon_results=stage_outputs["beacon_records"],
            attack_mapping=mapping,
        )
        assert "c2_beacon" in narrative
        assert "MITRE ATT&CK Coverage" in narrative


class TestAttackMapping:
    def test_mapping_from_real_stage_outputs(self, stage_outputs):
        mapping = ATTACKMapper().map_analysis(
            features=stage_outputs["features"],
            dns_analysis=stage_outputs["dns_analysis"],
            tls_analysis=stage_outputs["tls_analysis"],
            yara_results=stage_outputs["yara_results"],
            beacon_results=stage_outputs["beacon_records"],
        )
        techniques = {t.technique_id: t for t in mapping.techniques}

        # TLS: reached via certificate_alerts, with the server endpoint in evidence
        tls = techniques["T1573.002"]
        assert any("Self-signed certificate: c2-panel.net" in e and C2_IP in e for e in tls.evidence)

        # Beaconing on port 443 clears the 0.7 mapping threshold
        assert any(C2_IP in e for e in techniques["T1071.001"].evidence)

        # DNS
        assert "T1568.002" in techniques
        assert "T1071.004" in techniques

        # Exfiltration names the upload destination, never the download
        exfil_evidence = " ".join(techniques["T1048"].evidence)
        assert EXFIL_IP in exfil_evidence
        assert BENIGN_IP not in exfil_evidence
        assert f"to {CLIENT}" not in exfil_evidence

        # YARA evidence names the real carved file (results carry file_path, not file_name)
        assert any("stream7_0123456789.bin" in e for e in techniques["T1059"].evidence)

    def test_tls_counters_alone_map_nothing(self):
        mapping = ATTACKMapper().map_analysis(
            tls_analysis={"alerts": {"self_signed_count": 3, "expired_count": 1, "high_risk_count": 0}}
        )
        assert mapping.techniques == []


@pytest.mark.skipif(not yara_mod.YARA_AVAILABLE, reason="yara-python not installed")
class TestRealYaraScanCarriesCarveContext:
    def test_scan_carved_propagates_stream_time_and_endpoints(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "dropper.yar").write_text(
            'rule Suspicious_Dropper : malware { strings: $a = "EVIL_MARKER_PAYLOAD" condition: $a }\n'
        )
        carved_dir = tmp_path / "carved"
        carved_dir.mkdir()
        hit = carved_dir / "stream7_0123456789.bin"
        hit.write_bytes(b"MZ\x90\x00 EVIL_MARKER_PAYLOAD \x00")
        clean = carved_dir / "stream9_ffffffffff.bin"
        clean.write_bytes(b"<html>hello</html>")

        def carve_item(path, stream, **extra):
            return {
                "time": f"{T0 + 300:.6f}",
                "tcp_stream": stream,
                "content_type": "application/octet-stream",
                "content_length": str(path.stat().st_size),
                "sha256": "unused-by-scanner",
                "path": str(path),
                **extra,
            }

        # Today's carve shape (no endpoints), then the shape with endpoints recorded
        today = scan_carved_files([carve_item(hit, "7"), carve_item(clean, "9")], rules_dirs=[str(rules_dir)])
        assert today["matched"] == 1
        entry = next(r for r in today["results"] if r["has_matches"])
        assert entry["tcp_stream"] == "7"
        assert entry["observed_time"] == f"{T0 + 300:.6f}"
        assert "src_ip" not in entry and "dst_ip" not in entry
        # Existing keys are untouched
        assert {"file_path", "file_hash", "file_size", "matches", "scan_time", "error", "severity"} <= set(entry)
        assert entry["severity"] == "critical"

        with_ips = scan_carved_files([carve_item(hit, "7", src_ip=C2_IP, dst_ip=CLIENT)], rules_dirs=[str(rules_dir)])
        entry = with_ips["results"][0]
        assert (entry["src_ip"], entry["dst_ip"]) == (C2_IP, CLIENT)

        features = {"flows": [], "artifacts": {"ips": [C2_IP, CLIENT], "domains": []}}
        results = correlate_indicators(features=features, yara_results=with_ips)
        assert [(r.indicator, [s.name for s in r.signals]) for r in results] == [(C2_IP, ["yara_match"])]

        timeline = AttackNarrator().create_timeline(yara_results=today)
        assert len(timeline) == 1
        assert timeline[0].timestamp == datetime.fromtimestamp(T0 + 300, tz=timezone.utc)
