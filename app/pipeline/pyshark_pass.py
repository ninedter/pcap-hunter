from __future__ import annotations

import os
import subprocess
from typing import Any

from app import config as C
from app.pipeline.state import PhaseHandle
from app.utils.common import find_bin, uniq_sorted
from app.utils.logger import log_runtime_error


def parse_pcap_pyshark(
    pcap_path: str,
    limit_packets: int | None,
    phase: PhaseHandle | None,
    total_packets: int | None,
    progress_every: int = 2000,
) -> dict[str, Any]:
    # Input validation
    if not os.path.exists(pcap_path):
        log_runtime_error(f"PCAP file not found: {pcap_path}")
        return {
            "flows": [],
            "artifacts": {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "ja3": set(), "macs": set()},
        }

    if limit_packets is not None and not isinstance(limit_packets, int):
        log_runtime_error(f"Invalid limit_packets value: {limit_packets}")
        limit_packets = None

    tshark_path = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark_path:
        log_runtime_error("Tshark binary not found. Analysis may fail.")
        return {
            "flows": [],
            "artifacts": {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "ja3": set()},
        }

    # Fields to extract (from config)
    cmd = [
        tshark_path,
        "-r",
        pcap_path,
        "-T",
        "fields",
        "-E",
        "separator=\t",
    ]
    for field in C.TSHARK_FIELDS:
        cmd.extend(["-e", field])
    # Add packet length field
    cmd.extend(["-e", "frame.len"])

    # Tell tshark to stop after N packets (avoids reading entire PCAP when limited)
    if limit_packets:
        cmd.extend(["-c", str(limit_packets)])

    out = {
        "flows": [],
        "artifacts": {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "ja3": set(), "macs": set()},
    }
    flow_index: dict[tuple[str, str, str, str, str], int] = {}
    n = 0

    try:
        # Use Popen to stream output line by line
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=65536)
        try:
            for line in proc.stdout:
                if phase and phase.should_skip():
                    break

                n += 1
                if limit_packets and n > limit_packets:
                    break

                if phase and (n % progress_every == 0):
                    if total_packets:
                        frac = min(n / total_packets, 1.0)
                        phase.set(int(frac * 100), f"Parsing {n:,}/{total_packets:,} packets…")
                    else:
                        phase.set(0, f"Parsing {n:,} packets…")

                parts = line.strip().split("\t")
                if len(parts) < len(C.TSHARK_FIELDS):
                    continue

                # Unpack fields (tshark returns empty string for missing fields)
                # Note: tshark might return multiple values comma-separated if multiple layers match.
                # We take the first one usually.
                ts_str = parts[0]
                ip_src = parts[1]
                ip_dst = parts[2]
                ipv6_src = parts[3]
                ipv6_dst = parts[4]
                tcp_sport = parts[5]
                tcp_dport = parts[6]
                udp_sport = parts[7]
                udp_dport = parts[8]
                protos = parts[9]
                eth_src = parts[10] if len(parts) > 10 else None
                eth_dst = parts[11] if len(parts) > 11 else None
                pkt_len = int(parts[12]) if len(parts) > 12 and parts[12] else 0

                ts = float(ts_str) if ts_str else 0.0

                # Determine src/dst/proto
                src = ip_src or ipv6_src
                dst = ip_dst or ipv6_dst

                # Handle comma-separated values (e.g. tunneled traffic) - take first
                if "," in src:
                    src = src.split(",")[0]
                if "," in dst:
                    dst = dst.split(",")[0]

                if not src or not dst:
                    continue

                # Ports
                sport = tcp_sport or udp_sport
                dport = tcp_dport or udp_dport
                if "," in sport:
                    sport = sport.split(",")[0]
                if "," in dport:
                    dport = dport.split(",")[0]

                # Protocol (highest layer)
                # frame.protocols is like "eth:ethertype:ip:tcp:http"
                # We want the last interesting one.
                proto_list = protos.split(":")
                proto = proto_list[-1] if proto_list else "unknown"

                key = (src, dst, str(sport), str(dport), proto)
                idx = flow_index.get(key, -1)

                if idx < 0:
                    flow = {
                        "src": src,
                        "dst": dst,
                        "sport": str(sport),
                        "dport": str(dport),
                        "proto": proto,
                        "count": 0,
                        # True totals tracked as scalars — these stay correct
                        # beyond the MAX_FLOW_SAMPLES cap on the lists below.
                        "bytes": 0,
                        "first_ts": ts,
                        "last_ts": ts,
                        "pkt_times": [],
                        "pkt_lens": [],
                        "mac_src": eth_src,
                        "mac_dst": eth_dst,
                    }
                    out["flows"].append(flow)
                    idx = len(out["flows"]) - 1
                    flow_index[key] = idx

                flow = out["flows"][idx]
                flow["count"] += 1
                flow["bytes"] += pkt_len
                flow["last_ts"] = ts
                if len(flow["pkt_times"]) < C.MAX_FLOW_SAMPLES:
                    flow["pkt_times"].append(ts)
                    flow["pkt_lens"].append(pkt_len)

                out["artifacts"]["ips"].add(src)
                out["artifacts"]["ips"].add(dst)
                if eth_src:
                    out["artifacts"]["macs"].add(eth_src)
                if eth_dst:
                    out["artifacts"]["macs"].add(eth_dst)

            # Check for errors after loop
            if proc.poll() is not None and proc.returncode != 0:
                # If we terminated early, returncode might be non-zero (SIGTERM)
                # But if we didn't terminate and it failed:
                if not (limit_packets and n >= limit_packets) and not (phase and phase.should_skip()):
                    stderr = proc.stderr.read()
                    if stderr:
                        log_runtime_error(f"Tshark failed: {stderr}")

        finally:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()

    except Exception as e:
        log_runtime_error(f"Tshark parsing loop failed: {e}")

    if phase:
        phase.done("Tshark parsing complete." if not phase.should_skip() else "Parsing skipped.")

    out["artifacts"] = {k: uniq_sorted(v) for k, v in out["artifacts"].items()}
    return out
