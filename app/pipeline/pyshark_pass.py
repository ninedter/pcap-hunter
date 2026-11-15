from __future__ import annotations

import os
import subprocess
import threading
from typing import Any

from app import config as C
from app.pipeline.progress import PhaseHandle
from app.utils.common import find_bin, uniq_sorted
from app.utils.logger import log_runtime_error

_ARTIFACT_KEYS = ("ips", "domains", "urls", "hashes", "ja3", "macs")

# How much of tshark's stderr is kept for the failure log line.
_STDERR_TAIL_CHARS = 2000


def _new_parse_stats(limit: int | None) -> dict[str, Any]:
    """Fresh per-run parse diagnostics (returned under ``features["parse_stats"]``)."""
    return {
        "lines_read": 0,  # tshark output lines consumed
        "skipped_lines": 0,  # malformed lines dropped (bad number / too few fields)
        "packet_limit": limit,  # effective cap; None = unlimited
        "limit_reached": False,  # parsing stopped because the cap was hit
        "timed_out": False,  # PYSHARK_TIMEOUT_SECONDS watchdog fired
        "error": None,  # short reason when tshark could not run / exited non-zero
    }


def _empty_features(limit: int | None = None, error: str | None = None) -> dict[str, Any]:
    """The result shape every return path shares (artifact values are sorted lists)."""
    stats = _new_parse_stats(limit)
    stats["error"] = error
    return {
        "flows": [],
        "artifacts": {key: [] for key in _ARTIFACT_KEYS},
        "parse_stats": stats,
    }


def _first(value: str) -> str:
    """tshark joins multiple occurrences of a field with commas — keep the first."""
    return value.split(",", 1)[0] if "," in value else value


def parse_pcap_pyshark(
    pcap_path: str,
    limit_packets: int | None,
    phase: PhaseHandle | None,
    total_packets: int | None,
    progress_every: int = 2000,
) -> dict[str, Any]:
    """Stream a tshark field pass over the capture and aggregate packets into flows.

    Args:
        pcap_path: Capture file to parse.
        limit_packets: Hard cap on parsed packets. ``None`` or a value <= 0 means
            no limit at this layer (the runner resolves its own ``None`` to
            ``C.DEFAULT_PYSHARK_LIMIT`` before calling).
        phase: Optional progress handle.
        total_packets: Packet count from the pre-count stage, for percentages.
        progress_every: Emit progress every N lines.

    Returns:
        ``{"flows": [...], "artifacts": {ips, domains, urls, hashes, ja3, macs},
        "parse_stats": {...}}``. Every return path has this shape, with artifact
        values as sorted lists. ``parse_stats`` reports skipped malformed lines, a
        watchdog timeout, or a tshark failure so partial results are never silent.
    """
    # Input validation
    if not os.path.exists(pcap_path):
        log_runtime_error(f"PCAP file not found: {pcap_path}")
        return _empty_features(error="pcap_not_found")

    if limit_packets is not None and (isinstance(limit_packets, bool) or not isinstance(limit_packets, int)):
        log_runtime_error(f"Invalid limit_packets value: {limit_packets}")
        limit_packets = None
    if limit_packets is not None and limit_packets <= 0:
        limit_packets = None  # explicit "no limit"

    tshark_path = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark_path:
        log_runtime_error("Tshark binary not found. Analysis may fail.")
        return _empty_features(limit=limit_packets, error="tshark_not_found")

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

    flows: list[dict[str, Any]] = []
    artifacts: dict[str, set] = {key: set() for key in _ARTIFACT_KEYS}
    stats = _new_parse_stats(limit_packets)
    flow_index: dict[tuple[str, str, str, str, str], int] = {}
    min_fields = len(C.TSHARK_FIELDS)
    n = 0
    skipped = 0
    stopped_early = False  # we stopped reading on purpose (limit / user skip)

    try:
        # Use Popen to stream output line by line
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=65536)
    except Exception as e:
        log_runtime_error(f"Tshark parsing loop failed: {e}")
        stats["error"] = f"tshark exec failed: {e}"[:300]
        if phase:
            phase.done("Tshark parsing failed.")
        return {"flows": [], "artifacts": {key: [] for key in _ARTIFACT_KEYS}, "parse_stats": stats}

    # Wall-clock watchdog — same pattern as carve.py / tls_certs.py. Read at call
    # time (not import time) so config/monkeypatch changes apply.
    timeout_s = C.PYSHARK_TIMEOUT_SECONDS
    timed_out = threading.Event()

    def _kill() -> None:
        timed_out.set()
        proc.kill()

    watchdog = threading.Timer(timeout_s, _kill)
    watchdog.daemon = True
    watchdog.start()

    # Drain stderr on a daemon thread so a chatty tshark can't fill the OS pipe
    # buffer and stall the stdout loop; the collected text feeds the rc!=0 log line.
    stderr_lines: list[str] = []

    def _drain_stderr() -> None:
        try:
            for err_line in proc.stderr:
                stderr_lines.append(err_line)
                if len(stderr_lines) > 200:  # keep the tail only
                    del stderr_lines[:100]
        except (OSError, ValueError):  # pragma: no cover - pipe closed during kill
            pass

    stderr_thread: threading.Thread | None = None
    if proc.stderr is not None:
        stderr_thread = threading.Thread(target=_drain_stderr, name="pyshark-stderr-drain", daemon=True)
        stderr_thread.start()

    try:
        for line in proc.stdout:
            if phase and phase.should_skip():
                stopped_early = True
                break

            n += 1
            if limit_packets and n > limit_packets:
                n -= 1
                stopped_early = True
                break

            if phase and (n % progress_every == 0):
                if total_packets:
                    frac = min(n / total_packets, 1.0)
                    phase.set(int(frac * 100), f"Parsing {n:,}/{total_packets:,} packets…")
                else:
                    phase.set(0, f"Parsing {n:,} packets…")

            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split("\t")
            if len(parts) < min_fields:
                skipped += 1
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

            # One malformed number must cost one packet, not the rest of the capture.
            try:
                pkt_len = int(_first(parts[12])) if len(parts) > 12 and parts[12] else 0
                ts = float(_first(ts_str)) if ts_str else 0.0
            except ValueError:
                skipped += 1
                continue

            # Determine src/dst/proto
            src = ip_src or ipv6_src
            dst = ip_dst or ipv6_dst

            # Handle comma-separated values (e.g. tunneled traffic) - take first
            src = _first(src)
            dst = _first(dst)

            if not src or not dst:
                continue

            # Ports
            sport = _first(tcp_sport or udp_sport)
            dport = _first(tcp_dport or udp_dport)

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
                flows.append(flow)
                idx = len(flows) - 1
                flow_index[key] = idx

            flow = flows[idx]
            flow["count"] += 1
            flow["bytes"] += pkt_len
            flow["last_ts"] = ts
            if len(flow["pkt_times"]) < C.MAX_FLOW_SAMPLES:
                flow["pkt_times"].append(ts)
                flow["pkt_lens"].append(pkt_len)

            artifacts["ips"].add(src)
            artifacts["ips"].add(dst)
            if eth_src:
                artifacts["macs"].add(eth_src)
            if eth_dst:
                artifacts["macs"].add(eth_dst)

        if not stopped_early:
            # Watchdog is still armed here, so a child that closed stdout but
            # refuses to exit is killed rather than hanging the pool thread.
            proc.wait()
    except Exception as e:
        # Unexpected failure mid-stream: keep what was parsed, but say so.
        log_runtime_error(f"Tshark parsing loop failed: {e}")
        stats["error"] = f"parse loop failed: {e}"[:300]
        stopped_early = True
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except Exception:  # pragma: no cover - unkillable child
                pass

    # The process is dead here (waited or killed), so stderr has hit EOF and the
    # drain thread is finishing; the timeout is a guard against pathological pipes.
    if stderr_thread is not None:
        stderr_thread.join(timeout=5)

    stats["lines_read"] = n
    stats["skipped_lines"] = skipped
    stats["limit_reached"] = bool(limit_packets and n >= limit_packets)

    if timed_out.is_set():
        stats["timed_out"] = True
        stats["error"] = f"tshark timed out after {timeout_s}s"
        log_runtime_error(f"Tshark packet parse timed out after {timeout_s}s; keeping {n:,} packets parsed so far.")
    elif not stopped_early and proc.returncode not in (0, None):
        # We neither killed it nor stopped reading, so this is tshark's own failure
        # (commonly rc=2 for a capture that was cut short — output is still usable).
        stderr_text = "".join(stderr_lines).strip()[-_STDERR_TAIL_CHARS:]
        stats["error"] = f"tshark exited with code {proc.returncode}"
        log_runtime_error(f"Tshark failed (rc={proc.returncode}): {stderr_text or 'no stderr output'}")

    if skipped:
        log_runtime_error(f"Tshark parse skipped {skipped:,} malformed line(s) out of {n:,}.")

    if phase:
        if phase.should_skip():
            phase.done("Parsing skipped.")
        elif stats["timed_out"]:
            phase.done("Tshark parsing timed out (partial results).")
        else:
            phase.done("Tshark parsing complete.")

    return {
        "flows": flows,
        "artifacts": {k: uniq_sorted(v) for k, v in artifacts.items()},
        "parse_stats": stats,
    }
