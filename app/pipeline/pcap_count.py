from __future__ import annotations

import subprocess

from app import config as C
from app.utils.common import find_bin
from app.utils.logger import log_runtime_error


def count_packets_fast(pcap_path: str) -> int | None:
    # Try capinfos first (fastest)
    capinfos = find_bin("capinfos")
    if capinfos:
        try:
            # -T: Table output, -r: Headerless, -c: Count
            proc = subprocess.run(
                [capinfos, "-T", "-r", "-c", pcap_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=C.PCAP_COUNT_TIMEOUT_SECONDS,
            )
            val = proc.stdout.strip()
            if val.isdigit():
                return int(val)
        except subprocess.CalledProcessError as e:
            log_runtime_error(f"Capinfos failed: {e.stderr}")
        except Exception as e:
            log_runtime_error(f"Unexpected error during capinfos count: {e}")

    # Fallback to tshark
    tshark = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if tshark:
        try:
            # tshark -r file -T fields -e frame.number | wc -l
            # We'll just count lines in python to avoid shell pipe issues
            proc = subprocess.run(
                [tshark, "-r", pcap_path, "-T", "fields", "-e", "frame.number"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=C.PCAP_COUNT_TIMEOUT_SECONDS,
            )
            return len(proc.stdout.splitlines())
        except subprocess.CalledProcessError as e:
            log_runtime_error(f"Tshark count failed: {e.stderr}")
        except Exception as e:
            log_runtime_error(f"Unexpected error during tshark count: {e}")

    return None
