"""One-pass flow aggregation for dashboard top-N panels.

Computed once after the pipeline finishes and cached in session state so the
dashboard doesn't re-scan every flow on each Streamlit rerun.

Two weighting modes are supported so callers can match their existing semantics:

* ``weight="packets"`` (default) — sums the ``count`` field on each flow dict.
  Useful when you want to rank by traffic volume.
* ``weight="flows"`` — adds 1 per flow row regardless of packet count.
  Matches the legacy dashboard loop that incremented a counter once per flow.
"""

from __future__ import annotations

from collections import Counter
from typing import Literal

from app.utils.common import is_public_ipv4


def compute_flow_aggregates(
    flows: list[dict] | None,
    top_n: int = 10,
    weight: Literal["packets", "flows"] = "packets",
    exclude_private: bool = False,
) -> dict:
    """Return top-N counters for src/dst IPs, dst ports, and protocols.

    Args:
        flows: Flow dicts as produced by parse_pcap_pyshark
            (src/dst/dport/proto/count fields used).
        top_n: Number of entries per ranking.
        weight: ``"packets"`` sums the ``count`` field; ``"flows"`` adds 1 per
            row.  Use ``"flows"`` to reproduce the legacy dashboard behaviour
            where every flow contributes equally regardless of packet volume.
        exclude_private: When True, RFC-1918 / loopback addresses are omitted
            from the src and dst IP rankings (matches the dashboard's
            *Exclude private IPs* toggle).

    Returns:
        Dict with keys ``top_src_ips``, ``top_dst_ips``, ``top_dst_ports``,
        ``top_protos`` — each a ``list[(value, int)]`` sorted descending.
    """
    src: Counter = Counter()
    dst: Counter = Counter()
    ports: Counter = Counter()
    protos: Counter = Counter()

    for f in flows or []:
        if weight == "packets":
            try:
                n = int(f.get("count") or 0)
            except (TypeError, ValueError):
                n = 0
        else:
            n = 1

        s = f.get("src")
        d = f.get("dst")
        dport = f.get("dport")
        proto = f.get("proto")

        if s:
            if not exclude_private or is_public_ipv4(str(s)):
                src[str(s)] += n
        if d:
            if not exclude_private or is_public_ipv4(str(d)):
                dst[str(d)] += n
        if dport:
            ports[str(dport)] += n
        if proto:
            protos[str(proto)] += n

    return {
        "top_src_ips": src.most_common(top_n),
        "top_dst_ips": dst.most_common(top_n),
        "top_dst_ports": ports.most_common(top_n),
        "top_protos": protos.most_common(top_n),
    }
