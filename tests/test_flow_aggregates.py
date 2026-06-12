"""compute_flow_aggregates: one-pass top-N aggregation for the dashboard."""

from __future__ import annotations

from app.analysis.flow_aggregates import compute_flow_aggregates


def _flows():
    return [
        {"src": "10.0.0.1", "dst": "8.8.8.8", "sport": "5000", "dport": "53", "proto": "dns", "count": 10},
        {"src": "10.0.0.1", "dst": "1.1.1.1", "sport": "5001", "dport": "53", "proto": "dns", "count": 5},
        {"src": "10.0.0.2", "dst": "8.8.8.8", "sport": "5002", "dport": "443", "proto": "tls", "count": 20},
    ]


class TestComputeFlowAggregates:
    def test_top_counts(self):
        agg = compute_flow_aggregates(_flows(), top_n=10)
        # 8.8.8.8 appears in flows with count=10 and count=20 → 30 total
        assert agg["top_dst_ips"][0] == ("8.8.8.8", 30)
        # 10.0.0.2 has count=20; 10.0.0.1 has 10+5=15 → 10.0.0.2 ranks first
        assert agg["top_src_ips"][0] == ("10.0.0.2", 20)
        assert agg["top_src_ips"][1] == ("10.0.0.1", 15)
        # port 53 appears in flows with count=10+5=15; 443 in count=20 → 443 first
        assert agg["top_dst_ports"][0] == ("443", 20)
        assert agg["top_dst_ports"][1] == ("53", 15)
        # tls has count=20; dns has 10+5=15 → tls first
        assert agg["top_protos"][0] == ("tls", 20)
        assert agg["top_protos"][1] == ("dns", 15)

    def test_empty_and_malformed(self):
        assert compute_flow_aggregates([], top_n=5)["top_src_ips"] == []
        agg = compute_flow_aggregates([{"src": None, "dst": "", "count": "x"}], top_n=5)
        assert isinstance(agg["top_src_ips"], list)
        assert compute_flow_aggregates(None, top_n=5)["top_protos"] == []

    def test_flow_weight_counts_one_per_flow(self):
        """weight='flows' must count 1 per flow row, not sum 'count'."""
        agg = compute_flow_aggregates(_flows(), top_n=10, weight="flows")
        # 10.0.0.1 appears in 2 flows; 10.0.0.2 in 1
        assert agg["top_src_ips"][0] == ("10.0.0.1", 2)
        # 8.8.8.8 appears in 2 flows (from both src ips); 1.1.1.1 in 1
        assert agg["top_dst_ips"][0] == ("8.8.8.8", 2)
        # dns appears in 2 flows; tls in 1
        assert agg["top_protos"][0] == ("dns", 2)

    def test_top_n_respected(self):
        """top_n should limit result length."""
        agg = compute_flow_aggregates(_flows(), top_n=1)
        assert len(agg["top_dst_ips"]) == 1
        assert len(agg["top_src_ips"]) == 1

    def test_exclude_private(self):
        """exclude_private should filter RFC-1918 addresses."""
        flows = [
            {"src": "192.168.1.1", "dst": "8.8.8.8", "dport": "53", "proto": "dns", "count": 5},
            {"src": "10.0.0.1", "dst": "8.8.8.8", "dport": "53", "proto": "dns", "count": 3},
        ]
        agg = compute_flow_aggregates(flows, top_n=10, exclude_private=True)
        src_keys = [k for k, _ in agg["top_src_ips"]]
        assert "192.168.1.1" not in src_keys
        assert "10.0.0.1" not in src_keys
        dst_keys = [k for k, _ in agg["top_dst_ips"]]
        assert "8.8.8.8" in dst_keys

    def test_legacy_sentinel_buckets(self):
        """Missing dport/proto keys count under N/A/Unknown; empty strings are skipped.

        Mirrors the legacy dashboard loop exactly: ``str(f.get("dport", "N/A"))``
        and ``f.get("proto", "Unknown")`` followed by truthiness checks.
        """
        flows = [
            {"src": "1.2.3.4", "dst": "5.6.7.8", "count": 1},  # no dport/proto keys
            {"src": "1.2.3.4", "dst": "5.6.7.8", "dport": "", "proto": "", "count": 1},  # empty values
        ]
        agg = compute_flow_aggregates(flows, top_n=10, weight="flows")
        assert ("N/A", 1) in agg["top_dst_ports"]
        assert ("Unknown", 1) in agg["top_protos"]
        # empty-string values are skipped, not bucketed
        port_keys = [k for k, _ in agg["top_dst_ports"]]
        proto_keys = [k for k, _ in agg["top_protos"]]
        assert "" not in port_keys
        assert "" not in proto_keys
