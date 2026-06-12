"""Smoke tests: every chart used in the PDF must render to PNG via kaleido.

These tests catch two failure modes that the unit tests miss:
  1. API drift — the chart function's signature changes and the PDF's
     call site no longer matches (e.g. plot_network_graph expecting
     flows, plot_top_n_charts expecting a flat dict).
  2. Runtime render failure — the figure is valid Plotly but kaleido
     can't serialise it (colorscale incompatibility, unicode issue, etc.).

We pass production-shape inputs through each chart and verify a non-empty
PNG comes back. If the user reports "my PDF has no charts", one of these
tests should point to the culprit.
"""

from __future__ import annotations

import pytest

from app.reports.chart_images import charts_available, figure_to_data_uri
from app.ui.charts import (
    plot_attack_timeline,
    plot_flow_timeline,
    plot_network_graph,
    plot_protocol_distribution,
    plot_top_n_charts,
    plot_world_map,
)

# Skip the whole module if kaleido is missing — no charts = no PDF charts.
pytest.importorskip("kaleido")


def _assert_renders(fig, label: str) -> None:
    """Render *fig* to PNG and assert we got non-empty bytes."""
    uri = figure_to_data_uri(fig, width=800, height=400)
    assert uri is not None, f"{label} returned None from figure_to_data_uri"
    assert uri.startswith("data:image/png;base64,"), f"{label} URI has wrong prefix"
    # The base64 payload should be non-trivially sized (>1KB for any real chart)
    payload = uri.split(",", 1)[1]
    assert len(payload) > 1000, f"{label} payload suspiciously small ({len(payload)} chars)"


@pytest.mark.skipif(not charts_available(), reason="kaleido not available")
class TestChartRendering:
    """Each chart function used in the PDF is exercised here."""

    def test_protocol_distribution_renders(self):
        fig = plot_protocol_distribution({"TCP": 966, "UDP": 237, "TLS": 678, "QUIC": 138})
        _assert_renders(fig, "protocol distribution")

    def test_protocol_distribution_single_proto(self):
        """Single-protocol capture should still produce a valid chart."""
        fig = plot_protocol_distribution({"TCP": 100})
        _assert_renders(fig, "single-proto distribution")

    def test_top_n_flat_dict(self):
        """plot_top_n_charts takes a flat dict[str, int] — this is the shape
        the PDF passes. Regression guard for the ``'<' not supported between
        dict and dict`` crash we hit in production."""
        fig = plot_top_n_charts(
            {"8.8.8.8": 245, "1.1.1.1": 40, "34.12.37.224": 1200},
            "Top Destination IPs",
        )
        _assert_renders(fig, "top-N chart")

    def test_top_n_count_label_matches_call_site_semantics(self):
        """The count axis must say what the values count: the dashboard passes
        flow counts (default "Flows"), the PDF passes packet sums ("Packets")."""
        default_fig = plot_top_n_charts({"8.8.8.8": 245}, "Top Destination IPs")
        assert default_fig.layout.xaxis.title.text == "Flows"
        pdf_fig = plot_top_n_charts({"8.8.8.8": 245}, "Top Destination IPs", count_label="Packets")
        assert pdf_fig.layout.xaxis.title.text == "Packets"
        _assert_renders(pdf_fig, "top-N chart with packet label")

    def test_flow_timeline(self):
        flows = [
            {"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "TCP", "count": 10, "ts": 1_700_000_000},
            {"src": "10.0.0.1", "dst": "8.8.8.8", "proto": "TCP", "count": 5, "ts": 1_700_000_060},
            {"src": "10.0.0.1", "dst": "1.1.1.1", "proto": "UDP", "count": 2, "ts": 1_700_000_120},
        ]
        fig = plot_flow_timeline(flows)
        _assert_renders(fig, "flow timeline")

    def test_network_graph_takes_flows_positionally(self):
        """Regression guard: plot_network_graph takes ``flows`` as its first
        positional arg, not ``ip_data``. Passing the wrong shape used to
        silently produce an empty chart in the PDF."""
        flows = [
            {"src": "10.0.0.1", "dst": "8.8.8.8", "count": 10},
            {"src": "10.0.0.1", "dst": "34.12.37.224", "count": 200},
            {"src": "10.0.0.2", "dst": "8.8.8.8", "count": 50},
        ]
        fig = plot_network_graph(flows)
        _assert_renders(fig, "network graph")

    def test_world_map(self):
        geo = [
            {"ip": "8.8.8.8", "country": "United States", "city": "Mountain View", "lat": 37.386, "lon": -122.083},
            {"ip": "1.1.1.1", "country": "Australia", "city": "Sydney", "lat": -33.494, "lon": 143.210},
        ]
        fig = plot_world_map(geo)
        _assert_renders(fig, "world map")

    def test_attack_timeline(self):
        events = [
            {
                "timestamp": "2026-04-20T10:00:00",
                "event_type": "c2_beacon",
                "description": "Beacon to 34.12.37.224",
                "severity": "critical",
            },
            {
                "timestamp": "2026-04-20T10:01:00",
                "event_type": "dga_detection",
                "description": "DGA domain observed",
                "severity": "high",
            },
        ]
        fig = plot_attack_timeline(events)
        _assert_renders(fig, "attack timeline")
