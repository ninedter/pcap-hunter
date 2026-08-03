from app.ui.charts import (
    MAX_TIMELINE_FLOW_POINTS,
    MAX_TIMELINE_VOLUME_POINTS,
    plot_flow_timeline,
    plot_protocol_distribution,
    plot_world_map,
)


def test_plot_world_map_empty():
    fig = plot_world_map([], [])
    assert fig.layout.title.text == "Global Traffic Origins & Connectivity"
    assert len(fig.data) == 0


def test_plot_world_map_markers():
    ip_data = [
        {"ip": "1.1.1.1", "country": "US", "city": "TestCity", "lat": 10.0, "lon": 20.0},
        {"ip": "2.2.2.2", "country": "US", "city": "TestCity", "lat": 10.0, "lon": 20.0},
    ]
    fig = plot_world_map(ip_data, [])

    # Should have 1 trace for markers
    assert len(fig.data) == 1
    trace = fig.data[0]
    assert trace.type == "scattergeo"
    assert trace.mode is None  # defaults
    # Check customdata
    assert "1.1.1.1" in trace.customdata[0]
    assert "2.2.2.2" in trace.customdata[0]
    # Check aggregation (2 IPs in same city = count 2)
    assert "2)" in trace.text[0]


def test_plot_world_map_lines_variable_width():
    ip_data = [
        {"ip": "1.1.1.1", "lat": 0, "lon": 0, "city": "A", "country": "A"},
        {"ip": "2.2.2.2", "lat": 10, "lon": 10, "city": "B", "country": "B"},
        {"ip": "3.3.3.3", "lat": 20, "lon": 20, "city": "C", "country": "C"},
    ]
    # Create flows with different counts to trigger variable widths
    flows = [
        {"src": "1.1.1.1", "dst": "2.2.2.2", "count": 10},  # Low
        {"src": "2.2.2.2", "dst": "3.3.3.3", "count": 1000},  # High
    ]

    fig = plot_world_map(ip_data, flows)

    # 1 marker trace + at least 2 line traces (different widths)
    # Note: The exact binning depends on the max count.
    # Max = 1000.
    # T1 = 330, T2 = 660.
    # 10 is < 330 -> Low (width 1)
    # 1000 is > 660 -> High (width 5)
    # So we expect 2 line traces.

    assert len(fig.data) >= 3  # 1 marker + 2 lines

    widths = set()
    for trace in fig.data:
        if trace.mode == "lines":
            widths.add(trace.line.width)

    assert 1.5 in widths
    assert 6.0 in widths


def test_plot_protocol_distribution():
    counts = {"TCP": 10, "UDP": 5}
    fig = plot_protocol_distribution(counts)
    assert len(fig.data) == 1
    assert fig.data[0].type == "pie"
    assert list(fig.data[0].values) == [10, 5]


def test_plot_flow_timeline():
    flows = [
        {"pkt_times": [100, 105], "proto": "TCP", "count": 5, "src": "1.1.1.1", "dst": "2.2.2.2"},
        {"pkt_times": [110, 110], "proto": "UDP", "count": 1, "src": "3.3.3.3", "dst": "4.4.4.4"},
    ]
    fig = plot_flow_timeline(flows)
    # Now includes an aggregate 'Volume' trace (area chart)
    # Total traces: 1 (Volume) + 2 (Protocols: TCP, UDP) = 3
    assert len(fig.data) == 3

    # Check total points across all traces
    # TCP trace has 1 point, UDP has 1 point.
    # Volume trace covers the time range, typically 1 or more points depending on sampling.
    scatter_points = sum(len(trace.x) for trace in fig.data if trace.mode == "markers")
    assert scatter_points == 2


def test_plot_flow_timeline_uses_true_extent_beyond_sample_cap():
    # Sampled pkt_times stop at t=105 (per-flow cap, keep-first), but the flow
    # truly ran until t=400 — duration must come from first_ts/last_ts (300s),
    # not max(pkt_times) - min(pkt_times) (5s).
    flows = [
        {
            "pkt_times": [100.0, 105.0],
            "first_ts": 100.0,
            "last_ts": 400.0,
            "proto": "TCP",
            "count": 500,
            "src": "1.1.1.1",
            "dst": "2.2.2.2",
        },
    ]
    fig = plot_flow_timeline(flows)
    marker_traces = [t for t in fig.data if t.mode == "markers"]
    assert len(marker_traces) == 1
    assert marker_traces[0].y[0] == 300.0


def test_plot_flow_timeline_falls_back_to_pkt_times_extent():
    # Legacy flows without first_ts/last_ts keep the old min/max(pkt_times) path.
    flows = [
        {"pkt_times": [100.0, 105.0], "proto": "TCP", "count": 5, "src": "1.1.1.1", "dst": "2.2.2.2"},
    ]
    fig = plot_flow_timeline(flows)
    marker_traces = [t for t in fig.data if t.mode == "markers"]
    assert len(marker_traces) == 1
    assert marker_traces[0].y[0] == 5.0


def test_plot_flow_timeline_bounds_large_capture_payload():
    flows = [
        {
            "pkt_times": [float(i), float(i + 1)],
            "first_ts": float(i),
            "last_ts": float(i + 1),
            "proto": "TCP" if i % 2 else "UDP",
            "count": i % 20 + 1,
            "src": f"10.0.{i // 256}.{i % 256}",
            "dst": "203.0.113.10",
        }
        for i in range(MAX_TIMELINE_FLOW_POINTS * 2)
    ]

    fig = plot_flow_timeline(flows)

    flow_points = sum(len(trace.x) for trace in fig.data if trace.mode == "markers")
    volume_trace = next(trace for trace in fig.data if trace.name == "Volume")
    assert flow_points <= MAX_TIMELINE_FLOW_POINTS
    assert len(volume_trace.x) <= MAX_TIMELINE_VOLUME_POINTS
