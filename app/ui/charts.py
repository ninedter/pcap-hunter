from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def plot_world_map(
    ip_data: list[dict[str, Any]],
    flows: list[dict[str, Any]] = None,
    home_loc: tuple[float, float] = (0.0, 0.0),
    threat_scores: dict[str, float] | None = None,
) -> go.Figure:
    """
    Plots a world map with markers for IP locations and connectivity lines.
    ip_data: list of dicts with keys: ip, country, city, lat, lon
    flows: list of dicts with keys: src, dst, count (optional, for drawing lines)
    home_loc: (lat, lon) to use for private IPs that don't have geo data.
    """
    if not ip_data and not flows:
        return go.Figure()

    threat_scores = threat_scores or {}

    # Create a lookup for lat/lon by IP
    loc_map = {d["ip"]: (d["lat"], d["lon"]) for d in ip_data}

    df = pd.DataFrame(ip_data) if ip_data else pd.DataFrame()
    if not df.empty and "count" not in df.columns:
        df["count"] = 1

    fig = go.Figure()

    # 1. Markers with threat-level coloring
    if not df.empty:
        # Add threat score to each IP for coloring
        df["threat"] = df["ip"].map(lambda ip: threat_scores.get(ip, 0))

        def _threat_color(score):
            if score >= 0.7:
                return "red"
            elif score >= 0.4:
                return "orange"
            elif score >= 0.2:
                return "yellow"
            return "cyan"

        df["color"] = df["threat"].map(_threat_color)

        df_agg = (
            df.groupby(["lat", "lon", "city", "country"])
            .agg({"count": "sum", "ip": lambda x: list(x), "threat": "max", "color": "first"})
            .reset_index()
        )
        # Re-apply color based on max threat in cluster
        df_agg["color"] = df_agg["threat"].map(_threat_color)

        fig.add_trace(
            go.Scattergeo(
                lat=df_agg["lat"],
                lon=df_agg["lon"],
                text=df_agg["city"] + ", " + df_agg["country"] + " (" + df_agg["count"].astype(str) + ")",
                customdata=df_agg["ip"],
                marker=dict(
                    size=df_agg["count"] * 5,
                    sizemode="area",
                    sizemin=5,
                    color=df_agg["color"],
                    line=dict(width=1, color="#333"),
                ),
                name="Locations",
                hoverinfo="text",
            )
        )

    # 2. Connectivity Lines (Arcs)
    if flows:
        from app.utils.common import is_public_ipv4

        # Aggregate flows between src-dst pairs
        conn_counts = {}
        for f in flows:
            src, dst = f.get("src"), f.get("dst")
            count = f.get("count", 1)
            if src and dst and src != dst:
                # Resolve locations
                sloc = loc_map.get(src)
                if not sloc and not is_public_ipv4(src):
                    sloc = home_loc

                dloc = loc_map.get(dst)
                if not dloc and not is_public_ipv4(dst):
                    dloc = home_loc

                if sloc and dloc:
                    pair = tuple(sorted((src, dst)))
                    conn_counts[pair] = conn_counts.get(pair, 0) + count

                    # Update loc_map temporarily for the drawing loop
                    if src not in loc_map:
                        loc_map[src] = sloc
                    if dst not in loc_map:
                        loc_map[dst] = dloc

        if conn_counts:
            max_count = max(conn_counts.values())

            def get_lines_for_width(width_threshold_min, width_threshold_max, line_width, color):
                lats, lons = [], []
                for (src, dst), count in conn_counts.items():
                    if width_threshold_min <= count <= width_threshold_max:
                        slat, slon = loc_map[src]
                        dlat, dlon = loc_map[dst]
                        lats.extend([slat, dlat, None])
                        lons.extend([slon, dlon, None])
                if lats:
                    fig.add_trace(
                        go.Scattergeo(
                            lat=lats,
                            lon=lons,
                            mode="lines",
                            line=dict(width=line_width, color=color),
                            name=f"Traffic ({line_width}px)",
                            hoverinfo="skip",
                        )
                    )

            t1, t2 = max_count * 0.33, max_count * 0.66
            get_lines_for_width(0, t1, 1.5, "rgba(255, 100, 100, 0.4)")
            get_lines_for_width(t1 + 0.001, t2, 3.5, "rgba(255, 100, 100, 0.6)")
            get_lines_for_width(t2 + 0.001, float("inf"), 6.0, "rgba(255, 50, 50, 0.8)")

    fig.update_geos(
        showcountries=True,
        countrycolor="#444",
        showocean=True,
        oceancolor="#111",
        showland=True,
        landcolor="#222",
        bgcolor="#000",
        projection_type="equirectangular",
        lataxis_range=[-60, 90],
    )
    fig.update_layout(
        title="Global Traffic Origins & Connectivity",
        template="plotly_dark",
        margin={"r": 0, "t": 30, "l": 0, "b": 0},
        height=600,
        geo=dict(projection_scale=1.1, center=dict(lat=20, lon=0)),
        legend=dict(orientation="h", yanchor="bottom", y=0, xanchor="right", x=1),
    )
    return fig


def plot_protocol_distribution(protocol_counts: dict[str, int]) -> go.Figure:
    """
    Plots a donut chart of protocol distribution.
    """
    if not protocol_counts:
        return go.Figure()

    labels = list(protocol_counts.keys())
    values = list(protocol_counts.values())

    fig = px.pie(
        names=labels,
        values=values,
        hole=0.4,
        title="Protocol Distribution",
        template="plotly_dark",
        color_discrete_sequence=px.colors.qualitative.Pastel,
    )
    fig.update_traces(textposition="inside", textinfo="percent+label", customdata=labels)
    fig.update_layout(
        margin={"r": 0, "t": 30, "l": 0, "b": 0},
        height=400,
    )
    return fig


def plot_flow_timeline(flows: list[dict[str, Any]]) -> go.Figure:
    """
    Plots a dual-axis chart:
    - Primary Y (Scatter): Flow duration over time.
    - Secondary Y (Area): Aggregate traffic volume over time.
    Refined for a 'premium' look: subtle colors, better scaling, and less clutter.
    """
    if not flows:
        return go.Figure()

    data = []
    for f in flows:
        if not f.get("pkt_times"):
            continue
        start_ts = min(f["pkt_times"])
        duration = max(f["pkt_times"]) - start_ts
        proto = f.get("proto", "Unknown")
        size = f.get("count", 1)
        data.append(
            {
                "ts": pd.to_datetime(start_ts, unit="s"),
                "duration": duration,
                "proto": proto,
                "packets": size,
                "src": f.get("src"),
                "dst": f.get("dst"),
            }
        )

    if not data:
        return go.Figure()
    df = pd.DataFrame(data).sort_values("ts")

    # 1. Aggregate volume for area chart
    df_vol = df.resample("1s", on="ts").agg({"packets": "sum"}).fillna(0).reset_index()

    fig = go.Figure()

    # Trace 1: Volume (Area) on secondary Y - subtle professional color
    fig.add_trace(
        go.Scatter(
            x=df_vol["ts"],
            y=df_vol["packets"],
            fill="tozeroy",
            name="Volume",
            line=dict(color="rgba(100, 150, 255, 0.2)", width=1),
            fillcolor="rgba(100, 150, 255, 0.1)",
            yaxis="y2",
            hoverinfo="skip",  # Focus on flows
        )
    )

    # Trace 2: Flows (Scatter) on primary Y
    unique_protos = df["proto"].unique()
    colors = px.colors.qualitative.Pastel
    for i, p in enumerate(unique_protos):
        sub = df[df["proto"] == p]
        fig.add_trace(
            go.Scatter(
                x=sub["ts"],
                y=sub["duration"],
                mode="markers",
                name=p,
                # Refined marker scale: smaller bubbles
                marker=dict(
                    size=sub["packets"].apply(lambda x: min(2 + x * 0.5, 18)),
                    opacity=0.5,
                    color=colors[i % len(colors)],
                    line=dict(width=0.5, color="rgba(255,255,255,0.2)"),
                ),
                customdata=sub[["src", "dst", "packets"]],
                hovertemplate=(
                    "<b>%{name}</b><br>Time: %{x}<br>Duration: %{y}s<br>"
                    "Src: %{customdata[0]}<br>Dst: %{customdata[1]}<br>"
                    "Packets: %{customdata[2]}<extra></extra>"
                ),
            )
        )

    fig.update_layout(
        title="Analysis Timeline (Flows & Volume)",
        template="plotly_dark",
        height=500,
        xaxis_title=None,
        yaxis_title="Flow Duration (s)",
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", zerolinecolor="rgba(255,255,255,0.1)"),
        yaxis2=dict(
            title="Volume (pkts/sec)",
            overlaying="y",
            side="right",
            showgrid=False,
            rangemode="tozero",
            tickfont=dict(color="rgba(100, 150, 255, 0.6)"),
            title_font=dict(color="rgba(100, 150, 255, 0.6)"),
        ),
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.15,
            xanchor="center",
            x=0.5,
            font=dict(size=10),
            bgcolor="rgba(0,0,0,0)",
        ),
        hovermode="closest",
        margin=dict(l=50, r=50, t=80, b=40),
        xaxis=dict(
            gridcolor="rgba(255,255,255,0.05)",
            rangeslider=dict(visible=False),  # Removal of rangeslider for cleaner look
        ),
    )
    return fig


def plot_top_n_charts(data: dict[str, dict[str, int]], title: str) -> go.Figure:
    """
    Plots horizontal bar charts for TopN analysis.
    data: { "category": { "label": count, ... }, ... }
    Refined with 'premium' styling.
    """
    if not data:
        return go.Figure()

    labels = list(data.keys())
    values = list(data.values())

    # Sort for display
    sorted_items = sorted(zip(labels, values), key=lambda x: x[1], reverse=True)[:10]  # Top 10 focus
    if not sorted_items:
        return go.Figure()

    labels, values = zip(*sorted_items)

    fig = px.bar(
        x=values,
        y=labels,
        orientation="h",
        title=title,
        template="plotly_dark",
        labels={"x": "Frequency", "y": ""},  # Hide redundant 'Indicator' label
        color_discrete_sequence=["#4A90E2"],  # Professional blue
    )
    fig.update_layout(
        margin={"r": 20, "t": 40, "l": 20, "b": 20},
        height=350,
        yaxis={"categoryorder": "total ascending"},
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        title_font=dict(size=14, color="#DDD"),
    )
    fig.update_traces(
        marker_color="rgba(74, 144, 226, 0.7)", marker_line_color="rgba(74, 144, 226, 1)", marker_line_width=1
    )
    return fig


def plot_attack_timeline(timeline_events: list[dict[str, Any]]) -> go.Figure:
    """
    Plots an attack timeline scatter chart.
    X-axis: timestamp, Y-axis: severity level.
    Color-coded markers by event type.
    """
    if not timeline_events:
        return go.Figure()

    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    color_map = {
        "c2_beacon": "#FF4444",
        "dga_detection": "#FF8C00",
        "dns_tunneling": "#FF6600",
        "yara_match": "#9B59B6",
        "tls_anomaly": "#F1C40F",
        "connection": "#3498DB",
        "file_download": "#2ECC71",
        "alert": "#E74C3C",
    }

    data = []
    for evt in timeline_events:
        ts = evt.get("timestamp", "")
        severity = evt.get("severity", "info")
        event_type = evt.get("event_type", "alert")
        data.append(
            {
                "timestamp": str(ts),
                "severity_num": severity_map.get(severity, 0),
                "severity": severity.upper(),
                "event_type": event_type,
                "description": evt.get("description", ""),
                "source_ip": evt.get("source_ip", ""),
                "dest_ip": evt.get("dest_ip", ""),
                "color": color_map.get(event_type, "#95A5A6"),
            }
        )

    df = pd.DataFrame(data)

    fig = go.Figure()

    for etype in df["event_type"].unique():
        sub = df[df["event_type"] == etype]
        fig.add_trace(
            go.Scatter(
                x=sub["timestamp"],
                y=sub["severity_num"],
                mode="markers",
                name=etype.replace("_", " ").title(),
                marker=dict(
                    size=12,
                    color=sub["color"].iloc[0],
                    line=dict(width=1, color="rgba(255,255,255,0.3)"),
                    symbol="diamond",
                ),
                customdata=sub[["description", "source_ip", "dest_ip"]],
                hovertemplate=(
                    "<b>%{name}</b><br>"
                    "Time: %{x}<br>"
                    "Severity: %{text}<br>"
                    "%{customdata[0]}<br>"
                    "Src: %{customdata[1]}<br>"
                    "Dst: %{customdata[2]}"
                    "<extra></extra>"
                ),
                text=sub["severity"],
            )
        )

    fig.update_layout(
        title="Attack Timeline",
        template="plotly_dark",
        height=400,
        xaxis_title="Time",
        yaxis=dict(
            title="Severity",
            tickvals=[0, 1, 2, 3, 4],
            ticktext=["Info", "Low", "Medium", "High", "Critical"],
            gridcolor="rgba(255,255,255,0.05)",
        ),
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(size=10),
        ),
        hovermode="closest",
        margin=dict(l=60, r=20, t=50, b=40),
    )
    return fig


def plot_network_graph(
    flows: list[dict[str, Any]],
    threat_scores: dict[str, float] | None = None,
    max_nodes: int = 50,
) -> go.Figure:
    """
    Plots a network communication graph showing IP connectivity.
    Node size = total connections, color = threat score.
    Edge width = packet count between pair.
    """
    if not flows:
        return go.Figure()

    threat_scores = threat_scores or {}

    # Aggregate connections
    edge_counts: dict[tuple, int] = defaultdict(int)
    node_conns: dict[str, int] = defaultdict(int)

    for f in flows:
        src, dst = f.get("src", ""), f.get("dst", "")
        count = f.get("count", 1)
        if src and dst and src != dst:
            pair = tuple(sorted((src, dst)))
            edge_counts[pair] += count
            node_conns[src] += count
            node_conns[dst] += count

    if not edge_counts:
        return go.Figure()

    # Limit to top N most connected nodes
    top_nodes = sorted(node_conns.items(), key=lambda x: -x[1])[:max_nodes]
    node_set = {n for n, _ in top_nodes}

    # Filter edges to only include top nodes
    filtered_edges = {k: v for k, v in edge_counts.items() if k[0] in node_set and k[1] in node_set}

    if not filtered_edges:
        return go.Figure()

    # Simple circular layout
    nodes = list(node_set)
    n = len(nodes)
    pos = {}
    for i, node in enumerate(nodes):
        angle = 2 * math.pi * i / n
        pos[node] = (math.cos(angle), math.sin(angle))

    fig = go.Figure()

    # Draw edges
    max_edge = max(filtered_edges.values()) if filtered_edges else 1
    for (src, dst), count in filtered_edges.items():
        width = 0.5 + (count / max_edge) * 3
        opacity = 0.2 + (count / max_edge) * 0.4
        fig.add_trace(
            go.Scatter(
                x=[pos[src][0], pos[dst][0]],
                y=[pos[src][1], pos[dst][1]],
                mode="lines",
                line=dict(width=width, color=f"rgba(150,150,255,{opacity})"),
                hoverinfo="skip",
                showlegend=False,
            )
        )

    # Draw nodes
    node_x = [pos[n][0] for n in nodes]
    node_y = [pos[n][1] for n in nodes]
    node_sizes = [min(8 + (node_conns[n] / max(node_conns.values())) * 25, 35) for n in nodes]
    node_colors = []
    for n in nodes:
        score = threat_scores.get(n, 0)
        if score >= 0.7:
            node_colors.append("#FF4444")
        elif score >= 0.4:
            node_colors.append("#FFA500")
        elif score >= 0.2:
            node_colors.append("#FFD700")
        else:
            node_colors.append("#4A90E2")

    node_text = [
        f"{n}<br>Connections: {node_conns[n]}" + (f"<br>Threat: {threat_scores[n]:.0%}" if n in threat_scores else "")
        for n in nodes
    ]

    fig.add_trace(
        go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=1, color="rgba(255,255,255,0.3)"),
            ),
            text=[n.split(".")[-1] if len(n) > 12 else n for n in nodes],
            textposition="top center",
            textfont=dict(size=8, color="#AAA"),
            hovertext=node_text,
            hoverinfo="text",
            showlegend=False,
        )
    )

    fig.update_layout(
        title="Network Communication Graph",
        template="plotly_dark",
        height=600,
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, constrain="domain"),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, scaleanchor="x", scaleratio=1),
        margin=dict(l=20, r=20, t=50, b=20),
    )
    return fig


_WELL_KNOWN_PORTS: dict[str, str] = {
    "20": "FTP-Data",
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "67": "DHCP",
    "68": "DHCP",
    "80": "HTTP",
    "110": "POP3",
    "123": "NTP",
    "143": "IMAP",
    "443": "HTTPS",
    "445": "SMB",
    "465": "SMTPS",
    "587": "SMTP",
    "993": "IMAPS",
    "995": "POP3S",
    "1883": "MQTT",
    "3306": "MySQL",
    "3389": "RDP",
    "5060": "SIP",
    "5061": "SIPS",
    "5222": "XMPP",
    "5223": "APNs",
    "5228": "FCM",
    "5353": "mDNS",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
    "8883": "MQTT-TLS",
    "9200": "Elasticsearch",
}


def _port_label(dport: str, proto: str) -> str:
    """Return a human-readable label for a destination port."""
    name = _WELL_KNOWN_PORTS.get(dport, "")
    if name:
        return f"{dport}/{name}"
    return f"{dport}/{proto.upper()}"


def build_sankey_html(
    flows: list[dict[str, Any]],
    max_services: int = 10,
    max_clients: int = 8,
    max_servers: int = 12,
) -> tuple[str, int] | None:
    """Build an HTML string rendering an ECharts Sankey diagram.

    Returns a tuple of (html_string, chart_height_px) or None if no data.
    The HTML uses the ECharts CDN and is rendered via st.components.v1.html.
    Supports draggable nodes, mouse-wheel zoom, click-drag pan, and a
    toolbar with save-as-image and reset buttons.

    Each flow is normalised so the side with the well-known port
    (< 10000) is treated as the server.  Flows where neither port is
    well-known are skipped (ephemeral-to-ephemeral).
    """
    import json

    if not flows:
        return None

    # --- Step 1: normalise every flow and aggregate ---
    agg: dict[tuple, int] = defaultdict(int)

    for f in flows:
        src = f.get("src", "")
        dst = f.get("dst", "")
        if not src or not dst:
            continue

        try:
            sp = int(f.get("sport") or 0)
        except (ValueError, TypeError):
            sp = 0
        try:
            dp = int(f.get("dport") or 0)
        except (ValueError, TypeError):
            dp = 0

        proto = f.get("proto") or "unknown"
        count = f.get("count", 1)

        sp_wk = 0 < sp < 10000
        dp_wk = 0 < dp < 10000

        if dp_wk and not sp_wk:
            client, server, svc_port = src, dst, dp
        elif sp_wk and not dp_wk:
            client, server, svc_port = dst, src, sp
        elif dp_wk and sp_wk:
            if dp <= sp:
                client, server, svc_port = src, dst, dp
            else:
                client, server, svc_port = dst, src, sp
        else:
            continue

        service = _port_label(str(svc_port), proto)
        agg[(client, service, server)] += count

    if not agg:
        return None

    # --- Step 2: rank and pick top nodes ---
    cli_totals: dict[str, int] = defaultdict(int)
    svc_totals: dict[str, int] = defaultdict(int)
    srv_totals: dict[str, int] = defaultdict(int)
    for (c, s, d), cnt in agg.items():
        cli_totals[c] += cnt
        svc_totals[s] += cnt
        srv_totals[d] += cnt

    top_cli = [x for x, _ in sorted(cli_totals.items(), key=lambda v: -v[1])[:max_clients]]
    top_svc = [x for x, _ in sorted(svc_totals.items(), key=lambda v: -v[1])[:max_services]]
    top_srv = [x for x, _ in sorted(srv_totals.items(), key=lambda v: -v[1])[:max_servers]]

    cli_set, svc_set, srv_set = set(top_cli), set(top_svc), set(top_srv)
    filtered = {k: v for k, v in agg.items() if k[0] in cli_set and k[1] in svc_set and k[2] in srv_set}
    if not filtered:
        return None

    # --- Step 3: build ECharts nodes ---
    nodes: list[dict] = []
    for item in top_cli:
        nodes.append({"name": f"C_{item}", "depth": 0, "itemStyle": {"color": "#4A90E2"}})
    for item in top_svc:
        nodes.append({"name": f"S_{item}", "depth": 1, "itemStyle": {"color": "#FFA94D"}})
    for item in top_srv:
        nodes.append({"name": f"D_{item}", "depth": 2, "itemStyle": {"color": "#51CF66"}})

    # --- Step 4: build links ---
    links: list[dict] = []
    for (cli, svc, srv), cnt in filtered.items():
        links.append({"source": f"C_{cli}", "target": f"S_{svc}", "value": cnt})
        links.append({"source": f"S_{svc}", "target": f"D_{srv}", "value": cnt})

    # --- Step 5: compute height ---
    max_nodes = max(len(top_cli), len(top_svc), len(top_srv))
    node_gap = max(8, min(30, 300 // max(max_nodes, 1)))
    chart_height = max(500, min(1200, max_nodes * 55 + 120))

    nodes_json = json.dumps(nodes)
    links_json = json.dumps(links)

    # --- Step 6: build self-contained HTML ---
    html = f"""
    <div id="sankey" style="width:100%;height:{chart_height}px;"></div>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
    <script>
    var chart = echarts.init(document.getElementById('sankey'));
    var option = {{
        backgroundColor: 'transparent',
        title: {{
            text: 'Traffic Flow (Client \\u2192 Service \\u2192 Server)',
            left: 'left',
            textStyle: {{ color: '#222', fontSize: 14, fontWeight: 'bold' }}
        }},
        tooltip: {{
            trigger: 'item',
            triggerOn: 'mousemove',
            backgroundColor: 'rgba(255,255,255,0.95)',
            borderColor: '#999',
            textStyle: {{ color: '#333' }},
            formatter: function(params) {{
                if (params.dataType === 'node') {{
                    return params.name.replace(/^[CSD]_/, '');
                }}
                var src = params.data.source.replace(/^[CSD]_/, '');
                var tgt = params.data.target.replace(/^[CSD]_/, '');
                return src + ' \\u2192 ' + tgt + '<br/>Packets: ' + params.data.value;
            }}
        }},
        toolbox: {{
            show: true,
            right: 10,
            top: 0,
            feature: {{
                saveAsImage: {{ title: 'Save', pixelRatio: 2 }},
                restore: {{ title: 'Reset' }}
            }},
            iconStyle: {{ borderColor: '#666' }}
        }},
        series: [{{
            type: 'sankey',
            draggable: true,
            emphasis: {{ focus: 'adjacency' }},
            nodeAlign: 'justify',
            nodeGap: {node_gap},
            nodeWidth: 18,
            layoutIterations: 32,
            orient: 'horizontal',
            left: '8%',
            right: '8%',
            top: '8%',
            bottom: '5%',
            data: {nodes_json},
            links: {links_json},
            lineStyle: {{ color: 'gradient', curveness: 0.5, opacity: 0.35 }},
            label: {{
                position: 'right',
                fontSize: 11,
                color: '#333',
                fontWeight: 'bold',
                formatter: function(params) {{
                    return params.name.replace(/^[CSD]_/, '');
                }}
            }},
            levels: [
                {{
                    depth: 0,
                    label: {{ position: 'left' }},
                    itemStyle: {{ color: '#4A90E2' }},
                    lineStyle: {{ color: 'source', opacity: 0.3 }}
                }},
                {{
                    depth: 1,
                    label: {{ position: 'right' }},
                    itemStyle: {{ color: '#FFA94D' }},
                    lineStyle: {{ color: 'source', opacity: 0.3 }}
                }},
                {{
                    depth: 2,
                    label: {{ position: 'right' }},
                    itemStyle: {{ color: '#51CF66' }},
                    lineStyle: {{ color: 'source', opacity: 0.3 }}
                }}
            ]
        }}]
    }};
    chart.setOption(option);
    window.addEventListener('resize', function() {{ chart.resize(); }});
    </script>
    """
    return html, chart_height


def plot_traffic_timeline_heatmap(flows: list[dict]) -> go.Figure | None:
    """Plot a time-vs-IP heatmap showing when each IP communicated.

    Args:
        flows: List of flow dicts with 'dst', 'pkt_times' keys.

    Returns:
        Plotly Figure or None if insufficient data.
    """
    if not flows:
        return None

    rows = []
    for f in flows:
        dst = f.get("dst", "")
        times = f.get("pkt_times", [])
        if not dst or not times:
            continue
        for t in times[:500]:  # Limit per flow for performance
            try:
                rows.append({"IP": dst, "timestamp": float(t)})
            except (ValueError, TypeError):
                continue

    if len(rows) < 10:
        return None

    df = pd.DataFrame(rows)
    # Convert epoch to relative minutes
    t_min = df["timestamp"].min()
    df["minute"] = ((df["timestamp"] - t_min) / 60).astype(int)

    # Top 20 IPs by activity
    top_ips = df["IP"].value_counts().head(20).index.tolist()
    df = df[df["IP"].isin(top_ips)]

    # Create heatmap matrix
    pivot = df.groupby(["IP", "minute"]).size().reset_index(name="packets")
    heatmap = pivot.pivot_table(index="IP", columns="minute", values="packets", fill_value=0)

    fig = px.imshow(
        heatmap,
        aspect="auto",
        color_continuous_scale="YlOrRd",
        labels={"x": "Time (minutes)", "y": "Destination IP", "color": "Packets"},
        title="Traffic Timeline Heatmap (Top 20 IPs)",
        height=max(300, len(top_ips) * 25 + 100),
    )
    fig.update_layout(
        margin=dict(l=0, r=0, t=40, b=0),
        xaxis_title="Time (minutes from capture start)",
        yaxis_title="",
    )
    return fig


def plot_packet_size_histogram(flows: list[dict]) -> go.Figure | None:
    """Plot distribution of packet sizes across all flows.

    Args:
        flows: List of flow dicts with 'pkt_lens' key.

    Returns:
        Plotly Figure or None if insufficient data.
    """
    all_sizes = []
    for f in flows:
        pkt_lens = f.get("pkt_lens", [])
        if isinstance(pkt_lens, list):
            all_sizes.extend(pkt_lens[:1000])  # Limit per flow

    if len(all_sizes) < 10:
        return None

    # Cap at reasonable display range
    sizes = [min(s, 2000) for s in all_sizes if isinstance(s, (int, float)) and s > 0]
    if not sizes:
        return None

    df = pd.DataFrame({"Packet Size (bytes)": sizes})

    fig = px.histogram(
        df,
        x="Packet Size (bytes)",
        nbins=50,
        title="Packet Size Distribution",
        labels={"count": "Frequency"},
        height=350,
        color_discrete_sequence=["#4A90E2"],
    )
    fig.update_layout(
        margin=dict(l=0, r=0, t=40, b=0),
        bargap=0.05,
        showlegend=False,
    )

    # Add annotation for common sizes
    fig.add_vline(x=64, line_dash="dash", line_color="red", annotation_text="Min TCP (64B)")
    fig.add_vline(x=1500, line_dash="dash", line_color="orange", annotation_text="MTU (1500B)")

    return fig


def plot_inter_arrival_histogram(flows: list[dict]) -> go.Figure | None:
    """Plot distribution of inter-arrival times for traffic profiling.

    Args:
        flows: List of flow dicts with 'pkt_times' key.

    Returns:
        Plotly Figure or None if insufficient data.
    """
    import numpy as np

    all_gaps = []
    for f in flows:
        ts = sorted(f.get("pkt_times", []))
        if len(ts) < 2:
            continue
        gaps = list(np.diff(ts))
        all_gaps.extend(gaps[:500])  # Limit per flow

    if len(all_gaps) < 10:
        return None

    # Filter to reasonable range (0-60s) for display
    gaps = [g for g in all_gaps if isinstance(g, (int, float)) and 0 < g < 60]
    if not gaps:
        return None

    df = pd.DataFrame({"Inter-Arrival Time (seconds)": gaps})

    fig = px.histogram(
        df,
        x="Inter-Arrival Time (seconds)",
        nbins=60,
        title="Inter-Arrival Time Distribution",
        height=350,
        color_discrete_sequence=["#51CF66"],
    )
    fig.update_layout(
        margin=dict(l=0, r=0, t=40, b=0),
        bargap=0.05,
        showlegend=False,
    )
    return fig
