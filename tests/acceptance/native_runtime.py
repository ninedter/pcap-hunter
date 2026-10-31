"""Offline acceptance against actual packaged parsers, chart browser and PDF renderer."""

import json
import subprocess
import tempfile
from pathlib import Path

import plotly.graph_objects as go
import pyshark

from app.pipeline.zeek import load_zeek_any, run_zeek
from app.reports.chart_images import figure_to_data_uri
from app.reports.pdf_generator import PDFReportGenerator, ReportConfig


def probe():
    capture_path = "/fixtures/tiny.pcap"
    frames = subprocess.check_output(
        ["tshark", "-r", capture_path, "-T", "fields", "-e", "frame.number"],
        stderr=subprocess.DEVNULL,
        text=True,
    ).splitlines()
    assert len(frames) == 20
    capture = pyshark.FileCapture(capture_path, keep_packets=False)
    try:
        assert next(iter(capture)).number == "1"
    finally:
        capture.close()
    with tempfile.TemporaryDirectory() as directory:
        logs = run_zeek(capture_path, directory)
        assert "conn.log" in logs
        connections = len(load_zeek_any(logs["conn.log"]))
        assert connections == 20
    chart = figure_to_data_uri(go.Figure(go.Bar(x=["TCP", "UDP"], y=[20, 4])), width=800, height=400, scale=1)
    world = figure_to_data_uri(
        go.Figure(go.Scattergeo(lat=[25.0], lon=[121.0], text=["Synthetic endpoint"])),
        width=800,
        height=450,
        scale=1,
    )
    assert chart and world and all(value.startswith("data:image/png;base64,") for value in (chart, world))
    report = PDFReportGenerator(ReportConfig(title="Native runtime acceptance", include_charts=False)).generate(
        report_md="# Offline report\n\n![Protocol chart](" + chart + ")\n\n![Map](" + world + ")",
        features={"packet_count": 20},
        osint={},
    )
    assert report and report.content.startswith(b"%PDF") and report.page_count > 0
    assert Path(capture_path).is_file()
    return {
        "tshark_packets": len(frames),
        "pyshark_pdml_xml": True,
        "zeek_connections": connections,
        "offline_bar_and_geographic_png": True,
        "pdf_with_embedded_charts": True,
        "pdf_pages": report.page_count,
    }


if __name__ == "__main__":
    print(json.dumps(probe()))
