"""End-to-end PDF generation tests.

These tests exercise the complete PDF export path with **production-shape**
data — real dataclass instances (``CorrelationSignal``), real pandas
DataFrames for beacon scoring, and the same nested dict shapes the pipeline
produces. Unit tests alone missed bugs like the ``CorrelationSignal`` join
crash because they used simplified synthetic inputs.

Every production code path that contributes to the PDF has at least one
end-to-end assertion here. When adding new PDF sections, extend the
``test_full_pdf_with_all_sections`` fixture and add a targeted assertion.
"""

from __future__ import annotations

import re
from datetime import datetime

import pandas as pd
import pytest

from app.analysis.correlation import CorrelationResult, CorrelationSignal
from app.reports.pdf_generator import WEASYPRINT_AVAILABLE, PDFReportGenerator, ReportConfig

# ---------------------------------------------------------------------------
# Realistic fixtures — shaped exactly like live-pipeline output
# ---------------------------------------------------------------------------


@pytest.fixture
def realistic_features() -> dict:
    """Features dict matching parse_pcap_pyshark output structure."""
    return {
        "packet_count": 5_234,
        "pcap_hash": "a1b2c3d4e5f6",
        "flows": [
            {
                "src": "10.0.0.5",
                "dst": "8.8.8.8",
                "sport": 55001,
                "dport": 443,
                "proto": "TCP",
                "count": 245,
                "bytes": 32_768,
                "ts": 1_700_000_000,
            },
            {
                "src": "10.0.0.5",
                "dst": "1.1.1.1",
                "sport": 55002,
                "dport": 53,
                "proto": "UDP",
                "count": 40,
                "bytes": 2_048,
                "ts": 1_700_000_060,
            },
            {
                "src": "10.0.0.5",
                "dst": "34.12.37.224",
                "sport": 55004,
                "dport": 6888,
                "proto": "TCP",
                "count": 1_200,
                "bytes": 524_288,
                "ts": 1_700_000_120,
            },
            {
                "src": "10.0.0.6",
                "dst": "142.250.204.110",
                "sport": 55005,
                "dport": 443,
                "proto": "TCP",
                "count": 85,
                "bytes": 12_345,
                "ts": 1_700_000_180,
            },
        ],
        "artifacts": {
            "ips": ["8.8.8.8", "1.1.1.1", "34.12.37.224", "142.250.204.110", "10.0.0.5"],
            "domains": ["example.com", "malicious.dga.xyz", "dns.google"],
            "urls": ["https://example.com/api"],
            "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "ja3": ["771,4865-4866-4867,0-23-65281-10-11-35,29-23-24,0"],
            "macs": ["aa:bb:cc:dd:ee:ff"],
        },
    }


@pytest.fixture
def realistic_correlations() -> list[CorrelationResult]:
    """CorrelationResult objects with nested CorrelationSignal dataclasses.

    The CorrelationSignal bug (TypeError on .join) would be caught here
    because we pass the real dataclass, not a dict or string list.
    """
    return [
        CorrelationResult(
            indicator="34.12.37.224",
            indicator_type="ip",
            signals=[
                CorrelationSignal("vt_detections", -12, 0.12, "virustotal"),
                CorrelationSignal("beacon_score", 0.96, 0.96, "beacon"),
                CorrelationSignal("abuseipdb", 85, 0.85, "abuseipdb"),
            ],
            composite_score=0.85,
            verdict="critical",
        ),
        CorrelationResult(
            indicator="malicious.dga.xyz",
            indicator_type="domain",
            signals=[
                CorrelationSignal("dga_domain", 0.92, 0.92, "dns"),
                CorrelationSignal("vt_detections", "5/94", 0.053, "virustotal"),
            ],
            composite_score=0.62,
            verdict="high",
        ),
        CorrelationResult(
            indicator="8.8.8.8",
            indicator_type="ip",
            signals=[
                CorrelationSignal("greynoise_malicious", "benign", 0.0, "greynoise"),
            ],
            composite_score=0.15,
            verdict="low",
        ),
    ]


@pytest.fixture
def realistic_beacon_df() -> pd.DataFrame:
    """beacon_df shape matching rank_beaconing output (emits "pkts", not "count")."""
    return pd.DataFrame(
        [
            {"src": "10.0.0.5", "dst": "34.12.37.224", "dport": 6888, "score": 0.964, "cv": 0.106, "pkts": 120},
            {"src": "54.254.33.127", "dst": "10.0.0.5", "dport": 58663, "score": 0.949, "cv": 0.052, "pkts": 85},
            {"src": "10.0.0.5", "dst": "142.250.204.110", "dport": 443, "score": 0.542, "cv": 0.312, "pkts": 42},
        ]
    )


@pytest.fixture
def realistic_osint() -> dict:
    return {
        "ips": {
            "34.12.37.224": {
                "vt": {"data": {"attributes": {"reputation": -12, "last_analysis_stats": {"malicious": 5}}}},
                "abuseipdb": {"data": {"abuseConfidenceScore": 85}},
                "greynoise": {"classification": "malicious"},
            },
            "8.8.8.8": {
                "vt": {"data": {"attributes": {"reputation": 0}}},
                "greynoise": {"classification": "benign"},
            },
        },
        "domains": {
            "malicious.dga.xyz": {
                "vt": {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 89}}}},
            },
        },
    }


@pytest.fixture
def realistic_dns_analysis() -> dict:
    return {
        "total_records": 106,
        "unique_domains": 32,
        "alerts": {"dga_count": 1, "tunneling_count": 0, "fast_flux_count": 2},
        "dga_detections": [
            {"domain": "malicious.dga.xyz", "score": 0.92, "is_dga": True},
        ],
        "tunneling_detections": [],
    }


@pytest.fixture
def realistic_tls_analysis() -> dict:
    return {
        "total_certs": 3,
        "certificates": [
            {"subject": "example.com", "issuer": "Let's Encrypt", "valid_until": "2026-12-01"},
        ],
        "alerts": [
            {"type": "self_signed", "dst_ip": "34.12.37.224", "severity": "high", "cert": "CN=bad.local"},
        ],
    }


@pytest.fixture
def realistic_yara_results() -> dict:
    return {
        "scanned": 8,
        "matched": 1,
        "yara_available": True,
        "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "clean": 7},
        "results": [
            {
                "file_name": "payload_1.bin",
                "src_ip": "34.12.37.224",
                "severity": "high",
                "has_matches": True,
                "matches": [{"rule_name": "CobaltStrike_Beacon", "rule_tags": ["apt", "c2"]}],
            },
        ],
    }


@pytest.fixture
def realistic_geoip_data() -> list[dict]:
    return [
        {"ip": "8.8.8.8", "country": "United States", "city": "Mountain View", "lat": 37.386, "lon": -122.083},
        {"ip": "1.1.1.1", "country": "Australia", "city": "Sydney", "lat": -33.494, "lon": 143.210},
        {"ip": "34.12.37.224", "country": "United States", "city": "Kansas City", "lat": 39.099, "lon": -94.578},
    ]


@pytest.fixture
def full_report_html(
    realistic_features,
    realistic_correlations,
    realistic_beacon_df,
    realistic_osint,
    realistic_dns_analysis,
    realistic_tls_analysis,
    realistic_yara_results,
    realistic_geoip_data,
) -> str:
    """Complete report HTML built from the production-shape fixtures above.

    Section structure (numbering, TOC, headings, timestamps) is asserted on
    the HTML directly, so no WeasyPrint render is required.
    """
    gen = PDFReportGenerator(ReportConfig(title="Section Registry Test"))
    return gen._build_html(
        # Realistic LLM output includes its own numbered headings — they must
        # never collide with the registry's numbered section <h2>s.
        report_md="# Test\n\n## 2. Key Findings\n\nBody.\n\n## 3. Recommendations\n\nMore.",
        features=realistic_features,
        osint=realistic_osint,
        yara_results=realistic_yara_results,
        dns_analysis=realistic_dns_analysis,
        tls_analysis=realistic_tls_analysis,
        case_info={"id": "CASE-001", "title": "Registry Test"},
        beacon_df=realistic_beacon_df,
        correlations=realistic_correlations,
        geoip_data=realistic_geoip_data,
    )


# ---------------------------------------------------------------------------
# End-to-end tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="weasyprint not installed")
class TestFullPDFGeneration:
    """Exercise the complete generate() path with production-shape data."""

    def test_full_pdf_with_all_sections(
        self,
        realistic_features,
        realistic_correlations,
        realistic_beacon_df,
        realistic_osint,
        realistic_dns_analysis,
        realistic_tls_analysis,
        realistic_yara_results,
        realistic_geoip_data,
    ):
        """Full report with every section populated and every data type realistic.

        This is the canonical pre-commit smoke test for PDF export. If this
        fails, the LLM-Analysis 'Generate PDF Report' button is broken.
        """
        gen = PDFReportGenerator(
            ReportConfig(
                title="Integration Test Report",
                analyst="pytest",
                organization="pcap-hunter CI",
                classification="TLP:CLEAR",
            )
        )

        pdf = gen.generate(
            report_md=(
                "# Executive Summary\n\n"
                "Critical C2 beacon to 34.12.37.224 observed with high regularity.\n\n"
                "## Key Findings\n- DGA domain\n- Self-signed cert\n"
            ),
            features=realistic_features,
            osint=realistic_osint,
            yara_results=realistic_yara_results,
            dns_analysis=realistic_dns_analysis,
            tls_analysis=realistic_tls_analysis,
            case_info={"id": "CASE-001", "title": "E2E Test", "severity": "critical"},
            beacon_df=realistic_beacon_df,
            correlations=realistic_correlations,
            geoip_data=realistic_geoip_data,
        )

        assert pdf is not None, "PDF generation returned None — see error logs"
        assert len(pdf.content) > 10_000, "PDF unreasonably small — likely missing sections"
        assert pdf.page_count >= 3, f"Expected at least 3 pages, got {pdf.page_count}"
        assert pdf.content[:4] == b"%PDF", "Output is not a valid PDF file"
        assert pdf.filename.endswith(".pdf")
        assert isinstance(pdf.generated_at, datetime)

    def test_html_contains_every_expected_section(
        self,
        realistic_features,
        realistic_correlations,
        realistic_beacon_df,
        realistic_osint,
        realistic_dns_analysis,
        realistic_tls_analysis,
        realistic_yara_results,
        realistic_geoip_data,
    ):
        """Verify section IDs and key tokens appear in the generated HTML."""
        gen = PDFReportGenerator(ReportConfig(title="Section Coverage Test"))
        html = gen._build_html(
            report_md="# Test\n\nBody.",
            features=realistic_features,
            osint=realistic_osint,
            yara_results=realistic_yara_results,
            dns_analysis=realistic_dns_analysis,
            tls_analysis=realistic_tls_analysis,
            case_info=None,
            beacon_df=realistic_beacon_df,
            correlations=realistic_correlations,
            geoip_data=realistic_geoip_data,
        )

        # Section anchors
        assert 'id="summary"' in html
        assert 'id="charts"' in html
        assert 'id="correlations"' in html
        assert 'id="iocs"' in html
        assert 'id="osint"' in html
        assert 'id="dns"' in html
        assert 'id="tls"' in html
        assert 'id="yara"' in html
        assert 'id="beacons"' in html
        assert 'id="flows"' in html
        assert 'id="appendix"' in html

        # CorrelationSignal rendering — the bug that started this whole test file
        assert "34.12.37.224" in html
        assert "vt_detections" in html
        assert "beacon_score" in html
        assert "critical" in html.lower()

        # Beacon DataFrame rendering
        assert "0.964" in html or "0.96" in html  # beacon score
        # Packets column must read the "pkts" key emitted by rank_beaconing
        assert "<td>120</td>" in html

        # YARA match rendering
        assert "CobaltStrike_Beacon" in html

    def test_pdf_with_charts_embeds_png_data_uris(
        self,
        realistic_features,
        realistic_geoip_data,
    ):
        """The Visual Overview section must embed at least one chart as PNG."""
        pytest.importorskip("kaleido")
        gen = PDFReportGenerator(ReportConfig(include_charts=True))
        html = gen._build_html(
            report_md="# T",
            features=realistic_features,
            osint=None,
            yara_results=None,
            dns_analysis=None,
            tls_analysis=None,
            case_info=None,
            beacon_df=None,
            correlations=None,
            geoip_data=realistic_geoip_data,
        )
        count = html.count("data:image/png;base64,")
        assert count >= 5, (
            f"Expected at least 5 embedded charts in Visual Overview, got {count}. Chart rendering may have regressed."
        )

    def test_pdf_without_charts_still_works(self, realistic_features):
        """include_charts=False skips the section cleanly."""
        gen = PDFReportGenerator(ReportConfig(include_charts=False))
        pdf = gen.generate(report_md="# T\n\nBody.", features=realistic_features)
        assert pdf is not None
        assert b"%PDF" in pdf.content[:10]

    def test_correlation_edge_cases_do_not_crash(self):
        """Empty signals, mixed dict/dataclass — none should blow up generation."""
        gen = PDFReportGenerator()

        # Mix: dataclass, dict-with-list-of-dicts, dict-with-strings, empty signals
        correlations = [
            CorrelationResult(indicator="1.1.1.1", indicator_type="ip", signals=[], composite_score=0.0, verdict="low"),
            {"indicator": "2.2.2.2", "verdict": "medium", "signals": [{"name": "beacon_score"}]},
            {"indicator": "3.3.3.3", "verdict": "high", "signals": ["legacy_string_signal"]},
            {"indicator": "4.4.4.4", "verdict": "info", "signals": "single_string"},
        ]
        html = gen._render_correlation_section(correlations)
        # Every indicator should appear in the output
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"):
            assert ip in html, f"Missing indicator {ip} in correlation section"

    def test_pdf_generation_with_missing_optional_fields(self):
        """Verify the minimum-data path (no osint, no yara, etc.) works."""
        gen = PDFReportGenerator()
        pdf = gen.generate(
            report_md="# Minimal",
            features={"flows": [], "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []}},
        )
        assert pdf is not None
        assert b"%PDF" in pdf.content[:10]


class TestSectionRegistry:
    """One ordered registry drives section numbering and the TOC.

    Regression targets: the report used to ship TWO sections numbered "2.",
    unnumbered correlation/beacon sections, a beacon heading duplicated across
    the empty/data code paths, and a hand-built TOC that could disagree with
    the rendered body.
    """

    def test_section_numbering_is_sequential_and_unique(self, full_report_html):
        nums = [int(m.group(1)) for m in re.finditer(r"<h2>(\d+)\. ", full_report_html)]
        assert nums, "no numbered <h2> section headings found"
        assert nums == list(range(1, len(nums) + 1)), f"section numbers broken: {nums}"

    def test_toc_entries_match_rendered_sections_in_order(self, full_report_html):
        toc_ids = re.findall(r'<li><a href="#([a-z]+)">', full_report_html)
        body_ids = [b for b in re.findall(r'<section id="([a-z]+)"', full_report_html) if b in toc_ids]
        assert toc_ids, "TOC rendered no entries"
        assert toc_ids == body_ids

    def test_beacon_heading_appears_once(self, full_report_html):
        assert full_report_html.count("C2 Beacon Analysis</h2>") == 1

    def test_llm_content_headings_demoted_below_section_level(self, full_report_html):
        """LLM markdown headings (## N. Foo) must become h4 inside the summary,
        never h2 — h2 is reserved for registry-numbered section headings."""
        assert "<h4>2. Key Findings</h4>" in full_report_html
        assert "<h2>2. Key Findings</h2>" not in full_report_html
        assert "<h4>3. Recommendations</h4>" in full_report_html

    def test_beacon_heading_appears_once_with_empty_dataframe(self, realistic_features):
        """The empty-DataFrame path must emit the same single heading."""
        gen = PDFReportGenerator(ReportConfig(include_charts=False))
        html = gen._build_html(
            report_md="# T\n\nBody.",
            features=realistic_features,
            osint=None,
            yara_results=None,
            dns_analysis=None,
            tls_analysis=None,
            case_info=None,
            beacon_df=pd.DataFrame(),
            correlations=None,
        )
        assert html.count("C2 Beacon Analysis</h2>") == 1

    def test_numbering_stays_sequential_when_conditional_sections_absent(self, realistic_features):
        """With charts/correlations/beacons/osint/dns/tls/yara absent, the
        surviving sections must still be numbered 1..N and match the TOC."""
        gen = PDFReportGenerator(ReportConfig(include_charts=False))
        html = gen._build_html(
            report_md="# T\n\nBody.",
            features=realistic_features,
            osint=None,
            yara_results=None,
            dns_analysis=None,
            tls_analysis=None,
            case_info=None,
            beacon_df=None,
            correlations=None,
        )
        nums = [int(m.group(1)) for m in re.finditer(r"<h2>(\d+)\. ", html)]
        assert nums == list(range(1, len(nums) + 1)), f"section numbers broken: {nums}"
        toc_ids = re.findall(r'<li><a href="#([a-z]+)">', html)
        body_ids = [b for b in re.findall(r'<section id="([a-z]+)"', html) if b in toc_ids]
        assert toc_ids == body_ids
        assert toc_ids == ["summary", "iocs", "flows", "appendix"]

    def test_report_timestamp_is_timezone_aware(self, full_report_html):
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})? [A-Z]{2,5}", full_report_html)
