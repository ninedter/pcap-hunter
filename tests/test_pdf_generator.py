"""Tests for PDF report generation module."""

from datetime import datetime

import pytest

# Import pdf_generator FIRST — it runs _ensure_dyld_path() at module load
# time which fixes the WeasyPrint native-lib lookup on macOS. Importing
# weasyprint directly here would run before that fix and incorrectly
# report WeasyPrint as unavailable.
from app.reports.pdf_generator import (
    WEASYPRINT_AVAILABLE,
    PDFReport,
    PDFReportGenerator,
    ReportConfig,
)

# Keep MODULE_WEASYPRINT as an alias for any legacy test code that uses it.
MODULE_WEASYPRINT = WEASYPRINT_AVAILABLE


class TestReportConfig:
    """Test ReportConfig dataclass."""

    def test_default_config(self):
        config = ReportConfig()
        assert config.title == "PCAP Analysis Report"
        assert config.include_charts is True
        assert config.include_raw_data is True
        assert config.include_yara is True
        assert config.include_osint is True
        assert config.language == "en"

    def test_custom_config(self):
        config = ReportConfig(
            title="Custom Report",
            analyst="Test Analyst",
            organization="Test Org",
            classification="TLP:AMBER",
            include_charts=False,
        )
        assert config.title == "Custom Report"
        assert config.analyst == "Test Analyst"
        assert config.organization == "Test Org"
        assert config.classification == "TLP:AMBER"
        assert config.include_charts is False

    def test_to_dict(self):
        config = ReportConfig(title="Test")
        d = config.to_dict()
        assert d["title"] == "Test"
        assert "analyst" in d
        assert "include_charts" in d


class TestPDFReport:
    """Test PDFReport dataclass."""

    def test_pdf_report(self):
        now = datetime.now()
        report = PDFReport(
            content=b"test pdf content",
            filename="report.pdf",
            page_count=5,
            generated_at=now,
        )
        assert report.content == b"test pdf content"
        assert report.filename == "report.pdf"
        assert report.page_count == 5
        assert report.generated_at == now


class TestPDFReportGenerator:
    """Test PDFReportGenerator class."""

    def test_init_default_config(self):
        gen = PDFReportGenerator()
        assert gen.config.title == "PCAP Analysis Report"

    def test_init_custom_config(self):
        config = ReportConfig(title="Custom Title")
        gen = PDFReportGenerator(config)
        assert gen.config.title == "Custom Title"

    def test_is_available(self):
        """Test availability check."""
        gen = PDFReportGenerator()
        assert gen.is_available == MODULE_WEASYPRINT

    def test_build_html_minimal(self):
        """Test HTML building with minimal data."""
        gen = PDFReportGenerator()
        html = gen._build_html(
            report_md="# Test Report\n\nThis is a test.",
            features={},
            osint={},
            yara_results=None,
            dns_analysis=None,
            tls_analysis=None,
            case_info=None,
        )
        assert "<html" in html
        assert "Test Report" in html
        assert "</html>" in html

    def test_build_html_with_case_info(self):
        """Test HTML building with case info."""
        gen = PDFReportGenerator()
        case_info = {
            "id": "CASE-001",
            "title": "Test Case",
            "severity": "high",
        }
        html = gen._build_html(
            report_md="# Test",
            features={},
            osint={},
            yara_results=None,
            dns_analysis=None,
            tls_analysis=None,
            case_info=case_info,
        )
        assert "CASE-001" in html
        assert "Test Case" in html

    def test_build_html_with_osint(self):
        """Test HTML building with OSINT data."""
        gen = PDFReportGenerator()
        osint = {
            "virustotal": {
                "1.2.3.4": {"detections": 5, "total": 70},
            },
            "greynoise": {
                "1.2.3.4": {"classification": "malicious"},
            },
        }
        html = gen._build_html(
            report_md="# Test",
            features={},
            osint=osint,
            yara_results=None,
            dns_analysis=None,
            tls_analysis=None,
            case_info=None,
        )
        assert "OSINT" in html or "osint" in html.lower()

    def test_build_html_with_dns_analysis(self):
        """Test HTML building with DNS analysis."""
        gen = PDFReportGenerator()
        dns_analysis = {
            "total_records": 100,
            "unique_domains": 50,
            "alerts": {"dga_count": 2, "tunneling_count": 0, "fast_flux_count": 1},
            "dga_detections": [{"domain": "xk7m2p9q4.com", "score": 0.8, "is_dga": True}],
        }
        html = gen._build_html(
            report_md="# Test",
            features={},
            osint={},
            yara_results=None,
            dns_analysis=dns_analysis,
            tls_analysis=None,
            case_info=None,
        )
        assert "DNS" in html

    def test_build_html_with_tls_analysis(self):
        """Test HTML building with TLS analysis."""
        gen = PDFReportGenerator()
        tls_analysis = {
            "total_certs": 5,
            "certificates": [
                {
                    "subject": {"CN": "example.com"},
                    "issuer": {"CN": "CA"},
                    "not_before": "2024-01-01",
                    "not_after": "2025-01-01",
                }
            ],
            "alerts": [],
        }
        html = gen._build_html(
            report_md="# Test",
            features={},
            osint={},
            yara_results=None,
            dns_analysis=None,
            tls_analysis=tls_analysis,
            case_info=None,
        )
        assert "TLS" in html or "Certificate" in html

    def test_build_html_with_yara_results(self):
        """Test HTML building with YARA results."""
        gen = PDFReportGenerator()
        yara_results = {
            "scanned": 10,
            "matched": 2,
            "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "clean": 8},
            "results": [
                {
                    "file_path": "/tmp/test.bin",
                    "matches": [{"rule_name": "PE_Executable", "rule_tags": ["pe"]}],
                    "severity": "high",
                }
            ],
        }
        html = gen._build_html(
            report_md="# Test",
            features={},
            osint={},
            yara_results=yara_results,
            dns_analysis=None,
            tls_analysis=None,
            case_info=None,
        )
        assert "YARA" in html

    def test_build_html_with_flows(self):
        """Test HTML building with flow data."""
        gen = PDFReportGenerator()
        features = {
            "flows": [
                {
                    "src_ip": "192.168.1.1",
                    "dst_ip": "1.2.3.4",
                    "proto": "TCP",
                    "bytes": 1000,
                }
            ]
        }
        html = gen._build_html(
            report_md="# Test",
            features=features,
            osint={},
            yara_results=None,
            dns_analysis=None,
            tls_analysis=None,
            case_info=None,
        )
        # HTML should contain flow data or network info
        assert html  # Just verify it generates without error

    def test_generate_without_weasyprint(self):
        """Test generation when weasyprint is not available."""
        gen = PDFReportGenerator()
        if not gen.is_available:
            result = gen.generate(
                report_md="# Test",
                features={},
                osint={},
            )
            # When weasyprint is not available, generate returns None
            assert result is None

    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="weasyprint not installed")
    def test_generate_pdf(self):
        """Test actual PDF generation."""
        gen = PDFReportGenerator()
        result = gen.generate(
            report_md="# Test Report\n\nThis is a test report.",
            features={
                "pcap_hash": "abc123",
                "packet_count": 1000,
            },
            osint={},
        )
        assert result is not None
        assert len(result.content) > 0
        # Check PDF magic bytes
        assert result.content[:4] == b"%PDF"
        assert result.page_count > 0

    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="weasyprint not installed")
    def test_generate_pdf_full(self):
        """Test PDF generation with all data types."""
        config = ReportConfig(
            title="Full Test Report",
            analyst="Test Analyst",
            organization="Test Corp",
        )
        gen = PDFReportGenerator(config)
        result = gen.generate(
            report_md="# Executive Summary\n\nCritical threats detected.",
            features={
                "pcap_hash": "abc123def456",
                "packet_count": 5000,
                "flows": [{"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "proto": "UDP"}],
            },
            osint={
                "virustotal": {"8.8.8.8": {"detections": 0, "total": 70}},
            },
            yara_results={
                "scanned": 5,
                "matched": 1,
                "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "clean": 4},
            },
            dns_analysis={
                "total_records": 50,
                "unique_domains": 25,
                "alerts": {"dga_count": 0, "tunneling_count": 0, "fast_flux_count": 0},
            },
            tls_analysis={
                "total_certs": 3,
                "certificates": [],
                "alerts": [],
            },
            case_info={
                "id": "CASE-2024-001",
                "title": "Suspicious Network Activity",
                "severity": "high",
            },
        )
        assert result is not None
        assert len(result.content) > 0

    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="weasyprint not installed")
    def test_render_correlation_with_signal_dataclasses(self):
        """Regression: CorrelationSignal dataclass objects must not crash rendering.

        Previously the correlation section called ``', '.join(c.signals)``
        directly, which raised ``TypeError: sequence item 0: expected str
        instance, CorrelationSignal found`` when the real pipeline passed in
        dataclass instances. Render the names instead.
        """
        from app.analysis.correlation import CorrelationResult, CorrelationSignal

        correlations = [
            CorrelationResult(
                indicator="8.8.8.8",
                indicator_type="ip",
                signals=[
                    CorrelationSignal("vt_detections", -10, 0.5, "virustotal"),
                    CorrelationSignal("beacon_score", 0.9, 0.9, "beacon"),
                    CorrelationSignal("vt_detections", -10, 0.5, "virustotal"),  # duplicate
                ],
                composite_score=0.75,
                verdict="high",
            ),
        ]
        gen = PDFReportGenerator()
        html = gen._render_correlation_section(correlations)
        # Signals should appear as joined names, duplicates removed
        assert "vt_detections, beacon_score" in html
        assert "8.8.8.8" in html
        assert "high" in html

    @pytest.mark.skipif(not WEASYPRINT_AVAILABLE, reason="weasyprint not installed")
    def test_render_correlation_with_dict_signals(self):
        """Dict-shaped correlations with list[dict] signals must also render."""
        correlations = [
            {
                "indicator": "evil.example",
                "verdict": "critical",
                "signals": [{"name": "dga_domain"}, {"name": "dns_tunneling"}],
            },
        ]
        gen = PDFReportGenerator()
        html = gen._render_correlation_section(correlations)
        assert "dga_domain, dns_tunneling" in html
        assert "evil.example" in html


class TestConfigSections:
    """Test config section toggling."""

    def test_no_charts(self):
        """Test HTML without charts."""
        config = ReportConfig(include_charts=False)
        gen = PDFReportGenerator(config)
        html = gen._build_html("# Test", {}, {}, None, None, None, None)
        assert html  # Just ensure no error

    def test_no_raw_data(self):
        """Test HTML without raw data."""
        config = ReportConfig(include_raw_data=False)
        gen = PDFReportGenerator(config)
        html = gen._build_html("# Test", {}, {}, None, None, None, None)
        assert html

    def test_no_yara(self):
        """Test HTML without YARA section."""
        config = ReportConfig(include_yara=False)
        gen = PDFReportGenerator(config)
        yara_results = {"scanned": 5, "matched": 1}
        html = gen._build_html("# Test", {}, {}, yara_results, None, None, None)
        assert html

    def test_no_osint(self):
        """Test HTML without OSINT section."""
        config = ReportConfig(include_osint=False)
        gen = PDFReportGenerator(config)
        osint = {"virustotal": {"1.2.3.4": {}}}
        html = gen._build_html("# Test", {}, osint, None, None, None, None)
        assert html
