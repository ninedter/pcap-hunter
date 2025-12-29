"""Tests for batch processing and cross-file correlation."""

import pandas as pd

from app.pipeline.batch import (
    BatchProcessor,
    PCAPResult,
    aggregate_dns_analysis,
    aggregate_tls_analysis,
    correlate_results,
    merge_beacon_candidates,
    merge_osint,
    merge_zeek_tables,
)


def create_pcap_result(
    filename: str,
    ips: list[str] = None,
    domains: list[str] = None,
    ja3: list[str] = None,
    flows: list[dict] = None,
    packet_count: int = 100,
    error: str = None,
) -> PCAPResult:
    """Helper to create test PCAPResult."""
    return PCAPResult(
        path=f"/data/{filename}",
        filename=filename,
        features={
            "flows": flows or [],
            "artifacts": {
                "ips": ips or [],
                "domains": domains or [],
                "ja3": ja3 or [],
            }
        },
        packet_count=packet_count,
        error=error,
    )


class TestCorrelateResults:
    """Test cross-file correlation."""

    def test_empty_results(self):
        correlation = correlate_results([])
        assert correlation.total_packets == 0
        assert correlation.total_flows == 0
        assert len(correlation.shared_ips) == 0

    def test_single_file(self):
        results = [
            create_pcap_result("test.pcap", ips=["1.2.3.4", "5.6.7.8"])
        ]
        correlation = correlate_results(results)
        assert correlation.total_unique_ips == 2
        assert len(correlation.shared_ips) == 0  # No sharing with single file

    def test_shared_ips(self):
        results = [
            create_pcap_result("file1.pcap", ips=["1.2.3.4", "5.6.7.8"]),
            create_pcap_result("file2.pcap", ips=["1.2.3.4", "9.10.11.12"]),
        ]
        correlation = correlate_results(results)
        assert "1.2.3.4" in correlation.shared_ips
        assert len(correlation.shared_ips["1.2.3.4"]) == 2

    def test_shared_domains(self):
        results = [
            create_pcap_result("file1.pcap", domains=["evil.com", "example.com"]),
            create_pcap_result("file2.pcap", domains=["evil.com", "google.com"]),
        ]
        correlation = correlate_results(results)
        assert "evil.com" in correlation.shared_domains
        assert len(correlation.shared_domains["evil.com"]) == 2

    def test_error_files_excluded(self):
        results = [
            create_pcap_result("file1.pcap", ips=["1.2.3.4"], packet_count=100),
            create_pcap_result("file2.pcap", ips=["1.2.3.4"], error="Failed"),
        ]
        correlation = correlate_results(results)
        # Only file1 should be counted
        assert correlation.total_packets == 100
        assert len(correlation.shared_ips) == 0  # No sharing (error file excluded)

    def test_common_indicators(self):
        results = [
            create_pcap_result("file1.pcap", ips=["1.2.3.4"], domains=["c2.evil.com"]),
            create_pcap_result("file2.pcap", ips=["1.2.3.4"], domains=["c2.evil.com"]),
            create_pcap_result("file3.pcap", ips=["1.2.3.4"]),
        ]
        correlation = correlate_results(results)
        # 1.2.3.4 should appear in all 3 files
        assert "1.2.3.4" in correlation.shared_ips
        assert len(correlation.shared_ips["1.2.3.4"]) == 3
        # Check common indicators list
        ip_indicator = next((i for i in correlation.common_indicators if i["value"] == "1.2.3.4"), None)
        assert ip_indicator is not None
        assert ip_indicator["file_count"] == 3


class TestMergeZeekTables:
    """Test merging Zeek tables from multiple PCAPs."""

    def test_empty_results(self):
        merged = merge_zeek_tables([])
        assert merged == {}

    def test_single_file(self):
        df = pd.DataFrame([{"query": "example.com", "src": "192.168.1.1"}])
        result = PCAPResult(
            path="/data/test.pcap",
            filename="test.pcap",
            features={},
            zeek_tables={"dns.log": df},
        )
        merged = merge_zeek_tables([result])
        assert "dns.log" in merged
        assert len(merged["dns.log"]) == 1
        assert "_source_file" in merged["dns.log"].columns

    def test_multiple_files(self):
        df1 = pd.DataFrame([{"query": "example.com"}])
        df2 = pd.DataFrame([{"query": "google.com"}])

        results = [
            PCAPResult(path="/data/1.pcap", filename="1.pcap", features={}, zeek_tables={"dns.log": df1}),
            PCAPResult(path="/data/2.pcap", filename="2.pcap", features={}, zeek_tables={"dns.log": df2}),
        ]
        merged = merge_zeek_tables(results)
        assert "dns.log" in merged
        assert len(merged["dns.log"]) == 2


class TestMergeOSINT:
    """Test merging OSINT data from multiple PCAPs."""

    def test_empty_results(self):
        merged = merge_osint([])
        assert merged == {"ips": {}, "domains": {}, "ja3": {}}

    def test_merge_ips(self):
        results = [
            PCAPResult(
                path="/data/1.pcap",
                filename="1.pcap",
                features={},
                osint={"ips": {"1.2.3.4": {"greynoise": {"classification": "malicious"}}}, "domains": {}, "ja3": {}},
            ),
            PCAPResult(
                path="/data/2.pcap",
                filename="2.pcap",
                features={},
                osint={"ips": {"5.6.7.8": {"vt": {"score": -5}}}, "domains": {}, "ja3": {}},
            ),
        ]
        merged = merge_osint(results)
        assert "1.2.3.4" in merged["ips"]
        assert "5.6.7.8" in merged["ips"]


class TestMergeBeaconCandidates:
    """Test merging beaconing candidates."""

    def test_empty_results(self):
        merged = merge_beacon_candidates([])
        assert merged.empty

    def test_sort_by_score(self):
        df1 = pd.DataFrame([{"src": "1.1.1.1", "dst": "2.2.2.2", "score": 0.5}])
        df2 = pd.DataFrame([{"src": "3.3.3.3", "dst": "4.4.4.4", "score": 0.9}])

        results = [
            PCAPResult(path="/data/1.pcap", filename="1.pcap", features={}, beacon_df=df1),
            PCAPResult(path="/data/2.pcap", filename="2.pcap", features={}, beacon_df=df2),
        ]
        merged = merge_beacon_candidates(results)
        assert len(merged) == 2
        # Should be sorted by score descending
        assert merged.iloc[0]["score"] == 0.9


class TestAggregateDNS:
    """Test aggregating DNS analysis results."""

    def test_empty_results(self):
        aggregated = aggregate_dns_analysis([])
        assert aggregated["total_records"] == 0

    def test_aggregate_counts(self):
        results = [
            PCAPResult(
                path="/data/1.pcap",
                filename="1.pcap",
                features={},
                dns_analysis={
                    "total_records": 100,
                    "dga_detections": [],
                    "tunneling_detections": [],
                    "fast_flux_detections": [],
                    "query_types": {"A": 50},
                    "top_queried": [],
                },
            ),
            PCAPResult(
                path="/data/2.pcap",
                filename="2.pcap",
                features={},
                dns_analysis={
                    "total_records": 200,
                    "dga_detections": [],
                    "tunneling_detections": [],
                    "fast_flux_detections": [],
                    "query_types": {"A": 100, "AAAA": 50},
                    "top_queried": [],
                },
            ),
        ]
        aggregated = aggregate_dns_analysis(results)
        assert aggregated["total_records"] == 300
        assert aggregated["query_types"]["A"] == 150


class TestAggregateTLS:
    """Test aggregating TLS analysis results."""

    def test_empty_results(self):
        aggregated = aggregate_tls_analysis([])
        assert aggregated["total_certificates"] == 0

    def test_deduplicate_by_fingerprint(self):
        cert1 = {"fingerprint_sha256": "abc123", "subject_cn": "example.com", "is_self_signed": True}
        cert2 = {"fingerprint_sha256": "abc123", "subject_cn": "example.com", "is_self_signed": True}  # Duplicate
        cert3 = {"fingerprint_sha256": "def456", "subject_cn": "other.com", "is_self_signed": False}

        results = [
            PCAPResult(
                path="/data/1.pcap",
                filename="1.pcap",
                features={},
                tls_analysis={"certificates": [cert1, cert3]},
            ),
            PCAPResult(
                path="/data/2.pcap",
                filename="2.pcap",
                features={},
                tls_analysis={"certificates": [cert2]},  # Duplicate
            ),
        ]
        aggregated = aggregate_tls_analysis(results)
        assert aggregated["total_certificates"] == 2  # Deduplicated


class TestBatchProcessor:
    """Test BatchProcessor class."""

    def test_empty_processor(self):
        processor = BatchProcessor([])
        result = processor.merge_all()
        assert result.summary["total_files"] == 0

    def test_add_result(self):
        processor = BatchProcessor(["/data/test.pcap"])
        processor.add_result(create_pcap_result("test.pcap", ips=["1.2.3.4"]))
        assert len(processor.results) == 1

    def test_get_file_summary(self):
        processor = BatchProcessor([])
        processor.add_result(create_pcap_result("file1.pcap", packet_count=100))
        processor.add_result(create_pcap_result("file2.pcap", error="Failed"))

        summaries = processor.get_file_summary()
        assert len(summaries) == 2
        assert summaries[0]["packet_count"] == 100
        assert summaries[1]["error"] == "Failed"

    def test_full_merge(self):
        processor = BatchProcessor([])
        processor.add_result(create_pcap_result(
            "file1.pcap",
            ips=["1.2.3.4", "5.6.7.8"],
            domains=["evil.com"],
            packet_count=100,
        ))
        processor.add_result(create_pcap_result(
            "file2.pcap",
            ips=["1.2.3.4", "9.10.11.12"],
            domains=["evil.com"],
            packet_count=200,
        ))

        result = processor.merge_all()
        assert result.summary["total_files"] == 2
        assert result.summary["successful"] == 2
        assert result.summary["total_packets"] == 300
        assert result.summary["shared_ip_count"] == 1  # 1.2.3.4
        assert result.summary["shared_domain_count"] == 1  # evil.com
