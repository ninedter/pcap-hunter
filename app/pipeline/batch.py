"""Multi-PCAP batch processing with cross-file correlation.

Provides functionality to:
- Process multiple PCAP files in sequence
- Correlate IPs, domains, and artifacts across files
- Aggregate timeline data
- Generate merged reports
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# --- Constants ---
MAX_COMMON_INDICATORS = 100
MAX_BEACON_CANDIDATES = 50
MAX_DGA_RESULTS = 50
MAX_TUNNELING_RESULTS = 20
MAX_FAST_FLUX_RESULTS = 20
MAX_CERTIFICATES = 100


@dataclass
class PCAPResult:
    """Results from a single PCAP analysis."""

    path: str
    filename: str
    features: dict[str, Any] = field(default_factory=dict)
    zeek_tables: dict[str, pd.DataFrame] = field(default_factory=dict)
    osint: dict[str, Any] = field(default_factory=dict)
    beacon_df: pd.DataFrame | None = None
    dns_analysis: dict[str, Any] = field(default_factory=dict)
    tls_analysis: dict[str, Any] = field(default_factory=dict)
    packet_count: int = 0
    error: str | None = None


@dataclass
class CorrelationResult:
    """Cross-file correlation results."""

    # Entities seen across multiple files
    shared_ips: dict[str, list[str]]  # IP -> list of filenames
    shared_domains: dict[str, list[str]]  # domain -> list of filenames
    shared_ja3: dict[str, list[str]]  # JA3 hash -> list of filenames

    # Aggregate statistics
    total_packets: int
    total_flows: int
    total_unique_ips: int
    total_unique_domains: int

    # Timeline data
    time_range: tuple[float, float] | None  # earliest, latest timestamp

    # High-value indicators
    common_indicators: list[dict[str, Any]]  # Indicators in 2+ files


def correlate_results(results: list[PCAPResult]) -> CorrelationResult:
    """
    Correlate analysis results across multiple PCAP files.

    Args:
        results: List of PCAPResult from individual analyses

    Returns:
        CorrelationResult with cross-file correlations
    """
    # Track which files contain each entity
    ip_files: dict[str, list[str]] = defaultdict(list)
    domain_files: dict[str, list[str]] = defaultdict(list)
    ja3_files: dict[str, list[str]] = defaultdict(list)

    total_packets = 0
    total_flows = 0
    all_ips = set()
    all_domains = set()
    earliest_ts = None
    latest_ts = None

    for r in results:
        if r.error:
            continue

        filename = r.filename

        # Extract IPs
        artifacts = r.features.get("artifacts", {})
        ips = artifacts.get("ips", [])
        for ip in ips:
            ip_files[ip].append(filename)
            all_ips.add(ip)

        # Extract domains
        domains = artifacts.get("domains", [])
        for domain in domains:
            domain_files[domain].append(filename)
            all_domains.add(domain)

        # Extract JA3
        ja3_hashes = artifacts.get("ja3", [])
        for ja3 in ja3_hashes:
            ja3_files[ja3].append(filename)

        # Count packets and flows
        total_packets += r.packet_count
        flows = r.features.get("flows", [])
        total_flows += len(flows)

        # Track time range
        for flow in flows:
            pkt_times = flow.get("pkt_times", [])
            if pkt_times:
                flow_min = min(pkt_times)
                flow_max = max(pkt_times)
                if earliest_ts is None or flow_min < earliest_ts:
                    earliest_ts = flow_min
                if latest_ts is None or flow_max > latest_ts:
                    latest_ts = flow_max

    # Find shared entities (in 2+ files)
    shared_ips = {ip: files for ip, files in ip_files.items() if len(files) > 1}
    shared_domains = {dom: files for dom, files in domain_files.items() if len(files) > 1}
    shared_ja3 = {ja3: files for ja3, files in ja3_files.items() if len(files) > 1}

    # Build common indicators list
    common_indicators = []

    for ip, files in shared_ips.items():
        common_indicators.append(
            {
                "type": "ip",
                "value": ip,
                "files": files,
                "file_count": len(files),
            }
        )

    for domain, files in shared_domains.items():
        common_indicators.append(
            {
                "type": "domain",
                "value": domain,
                "files": files,
                "file_count": len(files),
            }
        )

    for ja3, files in shared_ja3.items():
        common_indicators.append(
            {
                "type": "ja3",
                "value": ja3,
                "files": files,
                "file_count": len(files),
            }
        )

    # Sort by file count
    common_indicators.sort(key=lambda x: x["file_count"], reverse=True)

    return CorrelationResult(
        shared_ips=shared_ips,
        shared_domains=shared_domains,
        shared_ja3=shared_ja3,
        total_packets=total_packets,
        total_flows=total_flows,
        total_unique_ips=len(all_ips),
        total_unique_domains=len(all_domains),
        time_range=(earliest_ts, latest_ts) if earliest_ts and latest_ts else None,
        common_indicators=common_indicators[:MAX_COMMON_INDICATORS],
    )


def merge_zeek_tables(results: list[PCAPResult]) -> dict[str, pd.DataFrame]:
    """
    Merge Zeek log tables from multiple PCAPs.

    Args:
        results: List of PCAPResult

    Returns:
        Dictionary of merged DataFrames by log type
    """
    merged: dict[str, list[pd.DataFrame]] = defaultdict(list)

    for r in results:
        if r.error:
            continue

        for log_name, df in r.zeek_tables.items():
            if df is not None and not df.empty:
                # Add source file column
                df_copy = df.copy()
                df_copy["_source_file"] = r.filename
                merged[log_name].append(df_copy)

    # Concatenate all DataFrames for each log type
    result = {}
    for log_name, dfs in merged.items():
        if dfs:
            result[log_name] = pd.concat(dfs, ignore_index=True)

    return result


def merge_osint(results: list[PCAPResult]) -> dict[str, Any]:
    """
    Merge OSINT results from multiple PCAPs.

    Args:
        results: List of PCAPResult

    Returns:
        Merged OSINT dictionary
    """
    merged = {
        "ips": {},
        "domains": {},
        "ja3": {},
    }

    for r in results:
        if r.error or not r.osint:
            continue

        # Merge IP data
        for ip, data in r.osint.get("ips", {}).items():
            if ip not in merged["ips"]:
                merged["ips"][ip] = data
            else:
                # Update with additional data
                merged["ips"][ip].update(data)

        # Merge domain data
        for domain, data in r.osint.get("domains", {}).items():
            if domain not in merged["domains"]:
                merged["domains"][domain] = data
            else:
                merged["domains"][domain].update(data)

        # Merge JA3 data
        for ja3, data in r.osint.get("ja3", {}).items():
            if ja3 not in merged["ja3"]:
                merged["ja3"][ja3] = data

    return merged


def merge_beacon_candidates(results: list[PCAPResult], top_n: int = 50) -> pd.DataFrame:
    """
    Merge beaconing candidates from multiple PCAPs.

    Args:
        results: List of PCAPResult
        top_n: Number of top candidates to return

    Returns:
        Merged DataFrame of beacon candidates
    """
    dfs = []

    for r in results:
        if r.error or r.beacon_df is None or r.beacon_df.empty:
            continue

        df_copy = r.beacon_df.copy()
        df_copy["_source_file"] = r.filename
        dfs.append(df_copy)

    if not dfs:
        return pd.DataFrame()

    merged = pd.concat(dfs, ignore_index=True)

    # Sort by score and take top N
    if "score" in merged.columns:
        merged = merged.sort_values("score", ascending=False).head(top_n)

    return merged


def aggregate_dns_analysis(results: list[PCAPResult]) -> dict[str, Any]:
    """
    Aggregate DNS analysis results from multiple PCAPs.

    Args:
        results: List of PCAPResult

    Returns:
        Aggregated DNS analysis dictionary
    """
    all_dga = []
    all_tunneling = []
    all_fast_flux = []
    query_types = Counter()
    total_records = 0
    all_domains = set()

    for r in results:
        if r.error or not r.dns_analysis:
            continue

        dns = r.dns_analysis

        total_records += dns.get("total_records", 0)

        # Aggregate detections (copy to avoid mutating input)
        for dga in dns.get("dga_detections", []):
            dga_copy = dict(dga)
            dga_copy["_source_file"] = r.filename
            all_dga.append(dga_copy)

        for tunnel in dns.get("tunneling_detections", []):
            tunnel_copy = dict(tunnel)
            tunnel_copy["_source_file"] = r.filename
            all_tunneling.append(tunnel_copy)

        for ff in dns.get("fast_flux_detections", []):
            ff_copy = dict(ff)
            ff_copy["_source_file"] = r.filename
            all_fast_flux.append(ff_copy)

        # Aggregate query types
        for qtype, count in dns.get("query_types", {}).items():
            query_types[qtype] += count

        # Aggregate domains
        for item in dns.get("top_queried", []):
            all_domains.add(item["domain"])

    # Sort by score
    all_dga.sort(key=lambda x: x.get("score", 0), reverse=True)
    all_tunneling.sort(key=lambda x: x.get("score", 0), reverse=True)
    all_fast_flux.sort(key=lambda x: x.get("score", 0), reverse=True)

    return {
        "total_records": total_records,
        "unique_domains": len(all_domains),
        "query_types": dict(query_types),
        "dga_detections": all_dga[:MAX_DGA_RESULTS],
        "tunneling_detections": all_tunneling[:MAX_TUNNELING_RESULTS],
        "fast_flux_detections": all_fast_flux[:MAX_FAST_FLUX_RESULTS],
        "alerts": {
            "dga_count": sum(1 for d in all_dga if d.get("is_dga")),
            "tunneling_count": sum(1 for t in all_tunneling if t.get("is_tunneling")),
            "fast_flux_count": sum(1 for f in all_fast_flux if f.get("is_fast_flux")),
        },
    }


def aggregate_tls_analysis(results: list[PCAPResult]) -> dict[str, Any]:
    """
    Aggregate TLS certificate analysis from multiple PCAPs.

    Args:
        results: List of PCAPResult

    Returns:
        Aggregated TLS analysis dictionary
    """
    all_certs = []
    seen_fingerprints = set()
    self_signed = 0
    expired = 0
    high_risk = 0

    for r in results:
        if r.error or not r.tls_analysis:
            continue

        tls = r.tls_analysis

        for cert in tls.get("certificates", []):
            fp = cert.get("fingerprint_sha256", "")
            if fp and fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                # Copy to avoid mutating input
                cert_copy = dict(cert)
                cert_copy["_source_file"] = r.filename
                all_certs.append(cert_copy)

                if cert_copy.get("is_self_signed"):
                    self_signed += 1
                if cert_copy.get("is_expired"):
                    expired += 1
                if cert_copy.get("risk_score", 0) >= 0.5:
                    high_risk += 1

    # Sort by risk score
    all_certs.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    return {
        "total_certificates": len(all_certs),
        "unique_fingerprints": len(seen_fingerprints),
        "self_signed": self_signed,
        "expired": expired,
        "high_risk": high_risk,
        "certificates": all_certs[:MAX_CERTIFICATES],
        "alerts": {
            "self_signed_count": self_signed,
            "expired_count": expired,
            "high_risk_count": high_risk,
        },
    }


@dataclass
class BatchResult:
    """Complete batch processing result."""

    pcap_results: list[PCAPResult]
    correlation: CorrelationResult
    merged_zeek: dict[str, pd.DataFrame]
    merged_osint: dict[str, Any]
    merged_beacons: pd.DataFrame
    aggregated_dns: dict[str, Any]
    aggregated_tls: dict[str, Any]
    summary: dict[str, Any]


class BatchProcessor:
    """
    Process multiple PCAP files with correlation analysis.

    Usage:
        processor = BatchProcessor(pcap_paths)
        result = processor.process_all(phase=phase)
    """

    def __init__(self, pcap_paths: list[str | Path]):
        """
        Initialize batch processor.

        Args:
            pcap_paths: List of paths to PCAP files
        """
        self.pcap_paths = [Path(p) for p in pcap_paths]
        self.results: list[PCAPResult] = []

    def add_result(self, result: PCAPResult) -> None:
        """Add a single PCAP result to the batch."""
        self.results.append(result)

    def correlate(self) -> CorrelationResult:
        """Perform cross-file correlation analysis."""
        return correlate_results(self.results)

    def merge_all(self) -> BatchResult:
        """
        Merge all results and perform correlation.

        Returns:
            BatchResult with all merged and correlated data
        """
        correlation = self.correlate()
        merged_zeek = merge_zeek_tables(self.results)
        merged_osint = merge_osint(self.results)
        merged_beacons = merge_beacon_candidates(self.results)
        aggregated_dns = aggregate_dns_analysis(self.results)
        aggregated_tls = aggregate_tls_analysis(self.results)

        # Build summary
        successful = sum(1 for r in self.results if not r.error)
        failed = len(self.results) - successful

        summary = {
            "total_files": len(self.results),
            "successful": successful,
            "failed": failed,
            "filenames": [r.filename for r in self.results],
            "total_packets": correlation.total_packets,
            "total_flows": correlation.total_flows,
            "total_unique_ips": correlation.total_unique_ips,
            "total_unique_domains": correlation.total_unique_domains,
            "shared_ip_count": len(correlation.shared_ips),
            "shared_domain_count": len(correlation.shared_domains),
            "shared_ja3_count": len(correlation.shared_ja3),
            "time_range": correlation.time_range,
            "alerts": {
                "cross_file_ips": len(correlation.shared_ips),
                "cross_file_domains": len(correlation.shared_domains),
                "dga_detections": aggregated_dns["alerts"]["dga_count"],
                "tunneling_detections": aggregated_dns["alerts"]["tunneling_count"],
                "self_signed_certs": aggregated_tls["alerts"]["self_signed_count"],
                "expired_certs": aggregated_tls["alerts"]["expired_count"],
            },
        }

        return BatchResult(
            pcap_results=self.results,
            correlation=correlation,
            merged_zeek=merged_zeek,
            merged_osint=merged_osint,
            merged_beacons=merged_beacons,
            aggregated_dns=aggregated_dns,
            aggregated_tls=aggregated_tls,
            summary=summary,
        )

    def get_file_summary(self) -> list[dict[str, Any]]:
        """Get summary for each processed file."""
        summaries = []
        for r in self.results:
            summary = {
                "filename": r.filename,
                "path": r.path,
                "packet_count": r.packet_count,
                "error": r.error,
            }

            if not r.error:
                flows = r.features.get("flows", [])
                artifacts = r.features.get("artifacts", {})
                summary.update(
                    {
                        "flow_count": len(flows),
                        "ip_count": len(artifacts.get("ips", [])),
                        "domain_count": len(artifacts.get("domains", [])),
                    }
                )

            summaries.append(summary)

        return summaries
