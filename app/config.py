from __future__ import annotations

import os
import pathlib

APP_NAME = "PCAP Threat Hunting Workbench"

# Directories — support env-var overrides for Docker/container deploys
DATA_DIR = pathlib.Path(os.getenv("PCAP_HUNTER_DATA_DIR", "data")).resolve()
CARVE_DIR = DATA_DIR / "carved"
ZEEK_DIR = DATA_DIR / "zeek"

# Each pipeline run writes Zeek logs and carved payloads into its own subdirectory
# (CARVE_DIR/<run_id>, ZEEK_DIR/<run_id>) so concurrent jobs never clobber each other.
# Run dirs older than this window are pruned at the start of the next run.
RUN_DIR_RETENTION_SECONDS = 7 * 24 * 3600  # 7 days

# LM Studio defaults
LM_BASE_URL = os.getenv("LM_BASE_URL", "http://localhost:1234/v1")
LM_API_KEY = os.getenv("LM_API_KEY", "lm-studio")
LM_MODEL = "local"
LM_LANGUAGE = "US English"
LM_TIMEOUT_SECONDS = 120  # Per-section API call timeout

# Multi-provider LLM defaults. The active provider selects which backend
# synthesize_report() dispatches to: LM Studio (local, chunked), OpenAI cloud,
# or Anthropic (official SDK). See app/llm/providers.py.
LLM_PROVIDER_DEFAULT = "lmstudio"  # one of providers.PROVIDERS
OPENAI_MODEL_DEFAULT = "gpt-4o"
ANTHROPIC_MODEL_DEFAULT = "claude-opus-4-8"

# OSINT keys (empty defaults, override with env or config UI)
OTX_KEY = os.getenv("OTX_KEY", "")
VT_KEY = os.getenv("VT_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
GREYNOISE_KEY = os.getenv("GREYNOISE_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_KEY", "")

# Allowed directories for user-supplied PCAP paths
ALLOWED_PCAP_DIRS = [DATA_DIR, pathlib.Path("pcaps").resolve(), pathlib.Path("/data").resolve()]

# Analysis defaults
DEFAULT_PYSHARK_LIMIT = 200000
PRECNT_DEFAULT = True

# OSINT Top-N default (0 = all public IPs)
OSINT_TOP_IPS_DEFAULT = 50
OSINT_CACHE_TTL_HOURS = 24  # OSINT response cache TTL

# Parallel pipeline
PARALLEL_PARSE_ENABLED = True  # Run PyShark + Zeek in parallel
MAX_PARALLEL_WORKERS = 3  # Max worker threads for pipeline stages

# Subprocess wall-clock timeouts (seconds). A malformed PCAP must never hang the pipeline.
ZEEK_TIMEOUT_SECONDS = 600
PCAP_COUNT_TIMEOUT_SECONDS = 120
CARVE_TIMEOUT_SECONDS = 300
TLS_EXTRACT_TIMEOUT_SECONDS = 300
LLM_PROBE_TIMEOUT_SECONDS = 15.0  # test_connection / fetch_models quick probes

# Per-flow cap on stored packet timestamps/lengths. Beacon statistics are stable far
# below this; keep-first preserves true inter-arrival deltas (sampling would not).
MAX_FLOW_SAMPLES = 5000

# Per-log row cap on Zeek tables held in memory/session state. DNS analysis
# and the UI preview read these capped frames, so DNS/TLS fidelity is bounded
# by this value; JA3 extraction reads the full uncapped log via zeek_log_paths.
# Raised from the old hardcoded 2000 (which silently truncated busy captures);
# still bounded to protect session-state size. A WARNING_ZEEK_TRUNCATED is
# emitted when any log exceeds it.
ZEEK_TABLE_MAX_ROWS = 50000

# Reverse DNS
RDNS_CACHE_TTL_HOURS = 168  # 7 days
RDNS_MAX_WORKERS = 10  # Concurrent rDNS lookups

# Batch processing
BATCH_MAX_FILES = 50
BATCH_MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB per file
BATCH_MAX_TOTAL_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB total

# ---- Detection Thresholds ----
# All detection thresholds centralized here for easy analyst tuning.

# DNS Analysis
DGA_ENTROPY_THRESHOLD = 4.0  # Shannon entropy above this → DGA suspect
FAST_FLUX_IP_THRESHOLD = 10  # Domain resolving to 10+ IPs → fast flux
NXDOMAIN_RATIO_THRESHOLD = 0.3  # NXDOMAIN ratio above this → suspicious
DNS_TUNNEL_SUBDOMAIN_LEN = 40  # Average subdomain length above this → tunneling

# Beacon / C2 Detection
BEACON_SCORE_THRESHOLD = 0.6  # Score above this → beacon candidate
BEACON_MIN_PACKETS = 4  # Minimum packets to evaluate for beaconing
BEACON_TOP_N = 20  # Number of top beacon candidates to report

# HTTP Analysis
HTTP_SUSPICIOUS_URI_LEN = 512  # URI length above this → suspicious (possible exfil/exploit)
HTTP_SUSPICIOUS_UA_TOKENS = frozenset(
    {
        "python-requests",
        "curl",
        "wget",
        "powershell",
        "go-http-client",
        "nmap",
        "sqlmap",
        "masscan",
    }
)

# Flow Analysis
FLOW_ASYMMETRY_RATIO = 10  # Outbound/inbound ratio above this → suspicious
FLOW_ASYMMETRY_MIN_BYTES = 1_000_000  # 1 MB minimum to flag asymmetry

# C2 Common Ports (non-standard ports that may indicate C2)
C2_SUSPECT_PORTS = frozenset({4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337})

# IOC Scoring
IOC_PRIORITY_CRITICAL = 0.8
IOC_PRIORITY_HIGH = 0.6
IOC_PRIORITY_MEDIUM = 0.4

# TShark fields to extract
TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.protocols",
    "eth.src",
    "eth.dst",
]

# ---- Feature Flags ----
# Toggle optional modules to reduce startup time or skip unavailable tools.
FEATURE_YARA_ENABLED = True
FEATURE_PDF_ENABLED = True
FEATURE_OSINT_ENABLED = True
FEATURE_ZEEK_ENABLED = True
