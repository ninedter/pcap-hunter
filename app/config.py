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

# Model context-window control. At most half of the selected window is used for
# prompt + evidence so providers do not need to compress the request context.
LLM_CONTEXT_WINDOW_MIN = 10_000
LLM_CONTEXT_WINDOW_MAX = 1_000_000
LLM_CONTEXT_WINDOW_STEP = 1_000
LLM_CONTEXT_WINDOW_DEFAULT = 32_000
LLM_INPUT_BUDGET_RATIO = 0.5

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
# Packet-parse cap. PipelineOptions.pyshark_packet_limit=None resolves to this value;
# 0 (or any value <= 0) is the explicit "no limit" request.
DEFAULT_PYSHARK_LIMIT = 200000
PRECNT_DEFAULT = True

# Zeek log handling. Analyzers (DNS / TLS / domain merge) receive up to
# ZEEK_ANALYSIS_MAX_ROWS rows per log; only the first ZEEK_DISPLAY_ROWS rows are kept
# for display / persistence. Zeek logs are chronological, so any truncation drops the
# END of the capture — it is always reported as a capture-metrics limitation.
ZEEK_ANALYSIS_MAX_ROWS = 200_000  # 0 = no cap (memory grows with the log)
ZEEK_DISPLAY_ROWS = 2000
# Logs collected from the Zeek output dir when present. The first four are the
# long-standing set; the rest are optional extras exposed under their own names.
ZEEK_LOG_NAMES = (
    "conn.log",
    "dns.log",
    "http.log",
    "ssl.log",
    "files.log",
    "notice.log",
    "weird.log",
    "x509.log",
)

# OSINT Top-N default (0 = all public IPs)
OSINT_TOP_IPS_DEFAULT = 50
OSINT_CACHE_TTL_HOURS = 24  # OSINT response cache TTL
# Domains queried per OSINT run (0 = all). Domains flagged by DNS analysis go first.
OSINT_MAX_DOMAINS_DEFAULT = 100
# Rate-limit / transient-failure handling, applied per provider.
OSINT_MAX_RETRIES = 2  # extra attempts after a 429 / 5xx answer
OSINT_BACKOFF_BASE_SECONDS = 1.0  # exponential: base * 2**attempt
OSINT_RETRY_AFTER_MAX_SECONDS = 30.0  # longest Retry-After we will sleep for
OSINT_BREAKER_THRESHOLD = 3  # consecutive throttled/5xx indicators before a provider is skipped
# Total seconds one provider may make an enrichment run wait in retry backoff. A provider
# that alternates successes with throttling never reaches the consecutive-failure
# threshold; once this budget is used up it is skipped for the rest of the run.
OSINT_PROVIDER_SLEEP_BUDGET_SECONDS = 120.0
OSINT_SLEEP_SLICE_SECONDS = 0.5  # backoff sleeps are sliced so a skip request is noticed

# Parallel pipeline
# NOTE: informational only — see "Informational constants" at the bottom of this file.
PARALLEL_PARSE_ENABLED = True  # Run PyShark + Zeek in parallel
MAX_PARALLEL_WORKERS = 3  # Max worker threads for pipeline stages

# Subprocess wall-clock timeouts (seconds). A malformed PCAP must never hang the pipeline.
ZEEK_TIMEOUT_SECONDS = 600
PYSHARK_TIMEOUT_SECONDS = 900  # tshark field pass; sized for a 200K-packet parse on slow disks
PCAP_COUNT_TIMEOUT_SECONDS = 120
CARVE_TIMEOUT_SECONDS = 300
TLS_EXTRACT_TIMEOUT_SECONDS = 300
LLM_PROBE_TIMEOUT_SECONDS = 15.0  # test_connection / fetch_models quick probes

# Per-flow cap on stored packet timestamps/lengths. Beacon statistics are stable far
# below this; keep-first preserves true inter-arrival deltas (sampling would not).
MAX_FLOW_SAMPLES = 5000

# Reverse DNS
RDNS_CACHE_TTL_HOURS = 168  # 7 days
RDNS_MAX_WORKERS = 10  # Concurrent rDNS lookups

# Batch processing
BATCH_MAX_FILES = 50
BATCH_MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB per file
BATCH_MAX_TOTAL_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB total

# ---- Detection Thresholds ----
# Intended as the single place for analyst tuning. NOTE: most of the constants in
# this block are currently informational only (the detector modules hard-code their
# own live values) — see "Informational constants" at the bottom of this file.

# DNS Analysis
DGA_ENTROPY_THRESHOLD = 4.0  # Shannon entropy above this → DGA suspect
FAST_FLUX_IP_THRESHOLD = 10  # Domain resolving to 10+ IPs → fast flux
NXDOMAIN_RATIO_THRESHOLD = 0.3  # NXDOMAIN ratio above this → suspicious
DNS_TUNNEL_SUBDOMAIN_LEN = 40  # Average subdomain length above this → tunneling

# Beacon / C2 Detection
BEACON_SCORE_THRESHOLD = 0.6  # Score above this → beacon candidate
BEACON_MIN_PACKETS = 4  # Minimum packets to evaluate for beaconing
BEACON_TOP_N = 20  # Number of top beacon candidates to report

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

# ---- Informational constants (declared, but NOT read by any code path) ----
# The names below document intended defaults, but nothing in ``app/`` reads them
# today. The live values are hard-coded in the modules listed, so editing a constant
# here does NOT change detector or pipeline behaviour. They are kept (not deleted)
# because docs and external tooling reference them; wire them in the owning module
# before relying on them.
#
#   DGA_ENTROPY_THRESHOLD, FAST_FLUX_IP_THRESHOLD,
#   NXDOMAIN_RATIO_THRESHOLD, DNS_TUNNEL_SUBDOMAIN_LEN
#       -> live values: app/pipeline/dns_analysis.py (it defines its own
#          NXDOMAIN_RATIO_THRESHOLD and *_SCORE_THRESHOLD constants)
#   BEACON_SCORE_THRESHOLD, BEACON_MIN_PACKETS, BEACON_TOP_N
#       -> live values: app/pipeline/beacon.py; top_n is passed by app/pipeline/runner.py
#   FLOW_ASYMMETRY_RATIO, FLOW_ASYMMETRY_MIN_BYTES
#       -> live values: app/analysis/flow_analysis.py
#   IOC_PRIORITY_CRITICAL, IOC_PRIORITY_HIGH, IOC_PRIORITY_MEDIUM
#       -> live values: app/analysis/ioc_scorer.py
#   FEATURE_YARA_ENABLED, FEATURE_PDF_ENABLED, FEATURE_OSINT_ENABLED, FEATURE_ZEEK_ENABLED
#       -> stages are gated by PipelineOptions / UI toggles, not by these flags
#   PARALLEL_PARSE_ENABLED, MAX_PARALLEL_WORKERS
#       -> app/pipeline/runner.py always parallelises and sizes its own pools
#
# C2_SUSPECT_PORTS is the exception in the thresholds block: it IS read
# (app/threat_intel/attack_mapping.py).
INFORMATIONAL_ONLY_CONSTANTS = (
    "DGA_ENTROPY_THRESHOLD",
    "FAST_FLUX_IP_THRESHOLD",
    "NXDOMAIN_RATIO_THRESHOLD",
    "DNS_TUNNEL_SUBDOMAIN_LEN",
    "BEACON_SCORE_THRESHOLD",
    "BEACON_MIN_PACKETS",
    "BEACON_TOP_N",
    "FLOW_ASYMMETRY_RATIO",
    "FLOW_ASYMMETRY_MIN_BYTES",
    "IOC_PRIORITY_CRITICAL",
    "IOC_PRIORITY_HIGH",
    "IOC_PRIORITY_MEDIUM",
    "FEATURE_YARA_ENABLED",
    "FEATURE_PDF_ENABLED",
    "FEATURE_OSINT_ENABLED",
    "FEATURE_ZEEK_ENABLED",
    "PARALLEL_PARSE_ENABLED",
    "MAX_PARALLEL_WORKERS",
)
