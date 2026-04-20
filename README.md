# PCAP Hunter

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **[繁體中文版 README (Traditional Chinese)](docs/zh-TW/README.md)**

**PCAP Hunter** is an AI-enhanced threat hunting workbench that bridges manual packet analysis and automated security monitoring. It empowers SOC analysts and threat hunters to rapidly ingest, analyze, and extract actionable intelligence from raw PCAP files.

By combining industry-standard network analysis tools (**Zeek**, **Tshark**, **PyShark**) with **Large Language Models (LLMs)** and **OSINT** APIs, PCAP Hunter automates the tedious parts of packet analysis — parsing, correlation, and enrichment — so analysts can focus on detection and response.

📖 **[User Manual (English)](docs/en/USER_MANUAL.md)** | **[中文說明 (Traditional Chinese)](docs/zh-TW/README.md)**

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Configuration](#configuration)
- [Docker](#docker)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

---

## Key Features

### AI-Powered Threat Analysis
- **Automated Reporting** — Generates professional, SOC-ready threat reports with severity-calibrated assessments, false-positive awareness, and structured analysis workflow (Characterize → Identify → Assess → Recommend).
- **Local & Cloud LLM Support**
  - **Local Privacy**: Fully compatible with [LM Studio](https://lmstudio.ai/) (Llama 3, Mistral, etc.) for air-gapped or privacy-sensitive environments.
  - **Cloud Power**: Supports any OpenAI-compatible API endpoint for leveraging larger models.
- **Multi-Language Reports** — 9 languages with region-specific terminology: English, Traditional Chinese (Taiwan), Simplified Chinese, Japanese, Korean, Italian, Spanish, French, German.
- **MITRE ATT&CK Mapping** — Automated mapping of detected behaviors and IOCs to ATT&CK techniques and Kill Chain phases.
- **Attack Narrative Synthesis** — Translates raw events into a coherent, actionable security story.

### IOC Priority Scoring
- **Tiered Signal Architecture** — Dynamically ranks indicators as Critical, High, Medium, or Low using a three-tier model:
  - **Tier 1 (Definitive)**: OSINT confirmations (VirusTotal, GreyNoise malicious) — any single Tier 1 hit sets a score floor.
  - **Tier 2 (Behavioral)**: C2 beaconing, flow asymmetry, DNS tunneling, DGA domains.
  - **Tier 3 (Contextual)**: AbuseIPDB, self-signed certs, expired certs, YARA matches.
- Tier 3 signals alone never exceed "medium"; corroboration from multiple tiers is required for "high" or "critical".

### Cross-Indicator Correlation Engine
- **Independence-complement formula** — Uses `1 − Π(1 − wᵢsᵢ)` (Bayesian independence model) instead of linear summation, producing diminishing returns while allowing multiple weak signals to compound meaningfully.
- **Strong-signal floors** — A confirmed VirusTotal detection automatically sets a minimum score regardless of other factors.
- Aggregates signals across all analysis modules (OSINT, beaconing, DNS, TLS, YARA, flow analysis).
- Produces composite threat scores per indicator with verdict classification (critical / high / medium / low).

### Flow Analysis & Exfiltration Detection
- **Data Exfiltration Detection** — Identifies suspicious outbound:inbound byte ratios per src/dst pair (default threshold: 10:1, minimum 1 MB).
- **Port Anomaly Detection** — Flags non-standard port usage, C2 common ports (4444, 5555, 6666, etc.), and high port pairs.

### Multi-PCAP Batch Processing
- **Multi-File Upload** — Upload and analyze multiple PCAP files simultaneously.
- **Cross-File Correlation** — Detects shared IPs, domains, and JA3 fingerprints across files.
- **Merged Dashboard** — Aggregated results with per-file detail cards and batch summary.
- **Resource Limits** — Configurable limits: 1 GB per file, 50 files max, 5 GB total.

### Parallel Pipeline Execution
- **PyShark + Zeek in parallel** — The two heaviest stages run concurrently via ThreadPoolExecutor.
- **HTTP Carving in parallel** with DNS/TLS/Beaconing analysis.
- **Tshark `-c` optimization** — Packet limit enforced at the tshark level for zero-waste I/O.

### Deep Packet Inspection & Flow Analysis
- **Multi-Engine Pipeline**: PyShark for granular inspection, Tshark for high-speed statistics.
- **Protocol Parsing**: Automatically extracts metadata for HTTP, DNS, TLS/SSL, and SMB protocols.

### Zeek Integration
- Automated Zeek execution on uploaded PCAPs — no manual CLI required.
- Parses and correlates core Zeek logs: `conn.log`, `dns.log`, `http.log`, `ssl.log`.

### Advanced DNS & TLS Forensics
- **DGA Detection** — Shannon entropy-based Domain Generation Algorithm identification.
- **DNS Tunneling** — Detects high-volume / anomalous DNS payloads.
- **Fast Flux Detection** — Identifies domains resolving to rapidly changing IP addresses.
- **JA3/JA3S Fingerprinting** — Matches TLS fingerprints against 90+ known malware signatures (Cobalt Strike, Trickbot, Emotet, QakBot, etc.).
- **Certificate Analysis** — Validates certificate chains; detects self-signed and expired certificates.

### C2 Beaconing Detection
- Statistical algorithm scoring flows based on:
  - **Periodicity** — Regularity of communication intervals (CV + entropy scoring).
  - **Jitter** — Modal interval analysis with ±20% tolerance for detecting randomized C2.
  - **Volume** — Packet count and payload size consistency.
- **False-Positive Reduction** — Multi-layered penalties to prevent benign traffic from triggering alerts:
  - Infrastructure allowlist (DNS resolvers: 1.1.1.1, 8.8.8.8, etc.)
  - Protocol awareness (ICMP, NTP, mDNS, SSDP, IGMP are inherently periodic)
  - Service port penalties (HTTPS, IMAPS, Apple Push, MQTT, SIP)
  - High-volume large-payload filtering (streaming/downloads vs. C2)

### Payload Carving & YARA Scanning
- **HTTP Payload Extraction** via `tshark` with automatic SHA256 hashing.
- **YARA Scanner** — Scan carved files with custom/community YARA rules.
- **Safe Storage** — Quarantined directory with path traversal and symlink protection.

### Interactive Dashboard & World Map
- **Threat Summary Panel** — At-a-glance risk level (Critical/High/Medium/Low) with corroboration-based escalation, alert count, beacon candidates, YARA hits, and certificate issues.
- **World Map** — Threat-level coloring, connectivity arcs with volume-based thickness, configurable home location.
- **Cross-Filtering** — Unified drill-down across Map, Protocol Pie Chart, and Flow Timeline.
- **Persistent View Options** — "Exclude Private IPs" toggle persists during interactive exploration.
- **TopN Charts** — Top IPs, Ports, Protocols, Domains with aggregated bar charts, metrics, and **reverse DNS hostnames**.
- **Dashboard Detections** — Beaconing candidates, YARA matches, and TLS certificate risks surfaced directly on the dashboard.
- **Network Communication Graph** — Force-directed graph with threat-colored nodes and equal-aspect-ratio rendering.

### OSINT Enrichment
Integrates with leading threat intelligence providers:
- **VirusTotal** — File hash and IP/Domain reputation.
- **AbuseIPDB** — Crowdsourced IP abuse reports.
- **GreyNoise** — Internet background noise and scanner identification.
- **OTX (AlienVault)** — Open Threat Exchange pulses and indicators.
- **Shodan** — Internet-facing device details and open ports.
- **Smart Caching** — SQLite-backed caching with configurable TTL to preserve API quotas.
- **Bulk Reverse DNS** — Parallel rDNS resolution for all public IPs with 7-day SQLite cache. Hostnames displayed throughout the dashboard.

### Case Management System
- Create, track, and close investigation cases.
- Store IOCs (IP, Domain, Hash, JA3, URL) with severity and context.
- Investigation notes, tag-based organization, and search.

### Professional PDF Export
- Multi-page PDF reports with executive summary, key findings, technical analysis, and recommendations.
- Chart/visualization embedding via WeasyPrint.
- Configurable TLP classification.

### Export Formats
- **CSV / JSON** — Export any data table with CSV injection protection.
- **STIX 2.0/2.1** — Export indicators in standard STIX format.
- **ATT&CK Navigator** — Export technique mappings for MITRE ATT&CK Navigator.

---

## Architecture

```
app/
├── analysis/        # Correlation engine, flow analysis, IOC scorer, narrator
├── database/        # Case management (SQLite)
├── llm/             # LLM client & multi-language report generation
├── pipeline/        # 10-stage analysis pipeline
│   ├── beacon.py    # C2 beaconing detection
│   ├── carve.py     # HTTP payload carving
│   ├── dns_analysis.py  # DGA, tunneling, fast flux
│   ├── geoip.py     # GeoIP resolution
│   ├── ja3.py       # JA3/JA3S fingerprinting
│   ├── batch.py     # Multi-PCAP batch processing & correlation
│   ├── osint.py     # OSINT provider queries (parallel)
│   ├── osint_cache.py   # SQLite OSINT caching layer
│   ├── rdns_cache.py    # SQLite reverse-DNS caching layer
│   ├── tls_certs.py # Certificate validation
│   └── yara_scan.py # YARA rule scanning
├── reports/         # PDF report generation
├── security/        # OPSEC hardening & data sanitization
├── threat_intel/    # MITRE ATT&CK mapping
├── ui/              # Streamlit interface (8 tabs)
├── utils/           # Export, GeoIP, config, binary discovery, network utils
├── config.py        # Application defaults
└── main.py          # Streamlit entry point
```

### Analysis Pipeline (10 Stages)

1. **Packet Counting** — Fast preliminary count via tshark
2. **Packet Parsing** — Deep inspection up to 200,000 packets (configurable)
3. **Zeek Processing** — Automated Zeek execution and log parsing
4. **DNS Analysis** — DGA, tunneling, fast flux, NXDOMAIN, query velocity
5. **TLS Certificate Analysis** — Chain validation, self-signed/expired detection
6. **Beaconing Ranking** — Temporal pattern analysis for C2 detection
7. **HTTP Carving** — Payload extraction with SHA256 hashing
8. **YARA Scanning** — Rule-based file scanning
9. **OSINT Enrichment** — Multi-provider reputation lookup
10. **LLM Report Generation** — AI-powered threat synthesis

---

## Installation

### Prerequisites

PCAP Hunter has **hard dependencies** on system binaries — the pipeline cannot parse
packets without them. The `make install` target now installs both system and Python
dependencies automatically, and verifies them afterwards.

| Tool | Required? | Purpose |
|------|-----------|---------|
| **Python 3.10+** | required | Runtime |
| **Tshark** (Wireshark) | required | Packet parsing — the pipeline silently produces empty results without it |
| **Capinfos** (Wireshark) | required | Fast packet counting (ships with tshark) |
| **Zeek** | required | Protocol analysis (conn.log, dns.log, http.log, ssl.log) |
| **YARA** | optional | Rule-based scanning of carved files |
| **Pango** | required for PDF | WeasyPrint PDF report generation |
| **LM Studio** | optional | Local LLM ([lmstudio.ai](https://lmstudio.ai/)) |

### Install (recommended)

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
make install           # installs system deps + python deps + runs dependency check
```

### Install (manual)

```bash
# macOS
brew install wireshark zeek yara pango
make install-python

# Debian / Ubuntu
sudo apt install -y tshark zeek yara libpango1.0-dev libpcap0.8
make install-python
```

### Verifying your install

```bash
make doctor    # runs scripts/check_dependencies.py and reports status
```

The app also runs this check at startup and shows a red banner at the top of every
page if any required binary is missing — you'll never get a silently empty dashboard.

---

## Quick Start

```bash
make run
```

Open `http://localhost:8501` in your browser.

---

## Usage Guide

1. **Upload** — Drag and drop one or more `.pcap` files in the Upload tab. Multiple files trigger batch mode with cross-file correlation.
2. **Configure** — Set your LLM endpoint, home location (Continent > Country > City), and OSINT API keys in the Config tab.
3. **Analyze** — Click **Extract & Analyze** to start the pipeline.
4. **Monitor** — Watch the Progress tab as stages execute: Packet Counting > Parsing > Zeek > DNS/TLS > Beaconing > Carving > YARA > OSINT > LLM Report.
5. **Review** — Explore results across Dashboard, LLM Analysis, OSINT, Raw Data, and Cases tabs.
6. **Export** — Download CSV/JSON data, PDF reports, STIX bundles, or ATT&CK Navigator layers.

### Re-run Reports

Changed your LLM model or language? Click **Re-run Report** to regenerate only the AI report without re-processing the entire PCAP.

### Data Management

Use the granular **Clear** buttons in Config to independently wipe PCAP data, OSINT cache, or the Cases database.

---

## Configuration

Defaults are managed in `app/config.py` and persisted to `.pcap_hunter_config.json`.

| Setting | Default | Description |
|---------|---------|-------------|
| `LM_BASE_URL` | `http://localhost:1234/v1` | LLM API endpoint |
| `LM_MODEL` | `local` | Model identifier |
| `LM_LANGUAGE` | `US English` | Report language |
| `DEFAULT_PYSHARK_LIMIT` | `200,000` | Max packets for deep inspection |
| `OSINT_TOP_IPS_DEFAULT` | `50` | Number of top IPs to enrich (0 = all) |
| `OSINT_CACHE_ENABLED` | `True` | SQLite caching for OSINT results |
| `PARALLEL_PARSE_ENABLED` | `True` | Run PyShark + Zeek in parallel |
| `RDNS_CACHE_TTL_HOURS` | `168` (7 days) | Reverse DNS cache TTL |
| `BATCH_MAX_FILES` | `50` | Max files in multi-PCAP batch |
| `DATA_DIR` | `./data` | Storage for analysis artifacts |

### OSINT API Keys

Set via the Config tab or environment variables:

```bash
export OTX_KEY="your-key"
export VT_KEY="your-key"
export ABUSEIPDB_KEY="your-key"
export GREYNOISE_KEY="your-key"
export SHODAN_KEY="your-key"
```

---

## Docker

```bash
docker build -t pcap-hunter .
docker run -p 8501:8501 pcap-hunter
```

The Docker image includes Zeek and Tshark pre-installed. Mount a volume for persistent data:

```bash
docker run -p 8501:8501 -v $(pwd)/data:/app/data pcap-hunter
```

---

## Development

```bash
make test       # Run tests with coverage
make lint       # Lint with Ruff
make format     # Format code with Ruff
make clean      # Clean caches
```

### macOS Capture Permissions

```bash
make fix-permissions
```

### CI/CD

GitHub Actions runs on every push/PR to `main`:
- Python 3.11 test suite with coverage
- Ruff linting and format check

---

## Documentation

- [User Manual (English)](docs/en/USER_MANUAL.md)
- [使用手冊 (繁體中文)](docs/zh-TW/USER_MANUAL.md)
- [Changelog](CHANGELOG.md)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2025 ninedter
