# PCAP Hunter

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **[繁體中文版 README (Traditional Chinese)](docs/zh-TW/README.md)**

**PCAP Hunter** is an AI-enhanced threat hunting workbench that bridges manual packet analysis and automated security monitoring. It empowers SOC analysts and threat hunters to rapidly ingest, analyze, and extract actionable intelligence from raw PCAP files.

By combining industry-standard network analysis tools (**Zeek**, **Tshark**, **PyShark**) with **Large Language Models (LLMs)** and **OSINT** APIs, PCAP Hunter automates the tedious parts of packet analysis — parsing, correlation, and enrichment — so analysts can focus on detection and response.

📖 **[User Manual (English)](docs/en/USER_MANUAL.md)** | **[中文說明 (Traditional Chinese)](docs/zh-TW/README.md)**

---

## Table of Contents

- [Visual Tour](#visual-tour)
- [Key Features](#key-features)
- [Integrations API](#integrations-api)
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

## Visual Tour

### 1. Upload — load one or many PCAPs

Drag-and-drop a `.pcap` / `.pcapng` file (up to 200 MB each) or paste a container path.
Multiple files trigger batch mode with cross-file correlation.

![Upload tab](docs/images/01-upload.png)

### 2. Progress — transparent 10-stage pipeline

Every stage of the analysis pipeline reports live progress with a skippable per-stage
control. You always know what's running and how far it has to go.

![Progress tab](docs/images/02-progress.png)

### 3. Dashboard — at-a-glance threat summary

The Dashboard surfaces the highest-signal findings first: overall risk level, alert
count, beacon candidates, YARA hits, and certificate issues. A global traffic map,
protocol distribution, and activity timeline put the capture in visual context.

![Dashboard tab](docs/images/03-dashboard.png)

### 4. LLM Analysis — AI-generated threat report

An 8-section narrative (Executive Summary → Key Findings → Indicators & Evidence →
OSINT Corroboration → Beaconing / C2 → DNS & TLS → Risk Assessment → Recommended
Actions) with confidence qualifiers and MITRE ATT&CK mapping, generated locally
via LM Studio or any OpenAI-compatible endpoint.

![LLM Analysis tab](docs/images/04-llm-analysis.png)

### 5. OSINT — multi-provider IOC enrichment

Prioritized IOC table with VirusTotal, AbuseIPDB, GreyNoise, Shodan, OTX, and
VT Domain signals merged into one view. Sub-tabs expose Domains, Detail Cards,
Geo Map, Infrastructure ASN clustering, Export, Devices, and Notes.

![OSINT tab](docs/images/05-osint.png)

### 6. Raw Data — Zeek logs, flows, carved payloads, YARA matches

Every underlying data source is available: flow table, DNS and TLS analyses,
NXDOMAIN analysis, JA3/JA3S fingerprints, Zeek `conn.log`/`dns.log`/`http.log`/
`ssl.log`, carved HTTP payloads, and YARA scan results. Export any view as CSV
or JSON with CSV-injection protection.

![Raw Data tab](docs/images/06-raw-data.png)

### 7. Cases — persistent investigation tracking

Promote any capture and its findings into a case. Cases carry IOCs, severity, tags,
investigation notes, status, and search — stored in a local SQLite database.

![Cases tab](docs/images/07-cases.png)

### 8. API Keys — manage programmatic access

Create, revoke, and monitor API keys for the Integrations API. Each key has its own
scope (full or feed-only), optional expiration, per-key rate limits, and a usage
sparkline. Environment-variable keys are shown as read-only bootstrap entries.

### 9. Config — centralized settings

LLM endpoint, API keys (PBKDF2-encrypted at rest), home location for the world map,
OSINT provider toggles, binary paths, and pipeline thresholds — all in one place
with per-section clear buttons.

![Config tab](docs/images/08-config.png)

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
  - Infrastructure allowlist (major public DNS resolvers)
  - Protocol awareness (ICMP, NTP, mDNS, SSDP, IGMP are inherently periodic)
  - Service port penalties (HTTPS, IMAPS, Apple Push, MQTT, SIP)
  - High-volume large-payload filtering (streaming/downloads vs. C2)

### Payload Carving & YARA Scanning
- **HTTP Payload Extraction** via `tshark` with automatic SHA256 hashing.
- **YARA Scanner** — Scan carved files with custom/community YARA rules.
- **Safe Storage** — Quarantined directory with path traversal and symlink protection.

### Integrations API (REST)
- **PCAP Ingestion** — `POST /api/v1/pcaps` accepts multipart uploads, queues background analysis, and returns a job ID for polling.
- **Job Tracking** — `GET /api/v1/jobs/{id}` returns stage-level progress, percent complete, and timestamps.
- **IOC Feed Egress** — Pull extracted indicators as JSON, CSV, or STIX 2.1 with ETag caching, cursor pagination, and score/type/date filters.
- **Case Retrieval** — `GET /api/v1/cases/{id}` and PDF report download.
- **DB-Backed API Key Management** — Create, revoke, and rotate keys via admin endpoints or the Streamlit API Keys tab. Each key carries a scope (full / feed-only), optional expiration, and per-key rate limit.
- **Backward-Compatible Auth** — Environment-variable keys (`PCAP_HUNTER_API_KEY`, `PCAP_HUNTER_FEED_KEY`) still work as bootstrap/fallback alongside DB keys.
- **RFC 7807 Errors** — All error responses use `application/problem+json` with request-ID tracing.
- **Ops-Ready** — Health/readiness endpoints, hourly GC sweep, request audit logging, CORS allowlist.

> Full endpoint reference, curl examples, and SIEM integration guides: **[docs/API.md](docs/API.md)**

### Interactive Dashboard & World Map
- **Threat Summary Panel** — At-a-glance risk level (Critical/High/Medium/Low) with corroboration-based escalation, alert count, beacon candidates, YARA hits, and certificate issues.
- **World Map** — Threat-level coloring, connectivity arcs with volume-based thickness, configurable home location.
- **Cross-Filtering** — Unified drill-down across Map, Protocol Pie Chart, and Flow Timeline.
- **Persistent View Options** — "Exclude Private IPs" toggle persists during interactive exploration.
- **TopN Charts** — Top IPs, Ports, Protocols, Domains with aggregated bar charts, metrics, and **reverse DNS hostnames**.
- **Dashboard Detections** — Beaconing candidates, YARA matches, and TLS certificate risks surfaced directly on the dashboard.
- **Severity Legend & UTC Timestamps** — One-line severity color legend for at-a-glance calibration; flow time-series axes are explicitly labeled UTC.
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
- **Embedded dashboard charts** — protocol distribution, top talkers, flow timeline, network graph, world map — rendered to PNG via kaleido for static handoff.
- Configurable TLP classification and analyst metadata.

### Export Formats
- **CSV / JSON** — Export any data table with CSV injection protection.
- **STIX 2.0/2.1** — Export indicators in standard STIX format.
- **ATT&CK Navigator** — Export technique mappings for MITRE ATT&CK Navigator.
- **CEF (ArcSight)** — SIEM-ingestible events from correlations, beacons, DNS, and IOCs.

---

## Integrations API

PCAP Hunter ships a FastAPI-based REST API alongside the Streamlit UI so SOAR platforms, SIEM systems, and custom scripts can submit PCAPs and consume IOCs programmatically.

```bash
# Start the API server (port 8000)
PCAP_HUNTER_API_KEY=changeme uvicorn app.api.app:create_app --factory --host 0.0.0.0 --port 8000

# Submit a PCAP for analysis
curl -X POST http://localhost:8000/api/v1/pcaps \
  -H "Authorization: Bearer changeme" \
  -F "pcap=@capture.pcap" \
  -F "name=Suspicious traffic"

# Poll job status
curl http://localhost:8000/api/v1/jobs/j_abc123 \
  -H "Authorization: Bearer changeme"

# Pull IOC feed (JSON)
curl "http://localhost:8000/api/v1/iocs.json?min_score=50" \
  -H "Authorization: Bearer changeme"
```

The API reuses the same 10-stage pipeline, SQLite case database, and configuration as the Streamlit app. Submissions create regular Cases visible in both interfaces.

> Complete endpoint reference, authentication guide, SIEM integration examples, and configuration: **[docs/API.md](docs/API.md)**

---

## Architecture

```
app/
├── analysis/        # Correlation engine, flow analysis, IOC scorer, narrator
├── api/             # FastAPI integrations API (REST endpoints, auth, key mgmt)
│   ├── routers/     # health, pcaps, jobs, cases, iocs, admin
│   ├── key_auth.py  # DB + env-var authentication pipeline
│   ├── key_repository.py  # SQLite API key store
│   ├── rate_limiter.py    # Sliding-window per-key rate limiter
│   └── worker.py    # Background pipeline execution (ProcessPoolExecutor)
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
├── reports/         # PDF report generation (WeasyPrint + kaleido charts)
├── security/        # OPSEC hardening & data sanitization
├── threat_intel/    # MITRE ATT&CK mapping
├── ui/              # Streamlit interface (8 tabs)
├── utils/           # Export, GeoIP, config, binary discovery, CEF
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
packets without them. The installer handles both system and Python dependencies,
and verifies everything afterwards.

| Tool | Required? | Purpose |
|------|-----------|---------|
| **Python 3.10+** | required | Runtime |
| **Tshark** (Wireshark) | required | Packet parsing |
| **Capinfos** (Wireshark) | required | Fast packet counting (ships with tshark) |
| **Zeek** | required | Protocol analysis (conn.log, dns.log, http.log, ssl.log) |
| **YARA** | optional | Rule-based scanning of carved files |
| **Pango + glib + cairo** | required for PDF | WeasyPrint PDF report generation |
| **LM Studio** | optional | Local LLM ([lmstudio.ai](https://lmstudio.ai/)) |

### One command, any platform

All install logic lives in a single cross-platform Python script
(`scripts/install.py`) that detects your OS and package manager automatically.

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
python3 scripts/install.py
```

This works identically on **macOS** (uses `brew`), **Linux** (uses `apt`), and
**Windows** (uses `winget` → `choco` → `scoop` in that order). It installs
system binaries, installs Python packages, and runs the dependency check.

### Idiomatic per-platform wrappers

Prefer your platform's usual workflow? Use one of these — they all delegate to
the same `install.py`:

| Platform | Command | What it does |
|----------|---------|--------------|
| macOS / Linux | `make install` | wrapper around `python3 scripts/install.py` |
| Windows (PowerShell) | `.\scripts\install.ps1` | bootstraps Python if missing, then delegates |
| Any platform | `python3 scripts/install.py` | the canonical entry point |
| Docker | `docker compose up --build` | all deps baked into the image |

### Installer flags

```
python3 scripts/install.py              # full install + verification
python3 scripts/install.py --check-only # just run the dependency checker
python3 scripts/install.py --skip-system # pip only
python3 scripts/install.py --skip-python # system binaries only
python3 scripts/install.py --dry-run    # preview commands without executing
python3 scripts/install.py --yes        # non-interactive (assume yes)
```

### Windows notes

**Zeek has no native Windows build.** Native Windows installs will work for the
tshark pipeline but skip the Zeek protocol-analysis stage. For the complete
pipeline on Windows, use:

- **Docker** (simplest) — `docker compose up --build`
- **WSL2** — `wsl --install -d Ubuntu`, then run `python3 scripts/install.py` inside Ubuntu

### Verifying your install

```bash
make doctor                              # macOS / Linux
python3 scripts/install.py --check-only  # any OS (including Windows)
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
6. **Export** — Download CSV/JSON data, PDF reports, STIX bundles, ATT&CK Navigator layers, or CEF syslog events.

### Re-run Reports

Changed your LLM model or language? Click **Re-run Report** to regenerate only the AI report without re-processing the entire PCAP.

### Data Management

Use the granular **Clear** buttons in Config to independently wipe PCAP data, OSINT cache, or the Cases database.

---

## Configuration

- Defaults in `app/config.py` (thresholds, paths, URLs)
- Persistent config in `~/.pcap_hunter_config.json` (encrypted by `ConfigManager`)
- API keys encrypted at rest with machine-derived PBKDF2 key
- Environment-variable overrides: `OTT_KEY`, `VT_KEY`, `SHODAN_KEY`, etc.
- LLM defaults: `http://localhost:1234/v1` (LM Studio)

### Key Thresholds

| Setting | Default | Purpose |
|---------|---------|---------|
| DGA entropy | 4.0 bits | Shannon entropy threshold for DGA detection |
| Fast flux | 10+ IPs | Minimum distinct IPs per domain |
| Flow asymmetry | 10:1 + ≥1 MB | Exfil candidate threshold |
| C2 common ports | 4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337 | Port-anomaly match list |
| PyShark limit | 200,000 packets | Deep-parse cap |

---

## Docker

The bundled `Dockerfile` ships tshark, zeek, libpcap, and all Python deps baked in — the simplest path to a fully-working environment.

```bash
docker compose up --build
# → http://localhost:8501
```

---

## Development

### Pre-commit gate — `make verify`

```bash
make verify     # format check + lint + full test suite
```

Required before every commit. CI runs the same three steps, so `make verify` passing locally means CI will pass too.

### Other make targets

```bash
make test          # pytest with coverage
make test-pdf      # focused PDF + chart test suite
make lint          # ruff check
make format        # ruff format
make doctor        # dependency verification
make clean         # remove caches
```

### Regenerate README screenshots

```bash
python3 scripts/capture_screenshots.py        # captures all 8 tabs, auto-redacts IPs
python3 scripts/capture_screenshots.py --redact-only   # re-run OCR redaction on existing PNGs
python3 scripts/capture_screenshots.py --keep-ips      # keep IPs (internal use only)
```

The capture script uses Playwright headless Chromium, drives the UI, and runs a two-pass IP redaction: DOM-aware bounding-box extraction first, then multi-PSM tesseract OCR for any IPs rendered into canvas (Streamlit's `st.dataframe`). After redaction it auto-crops trailing whitespace and any post-content duplicate render so README screenshots stay tight to actual content.

### Testing discipline

PCAP Hunter uses **production-shape test data**, not simplified inputs. See `tests/test_pdf_integration.py` for the canonical pattern — real `CorrelationSignal` dataclasses, real pandas DataFrames, and the nested dict shapes the pipeline actually produces. When adding a new PDF section or chart, extend the corresponding integration test.
---

## Documentation

- **[User Manual (English)](docs/en/USER_MANUAL.md)** — end-user guide
- **[Integrations API Reference](docs/API.md)** — REST endpoints, authentication, SIEM integration
- **[中文說明 (Traditional Chinese)](docs/zh-TW/README.md)** — 繁體中文版
- **[CLAUDE.md](CLAUDE.md)** — contributor/AI guide: conventions, testing discipline, known bug patterns
- **[docs/roadmap.md](docs/roadmap.md)** — planned work

---

## License

[MIT License](LICENSE) — see file for details.
