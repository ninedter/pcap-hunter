# PCAP Hunter

[![CI](https://github.com/ninedter/pcap-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/ninedter/pcap-hunter/actions/workflows/ci.yml)
[![Release: v2.0.0](https://img.shields.io/badge/release-v2.0.0-7c3aed.svg)](https://github.com/ninedter/pcap-hunter/releases/tag/v2.0.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **[繁體中文版 README (Traditional Chinese)](docs/zh-TW/README.md)**

**PCAP Hunter** is an AI-enhanced threat hunting workbench that bridges manual packet analysis and automated security monitoring. It empowers SOC analysts and threat hunters to rapidly ingest, analyze, and extract actionable intelligence from raw PCAP files.

By combining industry-standard network analysis tools (**Zeek**, **Tshark**, **PyShark**) with **Large Language Models (LLMs)** and **OSINT** APIs, PCAP Hunter automates the tedious parts of packet analysis — parsing, correlation, and enrichment — so analysts can focus on detection and response.

📖 **[User Manual (English)](docs/en/USER_MANUAL.md)** | **[中文說明 (Traditional Chinese)](docs/zh-TW/README.md)**

---

## What's new in version 2

- **Dedicated MITRE ATT&CK workspace** — evidence-backed technique hypotheses, ATT&CK v19.1 metadata, analyst dispositions, capture coverage, visibility gaps, and Navigator export.
- **Capture-quality telemetry** — packet/flow scale, parse ratio, time window, sampling limits, completed stages, and warnings now travel with UI and API results and persist with cases.
- **Durable UI analysis** — Streamlit now submits PCAP work to a process-backed queue, autosaves full evidence to SQLite, and restores recent jobs after a page stop or browser reload.
- **Safer PCAP intake** — Streamlit uploads are streamed in bounded chunks, preserve `.pcap`/`.pcapng`, validate magic bytes, enforce batch limits, and remove partial files after rejection.
- **Stronger Integrations API** — headless jobs return ATT&CK mappings and capture metrics, IOC feeds carry related technique IDs, readiness checks avoid starting the worker queue, and failed submissions clean up provisional cases and files.
- **Evidence without an LLM** — skipping or losing the optional AI narrative no longer hides deterministic packet, IOC, correlation, stage, and warning evidence.
- **Runtime and export reliability** — Docker adapts local LM Studio addresses to the host bridge, HTTP carving decodes tshark byte arrays correctly, case re-saves replace stale IOCs, and PDF timestamps are consistently UTC.

---

## Table of Contents

- [What's new in version 2](#whats-new-in-version-2)
- [Visual Tour](#visual-tour)
- [Key Features](#key-features)
- [Integrations API](#integrations-api)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Configuration](#configuration)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

---

## Visual Tour

These are captures of the real version-2 Streamlit app running in Docker against
the bundled sample PCAP. IP addresses, API secrets, email addresses, and local
user paths are masked in the image pixels before the files are committed.

### 1. Upload — load one or many PCAPs

Drag-and-drop `.pcap` / `.pcapng` files or paste a container path. Multiple files
trigger batch mode with cross-file correlation, and a dismissable getting-started
panel walks first-time users through the workflow.

![Upload tab](docs/images/01-upload.png)

### 2. Progress — transparent 10-stage pipeline

Every stage reports durable job progress. PyShark and Zeek run in parallel, then
DNS, TLS, beaconing, and carving fan out concurrently. The work runs outside the
Streamlit page thread, so the upper-right Stop control or a browser reload does
not discard the job; completed evidence is autosaved to Cases and restored.

![Progress tab](docs/images/02-progress.png)

### 3. Dashboard — at-a-glance threat summary

The Dashboard surfaces the highest-signal findings first: overall risk level with a
**"Why this risk level?"** explainability expander, a one-line **severity color
legend**, alert count, beacon candidates (with progress-bar scores), YARA hits, and
certificate issues. Sections that ran clean say so explicitly — no ambiguous blank
panels. A global traffic map, protocol distribution, and UTC-labelled activity
timeline put the capture in visual context.

![Dashboard tab](docs/images/03-dashboard.png)

### 4. MITRE Analysis — behaviors, evidence, and coverage

The dedicated ATT&CK workspace treats mappings as analyst hypotheses rather than
proof. It links network evidence to techniques and applicable detection context,
lets analysts record a disposition and note, makes detector gaps explicit, and
exports an ATT&CK Navigator layer with versioned metadata.

![MITRE Analysis tab](docs/images/10-mitre-analysis.png)

### 5. LLM Analysis — AI-generated threat report

A nine-section narrative — Executive Summary through Recommended Actions, plus an
**IOC Summary table** and a **Risk Matrix rendered as a real Markdown table** — with
confidence qualifiers and MITRE ATT&CK mapping. Generate locally via LM Studio
(section-by-section) or in a single full-context call via OpenAI or Anthropic.
Reports in 9 languages, including Traditional Chinese (zh-TW).

![LLM Analysis tab](docs/images/04-llm-analysis.png)

When a report is skipped or unavailable, this tab still shows a deterministic
snapshot of parsed packets, flows, IOCs, correlations, completed stages, and
pipeline warnings.

### 6. OSINT — multi-provider IOC enrichment

Prioritized IOC table with VirusTotal, AbuseIPDB, GreyNoise, Shodan, OTX, and
VT Domain signals merged into one view. **Provider-status pills** report each
provider honestly (OK / cached / rate-limited / key-rejected / no data), an explicit
**WHOIS lookup** selectbox + button complements row-click dialogs, and IOC search
offers a show-all-results toggle. Sub-tabs expose Domains, Detail Cards, Geo Map,
Infrastructure ASN clustering, Export, Devices, and Notes.

![OSINT tab](docs/images/05-osint.png)

### 7. Raw Data — Zeek logs, flows, carved payloads, YARA matches

Every underlying data source is available: the flow table (with explicit
**First/Last Seen (UTC)** timestamp columns), DNS and TLS analyses, NXDOMAIN
analysis, JA3/JA3S fingerprints, Zeek `conn.log`/`dns.log`/`http.log`/`ssl.log`,
carved HTTP payloads, and YARA scan results. Export any view as CSV or JSON with
CSV-injection protection.

![Raw Data tab](docs/images/06-raw-data.png)

### 8. Cases — persistent investigation tracking

Promote any capture and its findings into a case. Cases carry IOCs, severity,
tags, investigation notes, ATT&CK mappings, capture-quality metrics, status, and
search — stored in a local SQLite database.

![Cases tab](docs/images/07-cases.png)

### 9. API Keys — manage programmatic access

Create, revoke, and monitor API keys for the Integrations API. Each key has its own
scope (full or feed-only), optional expiration, per-key rate limits, and a usage
sparkline. Environment-variable keys are shown as read-only bootstrap entries.

![API Keys tab](docs/images/11-api-keys.png)

### 10. Config — centralized settings

An **LLM Integration** section with three providers (LM Studio, OpenAI, Anthropic),
a **YARA Rules** section with a configurable rules directory, OSINT provider keys
with a **Test Providers** live-check button, home location for the world map,
binary paths, and pipeline thresholds — all in one place with per-section clear
buttons. API keys are PBKDF2-encrypted at rest.

![Config tab](docs/images/08-config.png)

#### Choosing an LLM provider

Pick the backend that fits your environment: **LM Studio** for local, air-gapped
analysis (chunked per-section generation), or **OpenAI** / **Anthropic** for
single-shot full-context cloud reports. Each provider keeps its own credentials
and model picker.

![LLM provider selection](docs/images/09-llm-providers.png)

---

## Key Features

### AI-Powered Threat Analysis
- **Multi-Provider LLM Support** — three interchangeable backends behind one Config section:
  - **LM Studio** (local) — privacy-first, air-gapped friendly; reports are generated section-by-section to fit small context windows.
  - **OpenAI** (cloud) — single-shot report with the entire evidence corpus in one full-context call.
  - **Anthropic** (cloud) — Claude via the official `anthropic` SDK (`claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5`), single-shot with streaming.
- **Evidence-Grounded Reporting** — SOC-ready reports with severity-calibrated assessments, false-positive awareness, confidence qualifiers, a Risk Matrix rendered as a real Markdown table, and an IOC Summary table.
- **LLM-Optional Evidence View** — parsed packet, flow, IOC, correlation, stage, and warning evidence remains visible when generation is skipped or the provider is unavailable.
- **Multi-Language Reports** — 9 languages with region-specific terminology: English, Traditional Chinese (Taiwan), Simplified Chinese, Japanese, Korean, Italian, Spanish, French, German.
- **MITRE ATT&CK Analysis** — A separate Behaviors & Coverage workspace that maps network evidence to versioned ATT&CK hypotheses, links applicable Detection Strategies/Data Components, records analyst dispositions, and exports Navigator layers.
- **Capture-quality telemetry** — Packet/flow scale, parse coverage, time window, sampling limits, pipeline warnings, and detector visibility gaps are recorded alongside findings.
- **Attack Narrative Synthesis** — Translates raw events into a coherent, actionable security story.

### IOC Priority Scoring
- **Tiered Signal Architecture** — Dynamically ranks indicators as Critical, High, Medium, or Low using a three-tier model:
  - **Tier 1 (Definitive)**: OSINT confirmations (VirusTotal, GreyNoise malicious) — any single Tier 1 hit sets a score floor.
  - **Tier 2 (Behavioral)**: C2 beaconing, flow asymmetry, DNS tunneling, DGA domains.
  - **Tier 3 (Contextual)**: AbuseIPDB, self-signed certs, expired certs, YARA matches.
- Tier 3 signals alone never exceed "medium"; corroboration from multiple tiers is required for "high" or "critical".
- **Explainable Risk** — the Dashboard's "Why this risk level?" expander shows exactly which signals drove the verdict.

### Cross-Indicator Correlation Engine
- **Independence-complement formula** — Uses `1 − Π(1 − wᵢsᵢ)` (Bayesian independence model) instead of linear summation, producing diminishing returns while allowing multiple weak signals to compound meaningfully.
- **Strong-signal floors** — A confirmed VirusTotal detection automatically sets a minimum score regardless of other factors.
- Aggregates signals across all analysis modules (OSINT, beaconing, DNS, TLS, YARA, flow analysis).
- Produces composite threat scores per indicator with verdict classification (critical / high / medium / low).

### Flow Analysis & Exfiltration Detection
- **Data Exfiltration Detection** — Identifies suspicious outbound:inbound byte ratios per src/dst pair (default threshold: 10:1, minimum 1 MB).
- **Port Anomaly Detection** — Flags non-standard port usage, C2 common ports (4444, 5555, 6666, etc.), and high port pairs.
- **Memory-Bounded Sampling** — per-flow packet timestamps/lengths are capped at 5,000 samples while true byte/packet totals and first/last-seen times are kept exact.

### Multi-PCAP Batch Processing
- **Multi-File Upload** — Upload and analyze multiple PCAP files simultaneously.
- **Validated Streaming Intake** — `.pcap` and `.pcapng` uploads are written in bounded chunks, checked for file and batch limits, validated by magic bytes, and rolled back as a set after any failure.
- **Cross-File Correlation** — Detects shared IPs, domains, and JA3 fingerprints across files.
- **Merged Dashboard** — Aggregated results with per-file detail cards and batch summary.
- **Resource Limits** — Configurable limits: 1 GB per file, 50 files max, 5 GB total.

### Concurrent Pipeline Execution
- **PyShark + Zeek in parallel** — the two heaviest stages run concurrently via ThreadPoolExecutor.
- **Four-way analysis fan-out** — after the parse join, DNS, TLS, beaconing, and HTTP carving all run concurrently.
- **Per-run artifact isolation** — Zeek and carve outputs go to `data/zeek|carved/<case>_<uuid8>/` so concurrent runs never clobber each other; stale run dirs are pruned automatically after 7 days.
- **Bounded subprocesses** — every external tool call (zeek, tshark counting/carving/TLS extraction) runs under an explicit timeout.
- **Tshark `-c` optimization** — packet limit enforced at the tshark level for zero-waste I/O.

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
- **YARA Rules Config** — point the YARA Rules section in Config at any rules directory (scanned recursively); zero-config default is `data/yara_rules/` when present.
- **Safe Storage** — quarantined per-run directory with path traversal and symlink protection.

### Honest, Analyst-First UI
- **Central severity color system** — one palette drives every verdict badge, chart, and pill, with a one-line legend for calibration.
- **Honest provider status** — OSINT provider pills distinguish OK / cached / rate-limited / key-rejected / no-data instead of a generic error, aggregated across all queried indicators; a Test Providers button in Config live-checks each configured provider.
- **Contextual empty states** — panels distinguish "ran clean" from "stage skipped/failed"; nothing renders as a silent blank.
- **Humanized tables** — UTC-labelled timestamps, progress-bar score columns, named chart axes.
- **Cross-Filtering** — unified drill-down across Map, Protocol Pie Chart, and Flow Timeline; "Exclude Private IPs" persists during exploration.
- **TopN Charts** — top IPs, ports, protocols, domains with reverse-DNS hostnames.
- **World Map** — threat-level coloring, connectivity arcs with volume-based thickness, configurable home location.

### OSINT Enrichment
Integrates with leading threat intelligence providers:
- **VirusTotal** — File hash and IP/Domain reputation.
- **AbuseIPDB** — Crowdsourced IP abuse reports.
- **GreyNoise** — Internet background noise and scanner identification.
- **OTX (AlienVault)** — Open Threat Exchange pulses and indicators.
- **Shodan** — Internet-facing device details and open ports.
- **Smart Caching** — SQLite-backed caching with configurable TTL to preserve API quotas.
- **Bulk Reverse DNS** — Parallel rDNS resolution for all public IPs with 7-day SQLite cache.
- **WHOIS Lookup** — on-demand WHOIS dialog for any listed IP, via row-click or an explicit selectbox + button.

### Case Management System
- Create, track, and close investigation cases.
- Store IOCs (IP, Domain, Hash, JA3, URL) with severity and context.
- Persist ATT&CK hypotheses and capture-quality metrics with each analysis.
- Replace stale IOC rows cleanly when an existing analysis is re-saved.
- Investigation notes, tag-based organization, and search.

### Professional PDF Export
- Multi-page PDF reports with executive summary, key findings, technical analysis, and recommendations.
- **Self-consistent section registry** — section numbering and the table of contents are generated from one registry, so they always agree; LLM-authored headings are demoted below section level.
- **Risk Matrix & IOC Summary** — rendered as real tables in the PDF, not prose.
- **Embedded dashboard charts** — protocol distribution, top talkers, flow timeline, network graph, world map — rendered to PNG via kaleido for static handoff.
- **Timezone-aware timestamps** plus configurable TLP classification and analyst metadata.

### Export Formats
- **CSV / JSON** — Export any data table with CSV injection protection.
- **STIX 2.0/2.1** — Export indicators in standard STIX format.
- **ATT&CK Navigator** — Export technique mappings for MITRE ATT&CK Navigator.
- **CEF (ArcSight)** — SIEM-ingestible events from correlations, beacons, DNS, and IOCs.

---

## Integrations API

PCAP Hunter ships a FastAPI-based REST API alongside the Streamlit UI so SOAR
platforms, SIEM systems, and custom scripts can submit PCAPs, poll job progress,
retrieve cases/PDF reports, and pull IOC feeds (JSON / CSV / STIX 2.1)
programmatically. It reuses the same 10-stage pipeline, SQLite case database, and
configuration as the UI; DB-backed API keys are managed from the API Keys tab.
Headless results include capture-quality metrics and ATT&CK hypotheses, while IOC
feeds include the technique IDs associated with contributing analyses. Uploads are
streamed and validated before queueing; queue or persistence failures remove the
provisional file and case instead of leaving orphans.

```bash
make run-api     # http://localhost:8000
make smoke-api   # end-to-end smoke test against the local API
```

> Endpoint reference, authentication, curl examples, and SIEM integration guides:
> **[docs/API.md](docs/API.md)** and **[docs/api/README.md](docs/api/README.md)**

---

## Architecture

```
app/
├── analysis/        # Correlation, flow/IOC scoring, narration, capture visibility
├── api/             # FastAPI integrations API (REST endpoints, auth, key mgmt)
│   ├── routers/     # health, pcaps, jobs, cases, iocs, admin
│   ├── key_auth.py  # DB + env-var authentication pipeline
│   ├── key_repository.py  # SQLite API key store
│   ├── rate_limiter.py    # Sliding-window per-key rate limiter
│   └── queue.py     # Background pipeline execution (ProcessPoolExecutor)
├── database/        # Case management (SQLite)
├── llm/             # LLM client + multi-provider dispatch (providers.py)
├── pipeline/        # 10-stage analysis pipeline
│   ├── runner.py    # Headless orchestrator (parallel stages, per-run dirs)
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
├── ui/              # Streamlit interface (10 tabs, upload validation, MITRE workspace)
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

Stages 2–3 (PyShark, Zeek) run in parallel; after that parse join, stages 4–7
(DNS, TLS, beaconing, carving) run concurrently. Zeek and carve write into
per-run output directories (`data/zeek|carved/<case>_<uuid8>/`) so concurrent
runs never clobber each other; stale run dirs are pruned after 7 days.

---

## Installation

### Option A — Docker (recommended)

The canonical build-and-verify path. The image bakes in tshark, zeek, the
WeasyPrint libraries, and all Python deps — nothing to install on the host but
Docker itself.

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
make docker-up        # build + start the UI → http://localhost:8501
make docker-verify    # format + lint + full test suite INSIDE the image
make docker-down      # stop compose services
```

Compose notes:

- `./data` is mounted into the container, so PCAPs, carved files, Zeek logs, and
  the case database live on the host. Put YARA rules under `./data/yara_rules`.
  Set `PCAP_HUNTER_DATA_BIND` to use a different host data directory.
- API keys saved in the UI persist in the `pcap-hunter-home` volume; the compose
  file pins `hostname:` so the config encryption key stays stable across
  container recreation.
- LM Studio running on the host is reachable from the container —
  `LM_BASE_URL` defaults to `http://host.docker.internal:1234/v1`.
- A second compose service (`pcap-hunter-api`) serves the Integrations API on
  port 8000 from the same image.

### Option B — Standalone install

All install logic lives in a single cross-platform script
(`scripts/install.py`) that detects your OS and package manager, installs
system binaries and Python packages, then verifies everything.

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
python3 scripts/install.py
make run              # → http://localhost:8501
```

What it installs per platform:

| Platform | Manager | System packages |
|----------|---------|-----------------|
| macOS | `brew` | `wireshark` (tshark + capinfos), `zeek`, `yara`, and `pango` + `glib` + `cairo` for WeasyPrint PDF export |
| Linux | `apt-get` | `tshark`, `zeek`, `yara`, `libpcap0.8`, and the WeasyPrint runtime libs (`libpango-1.0-0`, `libpangocairo-1.0-0`, `libpangoft2-1.0-0`, `libharfbuzz0b`, `libcairo2`, `libgdk-pixbuf-2.0-0`, `shared-mime-info`, `fonts-dejavu-core`); non-apt distros get manual hints (dnf/pacman) |
| Windows | `winget` → `choco` → `scoop` | Wireshark (winget/choco/scoop), YARA (choco/scoop); Zeek has no native Windows build — the installer points you to WSL2 or Docker |

It then pip-installs `requirements.txt` (no separate Chromium needed — the
pinned `kaleido==0.2.1` bundles its own headless renderer) and runs the
dependency checker. Required Python packages are verified by name (streamlit,
pandas, numpy, pyshark, scapy, openai, anthropic, requests, cryptography,
plotly, kaleido, markdown, jinja2, fastapi, uvicorn); `weasyprint` and
`yara-python` are checked as optional — the app degrades gracefully without
them.

Prefer your platform's usual workflow? These wrappers all delegate to the same
`install.py`:

| Platform | Command |
|----------|---------|
| macOS / Linux | `make install` |
| Windows (PowerShell) | `.\scripts\install.ps1` (bootstraps Python first, then delegates) |
| Any platform | `python3 scripts/install.py` |

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

- **Docker** (simplest) — `make docker-up` or `docker compose up --build`
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
make docker-up   # Docker (recommended) → http://localhost:8501
# — or —
make run         # standalone, after python3 scripts/install.py
```

Open `http://localhost:8501` in your browser.

---

## Usage Guide

1. **Upload** — Drag and drop one or more `.pcap` files in the Upload tab. Multiple files trigger batch mode with cross-file correlation.
2. **Configure** — Pick an LLM provider (LM Studio / OpenAI / Anthropic), set your home location (Continent > Country > City), OSINT API keys, and optionally a YARA rules directory in the Config tab.
3. **Analyze** — Click **Extract & Analyze** to start the pipeline.
4. **Monitor** — Watch the Progress tab as stages execute in a durable background process: Packet Counting > Parsing + Zeek (parallel) > DNS / TLS / Beaconing / Carving (concurrent) > YARA > OSINT > LLM Report. Stopping or reloading the Streamlit page does not discard the job.
5. **Review** — Explore results across Dashboard, MITRE Analysis, LLM Analysis, OSINT, Raw Data, and Cases tabs.
6. **Export** — Download CSV/JSON data, PDF reports, STIX bundles, ATT&CK Navigator layers, or CEF syslog events.

### Re-run Reports

Changed your LLM provider, model, or report language? Click **Re-run Report** to regenerate only the AI report without re-processing the entire PCAP.

### Data Management

Use the granular **Clear** buttons in Config to independently wipe PCAP data, OSINT cache, or the Cases database.

---

## Configuration

- Defaults in `app/config.py` (thresholds, paths, URLs)
- Persistent config in `~/.pcap_hunter_config.json` (managed by `ConfigManager`)
- API keys encrypted at rest with machine-derived PBKDF2 key
- Environment-variable overrides: `OTX_KEY`, `VT_KEY`, `SHODAN_KEY`, etc.
- LLM defaults: LM Studio at `http://localhost:1234/v1`
- YARA rules: leave the directory blank to use `data/yara_rules/` when present

### Key Thresholds

| Setting | Default | Purpose |
|---------|---------|---------|
| DGA entropy | 4.0 bits | Shannon entropy threshold for DGA detection |
| Fast flux | 10+ IPs | Minimum distinct IPs per domain |
| Flow asymmetry | 10:1 + ≥1 MB | Exfil candidate threshold |
| C2 common ports | 4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337 | Port-anomaly match list |
| PyShark limit | 200,000 packets | Deep-parse cap |
| Flow sample cap | 5,000 per flow | Sampled timestamps/lengths (true totals kept exact) |
| Run-dir retention | 7 days | Per-run `data/zeek\|carved/` dirs pruned on the next run |
| Subprocess timeouts | zeek 600 s; count 120 s; carve / TLS extract 300 s | Bounded external tool calls |

---

## Development

### Pre-commit gate — `make verify`

```bash
make verify     # format check + lint + full test suite
```

Required before every commit. CI (GitHub Actions, Python 3.11) runs the same
checks on every push/PR to `main`. For build-shaped verification (dependency
changes, install paths, release checks) use `make docker-verify` — it runs the
identical gate inside the runtime image, independent of the host Python setup.

### Make targets

| Target | What it does |
|--------|--------------|
| `make install` | Full install (system + python) + verification |
| `make install-system` / `make install-python` | System binaries only / Python packages only |
| `make check-deps` / `make doctor` | Verify all dependencies are present |
| `make run` | Start the app (checks deps first) |
| `make test` | Run the test suite with coverage |
| `make test-pdf` | Focused PDF + charts test suite |
| `make verify` | Pre-commit gate: format + lint + full tests |
| `make lint` / `make format` | Ruff check / Ruff format |
| `make clean` | Remove caches |
| `make docker-build` | Build the runtime image (`pcap-hunter:latest`) |
| `make docker-up` | Build + start the UI container on :8501 |
| `make docker-down` | Stop compose services |
| `make docker-verify` | Format + lint + full tests inside the image |
| `make run-api` / `make run-api-dev` | Start the Integrations API on :8000 (dev adds --reload) |
| `make smoke-api` | End-to-end smoke test against the local API |
| `make fix-permissions` | Grant macOS BPF capture permissions |

### Regenerating doc screenshots

`scripts/capture_screenshots.py` re-captures every README/manual screenshot with
the real Docker-hosted Streamlit UI in headless Chromium. It masks IP addresses,
API secrets, email addresses, and local user paths at the pixel level; tesseract
provides a fallback for canvas-rendered tables and a final privacy audit.

```bash
python3 -m pip install -r requirements-docs.txt
python3 -m playwright install chromium
DOCS_DATA="$(mktemp -d)"
cp data/sample.pcap "$DOCS_DATA/sample.pcap"
PCAP_HUNTER_DATA_BIND="$DOCS_DATA" make docker-up
python3 scripts/capture_screenshots.py --seed-docs-key
```

The isolated bind prevents local cases, keys, cache entries, or prior captures
from appearing in the documentation. The script creates its example API key
through the real UI, then reloads away the one-time secret before capture.

### Testing discipline

PCAP Hunter uses **production-shape test data**, not simplified inputs. See `tests/test_pdf_integration.py` for the canonical pattern — real `CorrelationSignal` dataclasses, real pandas DataFrames, and the nested dict shapes the pipeline actually produces. When adding a new PDF section or chart, extend the corresponding integration test.

---

## Documentation

- **[User Manual (English)](docs/en/USER_MANUAL.md)** — end-user guide
- **[使用手冊 (Traditional Chinese)](docs/zh-TW/USER_MANUAL.md)** — 繁體中文使用手冊
- **[Integrations API Reference](docs/API.md)** — REST endpoints, authentication, configuration
- **[API Integration Guides](docs/api/README.md)** — SIEM / SOAR integration recipes
- **[中文說明 (Traditional Chinese README)](docs/zh-TW/README.md)** — 繁體中文版

---

## License

[MIT License](LICENSE) — see file for details.
