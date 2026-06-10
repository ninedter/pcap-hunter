# PCAP Hunter User Manual

**PCAP Hunter** is an advanced threat hunting workbench that bridges the gap between manual packet analysis and automated security monitoring. It combines industry-standard tools (**Zeek**, **Tshark**) with modern AI (**LLMs**) and threat intelligence (**OSINT**) to rapidly ingest, analyze, and extract actionable intelligence from network traffic.

---

## 📚 Table of Contents
1. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
   - [Installation & Launch](#installation--launch)
2. [Core Workflows](#core-workflows)
   - [Data Ingestion (Upload)](#1-data-ingestion)
   - [Analysis Pipeline](#2-analysis-pipeline)
3. [Analysis Dashboard](#analysis-dashboard)
   - [Threat Summary Panel](#threat-summary-panel)
   - [Global Map & Filters](#global-map--filters)
   - [Sankey Flow Diagram](#sankey-flow-diagram)
   - [Charts & Visualizations](#charts--visualizations)
   - [Top Metrics](#top-metrics)
   - [Detection Panels](#detection-panels)
   - [Cross-Indicator Correlation](#cross-indicator-correlation)
4. [Advanced Features](#advanced-features)
   - [AI Threat Report](#ai-threat-report)
   - [Multi-PCAP Batch Analysis](#multi-pcap-batch-analysis)
   - [OSINT Enrichment](#osint-enrichment)
   - [Bulk Reverse DNS](#bulk-reverse-dns)
   - [Forensics (DNS, TLS, YARA, Carving)](#forensics)
5. [Configuration](#configuration)
   - [LLM Setup](#llm-setup)
   - [OSINT Keys](#osint-keys)
   - [Map Location](#map-location)
   - [Data Management](#data-management)
6. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites
Ensure the following tools are installed on your system:
- **Python 3.10+**: The core runtime.
- **Zeek**: Network security monitor for generating logs (`brew install zeek`).
- **Wireshark/Tshark**: Packet analyzer for parsing and statistics (`brew install wireshark`).
- **Pango**: Library required for PDF report generation (`brew install pango`).
- **LM Studio** (Optional): For running local AI models privacy-first.

### Installation & Launch
1. **Clone the repository**:
   ```bash
   git clone https://github.com/ninedter/pcap-hunter.git
   cd pcap-hunter
   ```
2. **Install dependencies**:
   ```bash
   make install
   ```
3. **Run the application**:
   ```bash
   make run
   ```
   The application will open in your default browser at `http://localhost:8501`.

---

## Core Workflows

### 1. Data Ingestion
Navigate to the **Load PCAP** tab to start.

#### File Upload
- **Single File**: Drag & drop a `.pcap` or `.pcapng` file into the upload area.
- **Multiple Files**: Upload multiple PCAPs at once to enter **Batch Mode** with cross-file correlation. Limits: 50 files max, 1 GB per file, 5 GB total.
- **Manual Path**: For large files (>200MB) that browsers struggle to upload, type the absolute path to the file on your disk (e.g., `/Users/name/capture.pcap`) and press Enter.

### 2. Analysis Pipeline
By default, PCAP Hunter executes a complete analysis pipeline. You can customize which phases run (e.g., disable Zeek or Carving) in the **Config** tab under the **Extraction / Analysis** section.

#### Parallel Execution
The two heaviest stages — **PyShark packet parsing** and **Zeek log processing** — run concurrently via a thread pool, significantly reducing total analysis time. HTTP carving also runs in parallel with DNS/TLS/Beaconing analysis.

Click **Extract & Analyze** to begin. Monitor progress in the **Progress** tab.

---

## Analysis Dashboard

The **Dashboard** tab is your central mission control.

### Threat Summary Panel
At the top of the dashboard, a panel displays five key metrics at a glance:
- **Risk Level** — Overall threat assessment (Critical / High / Medium / Low) based on corroboration across multiple signal categories.
- **Total Alerts** — Number of indicators flagged by the correlation engine.
- **Beacon Candidates** — Flows exhibiting C2-like periodic communication patterns.
- **YARA Hits** — Files matching YARA rule signatures.
- **Cert Issues** — TLS certificates with problems (self-signed, expired, or untrusted chains).

The risk level requires **corroboration from 2+ signal categories** to escalate to Medium, and YARA or high-confidence OSINT signals for High/Critical — preventing false positives from single weak signals.

### Global Map & Filters
- **Interactive World Map**: Visualizes the geographic destination of your traffic.
  - **Selection**: Use **Box Select** or **Lasso Select** tools to highlight a region. This **cross-filters** the entire dashboard (charts, tables, timeline) to show only traffic relevant to that area.
  - **Home Location**: Configure your physical location in the **Config** tab to draw accurate connection lines.
- **Global Filters**:
  - **Exclude Private IPs**: Toggle this checkbox to hide RFC1918 (local LAN) traffic from the map and "Top 10" charts. This helps focus on external threats.
  - **Clear All Filters**: Instantly resets the dashboard view, clearing IP, protocol, and time selections.

### Sankey Flow Diagram
Displayed alongside the Network Communication Graph, the **Sankey diagram** visualizes traffic flows in three columns:
- **Left**: Client (source) IPs
- **Middle**: Service ports with human-readable protocol labels (e.g., "443 (HTTPS)", "53 (DNS)")
- **Right**: Server (destination) IPs

The diagram automatically normalizes flow direction: the side using a well-known port (< 10000) is treated as the server. Ephemeral ports (>= 10000) are excluded to keep the visualization clean and focused on meaningful service connections.

### Charts & Visualizations
- **Protocol Distribution**: A pie chart showing protocol breakdown (TCP, UDP, TLS, HTTP, etc.). Click a slice to filter the dashboard by that protocol.
- **Flow Timeline**: A time-series chart showing traffic volume over time.
  - **Zoom**: Click and drag to create a time window. The dashboard will update to show only traffic from that specific period.
- **Network Communication Graph**: Force-directed graph with threat-colored nodes and equal-aspect-ratio rendering.

### Top Metrics
- **Top 10 Tables**: Tables and bar charts displaying the most active:
  - **Source IPs** (with reverse DNS hostnames)
  - **Destination IPs** (with reverse DNS hostnames)
  - **Destination Ports**
  - **Protocols** or **Domains**

### Detection Panels
The dashboard surfaces key detection results directly:
- **Beaconing Candidates** — Flows scoring above the C2 threshold (0.6+), with periodicity and jitter details.
- **YARA Matches** — Files carved from HTTP traffic that matched YARA rules.
- **TLS Certificate Risks** — Expired, self-signed, or untrusted certificates detected in SSL/TLS traffic.

### Cross-Indicator Correlation
A dedicated section displays the **correlation engine's composite threat scores** for each indicator:
- Uses an **independence-complement formula** (`1 − Π(1 − wᵢsᵢ)`) to combine signals from OSINT, beaconing, DNS, TLS, YARA, and flow analysis.
- Indicators are classified as **Critical**, **High**, **Medium**, or **Low** with supporting signal breakdowns.
- Strong-signal floors ensure that a confirmed VirusTotal detection automatically sets a minimum score.

---

## Advanced Features

### AI Threat Report
Located in the **LLM Analysis** tab.
- **Structured Analysis Workflow**: The AI follows a professional methodology: Characterize → Identify → Assess → Recommend.
- **Severity Calibration**: The LLM is guided by examples for each severity level, with built-in false-positive awareness to avoid over-rating benign traffic.
- **Pre-Computed Context**: The report receives pre-computed correlation verdicts, risk distributions, and top threats — ensuring the AI narrative aligns with the quantitative analysis.
- **Sections**: Includes Executive Summary, Key Findings, Indicators of Compromise (IOCs), Risk Assessment, and Recommended Actions.
- **PDF Export**: Click **Generate PDF Report** to download a formatted report. The PDF includes:
  - Cover Page with classification (TLP:CLEAR).
  - Full AI narrative.
  - Tables for detected IOCs (IPs, Domains, Hashes).
  - YARA Scan results.
  - TLS Analysis (expired/self-signed certs).

### Multi-PCAP Batch Analysis
Upload multiple PCAP files at once to enable batch mode:
- **Per-File Analysis**: Each file runs through the full 10-stage pipeline independently.
- **Cross-File Correlation**: After individual analysis, the engine detects shared indicators (IPs, domains, JA3 fingerprints) across files — revealing coordinated activity or persistent threats.
- **Batch Summary**: Aggregated metrics and per-file detail cards are displayed in the dashboard.
- **Resource Limits**: Configurable via `app/config.py` — default 50 files max, 1 GB per file, 5 GB total.

### OSINT Enrichment
Located in the **OSINT** tab.
- **IP Intelligence**: Displays reputation scores from VirusTotal, GreyNoise (noise vs. malicious), and PTR records.
- **Domain Intelligence**: Categories and reputation for queried domains.
- **WHOIS**: Click on an IP or Domain to view registration details in a popup.

### Bulk Reverse DNS
PCAP Hunter automatically performs **bulk reverse DNS (rDNS) resolution** for all public IPs observed in the traffic:
- Parallel resolution via ThreadPoolExecutor for speed.
- Results cached in a dedicated **SQLite database** with a 7-day TTL to avoid redundant lookups.
- Resolved hostnames are displayed throughout the dashboard in Top 10 tables, correlation results, and OSINT views.

### Forensics
- **DNS Analysis**:
  - **DGA Detection**: Uses Shannon Entropy to identify randomly generated domains used by malware.
  - **Tunneling**: Flags unusually large or frequent DNS queries indicative of data exfiltration.
- **TLS Analysis**:
  - **JA3 Fingerprinting**: Identifies client applications based on SSL hello packets.
  - **Certificate Hygiene**: Alerts on self-signed, expired, or unusual certificates.
- **YARA Scanning**: Automatically scans files extracted from HTTP traffic.
  - **Carved Files**: Each run stores its files in a per-run folder under `./data/carved/<run_id>/`, auto-pruned after 7 days — export anything you need to keep.
  - **Rules**: Uses custom or standard YARA rules to detect known malware families.

---

## Configuration

Customize the application in the **Config** tab.

### LLM Setup
- **Endpoint**: Default is `http://localhost:1234/v1` (LM Studio). consistent with OpenAI API standards.
- **Model**: Type the model name (e.g., `llama-3.2-3b-instruct`) or click **Fetch Models** to auto-populate from the server.
- **Language**: Select from **9 supported languages** (English, Chinese, Japanese, Korean, Italian, Spanish, French, German) for the report.
  - **Re-run Report**: If you change the language or model, use this button to regenerate *only* the report without re-processing the PCAP.

### OSINT Keys
Enter your API keys to enable enrichment. Keys are saved securely in your local configuration.
- **VirusTotal**: For file has and IP/Domain reputation.
- **AbuseIPDB**: For community-reported malicious IPs.
- **GreyNoise**: To identify internet scanners (benign vs. malicious).
- **Shodan**: For device fingerprinting.
- **OTX**: AlienVault Open Threat Exchange.

### Extraction / Analysis
Enable or disable specific pipeline steps to speed up analysis or skip unnecessary processing:
- **PyShark Parsing**: Deep packet inspection (Required for flow charts).
- **Packet Limit**: Max packets to parse (Default: 200,000) to prevent memory exhaustion.
- **Zeek Processing**: Toggles Zeek log generation.
- **Parallel Execution**: When both PyShark and Zeek are enabled, they run concurrently (enabled by default).
- **Carve HTTP bodies**: Extracts files from HTTP traffic.
- **YARA Scan**: Scans carved files (requires Carving to be enabled).
- **Pre-count packets**: Counts total packets before parsing.
- **OSINT Cache**: Toggles local caching of API results.

### Map Location
Set your **Home Location** using the cascading selectors:
- **Continent** -> **Country** -> **City**
- This fixes the origin point for connection lines on the map.

### Data Management
Granular controls to manage disk usage:
- **Save/Load Config**: Persist your settings (keys, location, preferences) across sessions.
- **Clear PCAP Data**: Deletes all uploaded PCAPs, Zeek logs, and carved files to free disk space.
- **Clear OSINT Cache**: PCAP Hunter caches API responses to save quota. Use this to force fresh lookups.
- **Clear Cases**: Wipes the internal database of all investigation cases and notes.

---

## Troubleshooting

- **"Binaries not found"**:
  - The app attempts to auto-detect `zeek` and `tshark`.
  - If it fails, check the **System Health** section in the **Config** tab.
  - You can manually enter the binary paths (e.g., `/opt/homebrew/bin/zeek`) in the Config tab.
- **"LLM Generation Failed"**:
  - Ensure LM Studio is running and the "Start Server" button is active.
  - Verify the Base URL matches the one in LM Studio.
- **"PDF Generation Error"**:
  - Requires the `pango` library. Run: `brew install pango`.

---
*PCAP Hunter v0.6.0-alpha*
