# PCAP Hunter User Manual

**PCAP Hunter** is an AI-enhanced threat hunting workbench that bridges the gap between manual packet analysis and automated security monitoring. It combines industry-standard tools (**Zeek**, **Tshark**, **PyShark**) with **LLMs** and **OSINT** threat intelligence to rapidly ingest, analyze, and extract actionable intelligence from network traffic.

This manual walks through the application the way a new SOC analyst would: install, load a capture, watch the pipeline, then work the results tab by tab.

---

## 📚 Table of Contents
1. [Getting Started](#getting-started)
   - [Option A — Docker (recommended)](#option-a--docker-recommended)
   - [Option B — Standalone install](#option-b--standalone-install)
   - [First Launch](#first-launch)
2. [Loading PCAPs](#loading-pcaps)
3. [The Analysis Pipeline & Progress Tab](#the-analysis-pipeline--progress-tab)
4. [Dashboard](#dashboard)
5. [MITRE ATT&CK Analysis](#mitre-attck-analysis)
6. [OSINT Enrichment](#osint-enrichment)
7. [LLM Analysis (AI Threat Report)](#llm-analysis-ai-threat-report)
8. [Raw Data](#raw-data)
9. [Cases](#cases)
10. [Exports & PDF Reports](#exports--pdf-reports)
11. [Configuration](#configuration)
12. [Data Retention](#data-retention)
13. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Option A — Docker (recommended)

The Docker image bakes in tshark, Zeek, the WeasyPrint PDF libraries, and all Python dependencies — nothing to install on the host but Docker itself.

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
make docker-up        # build + start the UI → http://localhost:8501
make docker-down      # stop when finished
```

Good to know:

- **`./data` is mounted into the container** — PCAPs, carved files, Zeek logs, and the case database live on the host and survive container restarts. Put YARA rules under `./data/yara_rules`.
- **API keys you save in the UI persist** in the `pcap-hunter-home` Docker volume. The compose file pins the container `hostname:` so the machine-derived config encryption key stays stable across container recreation.
- **LM Studio on the host is reachable from the container** — `LM_BASE_URL` defaults to `http://host.docker.internal:1234/v1`.
- A second compose service (`pcap-hunter-api`) serves the Integrations API on port 8000 from the same image.

### Option B — Standalone install

A single cross-platform installer detects your OS and package manager, installs system binaries (tshark, Zeek, YARA, the WeasyPrint libraries) and Python packages, then verifies everything:

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
python3 scripts/install.py
make run              # → http://localhost:8501
```

`make install` (macOS/Linux) and `.\scripts\install.ps1` (Windows PowerShell) are wrappers around the same script. Useful flags: `--check-only`, `--skip-system`, `--skip-python`, `--dry-run`, `--yes`.

> **Windows note:** Zeek has no native Windows build. Native installs run the tshark pipeline but skip the Zeek stage — use Docker or WSL2 for the complete pipeline.

### First Launch

- A dismissable **Getting started** panel appears on the Upload tab until your first analysis: load a PCAP, click **Extract & Analyze**, watch **Progress**, then review the **Dashboard**. Click **"Got it — don't show again"** to hide it.
- The app runs a dependency check at startup and shows a **red banner** on every page if a required binary (e.g. `tshark`) is missing — you will never get a silently empty dashboard. To check manually: `make doctor` or `python3 scripts/install.py --check-only`.

---

## Loading PCAPs

Open the **Upload** tab.

- **Drag & drop** one or more `.pcap` / `.pcapng` files. The browser uploader accepts files up to **200 MB each**.
- **Larger files — use the path field.** Type a path in *"...or type a container path"* and press Enter. The path must point to a `.pcap`/`.pcapng` inside an allowed directory: `data/`, `pcaps/`, or `/data/`. In Docker, `./data` on the host is mounted into the container — drop a big capture into `./data/` and reference it as `/data/<name>.pcap`.
- **Batch mode** activates automatically when you upload multiple files: each file runs the full pipeline independently, then cross-file correlation detects shared IPs, domains, and JA3 fingerprints across captures. Limits: 50 files, 1 GB per file, 5 GB total.

Click **Extract & Analyze** to start.

The run is immediately queued as an autosaved Case. Analysis continues in a
separate worker process if you press Streamlit's upper-right **Stop** control or
reload the browser. Reopening the app within seven days reattaches the most
recent UI job; completed evidence can always be reopened from **Cases**.

---

## The Analysis Pipeline & Progress Tab

PCAP Hunter runs a 10-stage pipeline:

| # | Stage | What it does |
|---|-------|--------------|
| 1 | Packet Counting | Fast preliminary count via tshark |
| 2 | Packet Parsing | PyShark deep inspection (default cap 200,000 packets) |
| 3 | Zeek Processing | Automated Zeek run + `conn`/`dns`/`http`/`ssl` log parsing |
| 4 | DNS Analysis | DGA, tunneling, fast flux, NXDOMAIN, query velocity |
| 5 | TLS Certificate Analysis | Chain validation, self-signed/expired detection |
| 6 | Beaconing Ranking | Statistical C2 periodicity/jitter/volume scoring |
| 7 | HTTP Carving | Payload extraction with SHA256 hashing |
| 8 | YARA Scanning | Rule-based scan of carved files |
| 9 | OSINT Enrichment | Multi-provider reputation lookups |
| 10 | LLM Report Generation | AI threat synthesis |

**Execution shape:** stages 2–3 (PyShark, Zeek) run **in parallel**; once both finish, stages 4–7 (DNS, TLS, beaconing, carving) fan out **concurrently**. The Progress tab monitors the durable job:

- The overall progress bar and per-file rows identify the active stage and job status.
- Streamlit's upper-right **Stop** control pauses only the page display; it does not cancel the worker or erase completed stages.
- Pipeline components can be enabled or disabled in **Config** before submission, and LLM report generation has its own checkbox on **Upload**.
- The final phase, **LLM Report Analysis**, runs in the worker and its report is persisted with the analysis.

When the pipeline finishes, the saved results are restored into Dashboard, MITRE Analysis, LLM Analysis, OSINT, and Raw Data.

---

## Dashboard

The **Dashboard** tab is mission control. Top to bottom:

### Threat Summary

Five metrics at a glance: **Risk Level**, **Total Alerts**, **Beacon Candidates**, **YARA Hits**, and **Cert Issues**, followed by a one-line **severity color legend** so you can calibrate every badge and chart color on the page.

### "Why this risk level?" explainability

Expand the **Why this risk level?** panel under the summary to see exactly which signals drove the verdict. The risk level is the **highest tier that actually triggered**, under these escalation rules:

- **Tier 1 (Definitive)** — OSINT confirmations (e.g. VirusTotal detections, GreyNoise *malicious*). Any single Tier 1 hit sets a score floor.
- **Tier 2 (Behavioral)** — C2 beaconing, flow asymmetry, DNS tunneling, DGA domains.
- **Tier 3 (Contextual)** — AbuseIPDB reports, self-signed/expired certificates, YARA matches.
- Tier 3 signals **alone never exceed Medium**; High/Critical requires corroboration across tiers.

If nothing fired, the expander says so: "✅ No threat signals fired — nothing exceeded thresholds".

### Honest empty states

Every panel distinguishes two very different kinds of "nothing here":

- **✅ Ran and found nothing** — the stage executed and came back clean. A genuine negative result.
- **📭 Not run / not available** — the stage was skipped, failed, or its data was not persisted (e.g. "📭 DNS analysis was skipped for this run."). Not evidence of absence.

Treat ✅ as an answer and 📭 as a gap to close before signing off an investigation.

### Filters & charts

- **World map** — box/lasso selection cross-filters the entire dashboard; configure your home location in Config for accurate connection arcs.
- **Protocol pie** — click a slice to filter by protocol.
- **Flow timeline** — drag to zoom into a time window. Chart time axes are labelled **UTC**.
- **Exclude Private IPs** persists while you explore; **Clear All Filters** resets everything.
- **Top 10 tables** for source/destination IPs (with reverse-DNS hostnames), ports, protocols/domains; Sankey and force-directed network graphs.

### Flow table

The flow table includes explicit **First Seen (UTC)** and **Last Seen (UTC)** columns — true flow start/end times are kept exact even when per-flow packet samples are capped (5,000 samples per flow).

## MITRE ATT&CK Analysis

The **MITRE ATT&CK Analysis** tab is a separate workspace from the Dashboard. It presents network-derived technique matches as **hypotheses**, with supporting evidence and a confidence band for each match. It also shows detector coverage and visibility gaps so an unavailable stage is not mistaken for a clean result.

The page is deliberately scoped to the capture: PCAP evidence cannot establish process lineage, user identity, authorization, host persistence, or traffic outside the sensor. Validate the raw flows and supporting endpoint telemetry before treating a technique as confirmed. The **Coverage & Gaps** sub-tab records packet parse coverage, capture window, flow totals, sampling limits, stage warnings, and detector availability. The **Exports** sub-tab provides an ATT&CK Navigator layer using current ATT&CK version metadata.

---

## OSINT Enrichment

The **OSINT** tab enriches the most active public IPs (default: top 50, configurable) and observed domains via VirusTotal, AbuseIPDB, GreyNoise, OTX, Shodan, and VT Domain.

### Provider status pills — read these first

Each queried provider reports its status honestly, aggregated across all indicators:

| Pill | Meaning | What to do |
|------|---------|------------|
| ✅ *provider* | Queried successfully | Trust the columns |
| 💾 *provider* | Served from local SQLite cache | Fine — saves quota; clear cache in Config for fresh data |
| ⏳ *provider* rate limited | API quota exhausted | Wait for the quota window or upgrade the key |
| 🔑 *provider* key rejected | Authentication failed | Fix the key in Config → OSINT API Keys |
| ➖ *provider* no data | Provider answered but **knows nothing about these indicators** | **Not a failure** — the indicators are simply unknown to that source |
| *(no pill)* | Provider not configured / not queried | Add a key in Config if you want its signal |

The ➖ distinction matters: "no data" is a real, honest answer from a working provider — don't mistake it for a broken integration, and don't treat it as proof an indicator is benign.

### Working the tab

- **IP triage table** — per-IP verdicts with merged provider scores, rDNS hostnames, and progress-bar score columns.
- **WHOIS lookup** — pick an IP in the **selectbox and click the lookup button**, or simply **select a row** in the table; either opens the WHOIS detail dialog.
- **Domains** — reputation and categories for observed domains.
- **Detail cards** — full per-indicator provider breakdowns.
- Additional sub-tabs: Geo Map, Infrastructure (ASN clustering), Export, Devices, Notes.
- **IOC search** — search across all indicators; a **show-all-results toggle** expands past the default result cap.

---

## LLM Analysis (AI Threat Report)

The **LLM Analysis** tab generates a narrative threat report grounded in the pipeline's quantitative findings. Three interchangeable providers (configured in Config → LLM Integration):

| Provider | Where it runs | How it generates |
|----------|---------------|------------------|
| **LM Studio** | Local / air-gapped | Section-by-section (chunked) to fit small context windows |
| **OpenAI** | Cloud | Single full-context call — the entire evidence corpus in one prompt |
| **Anthropic** | Cloud | Single full-context call with streaming, via the official SDK (`claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5`) |

Frontier cloud models add **MITRE ATT&CK technique IDs** inline and propose **carefully hedged hypotheses** ("consistent with…", "would confirm…") rather than overclaiming.

### Report sections

1. Executive Summary
2. Threat Correlation
3. Indicators & Evidence
4. OSINT Corroboration
5. DNS & TLS Analysis
6. Beaconing & Network
7. Risk Assessment — includes a **Risk Matrix rendered as a real Markdown table** (one row per category)
8. Recommended Actions
9. IOC Summary — a structured **IOC table** (indicator, type, verdict, evidence)

Reports are available in **9 languages** — US English, **Traditional Chinese (zh-tw, Taiwan terminology)**, Simplified Chinese, Japanese, Korean, Italian, Spanish, French, German — selected in Config.

### Re-run Report

Changed provider, model, or language? Click **Re-run Report** to regenerate *only* the AI report — the PCAP is not re-processed.

---

## Raw Data

The **Raw Data** tab exposes every underlying data source: the flow table, DNS analysis (DGA / tunneling / NXDOMAIN), TLS certificates and JA3/JA3S fingerprints, Zeek `conn.log` / `dns.log` / `http.log` / `ssl.log`, carved HTTP payloads with SHA256 hashes, and YARA scan results. Any view exports as CSV or JSON with CSV-injection protection.

---

## Cases

The **Cases** tab turns a capture into a persistent investigation:

- **Save** the current analysis into a case — IOCs, severity, tags, investigation notes, and status are stored in a local SQLite database, searchable across sessions.
- **Load into Dashboard** restores a saved case's results into the live dashboard.

**What's restored vs. reset:** stored findings (summary metrics, IOCs, correlations, report) come back; heavyweight artifacts that are *not* persisted in the case record (e.g. full packet-level data, pruned run directories) show **"📭 not available"** empty states until you re-run the original PCAP. The dashboard tells you which is which — see [Honest empty states](#honest-empty-states).

---

## Exports & PDF Reports

### PDF report

Click **Generate PDF Report** in the LLM Analysis tab. The PDF includes:

- A cover page with configurable **TLP classification** and analyst metadata.
- **Numbered sections with a matching table of contents** — both are generated from one section registry, so numbering and the TOC always agree.
- The full AI narrative, with the **Risk Matrix and IOC Summary as real tables**, plus YARA results and TLS findings.
- **Embedded dashboard charts** (protocol distribution, top talkers, flow timeline, network graph, world map) rendered to PNG.
- **Timezone-aware timestamps** throughout.

### Data exports

- **CSV / JSON** — any table, with CSV-injection protection.
- **STIX 2.0 / 2.1** — standard indicator bundles.
- **ATT&CK Navigator** — technique-mapping layer files.
- **CEF (ArcSight)** — SIEM-ingestible events from correlations, beacons, DNS, and IOCs.

> Need programmatic access instead? The **Integrations API** serves PCAP submission, job polling, and IOC feeds (JSON / CSV / STIX 2.1) on port 8000 — see [docs/API.md](../API.md).

---

## Configuration

Everything lives in the **Config** tab; settings persist to `~/.pcap_hunter_config.json` and API keys are PBKDF2-encrypted at rest.

### LLM Integration

- A **provider selector** (LM Studio / OpenAI / Anthropic) with per-provider fields: base URL, API key, and a model picker with **Fetch Models**.
- **Test Connection** probes the selected provider and reports the result inline.
- **Report language** — the 9-language selector described above.
- **Model context window** — select 10K–1M tokens. PCAP Hunter uses no more than 50% for input evidence, reserving the rest for output and provider/tokenizer variance.
- **No context window limit** — sends all available sanitized evidence in one request and disables the slider. The provider can still reject a request beyond the model's physical context limit.

### OSINT API Keys

- Keys for VirusTotal, AbuseIPDB, GreyNoise, OTX, Shodan. Environment variables (`VT_KEY`, `SHODAN_KEY`, …) override saved config.
- **Test Providers** live-checks every configured provider with a benign indicator and reports the same statuses as the OSINT pills (ok / rate limited / key rejected / …) — run it after entering new keys.

### YARA Rules

- Point **YARA Rules directory** at any folder of `.yar`/`.yara` rules (scanned recursively).
- **Zero-config default:** leave it blank and `data/yara_rules/` is used when present. In Docker, put rules under `./data/yara_rules` — the data folder is mounted.
- The field gives **live feedback** with the number of rule files found at the configured path, so you know your rules will load before you run.

### Other sections

- **Binary paths** — override auto-detected `zeek` / `tshark` locations; a System Health readout shows what was found.
- **Home location** — Continent → Country → City; anchors the world-map connection arcs.
- **Extraction / Analysis** — toggle pipeline stages (Zeek, carving, YARA, pre-count, OSINT cache) and the PyShark packet limit (default 200,000).
- **Data management** — granular **Clear** buttons for PCAP data, OSINT cache, and the Cases database, each independent.

### API Keys tab

Programmatic keys for the Integrations API are managed in the separate **API Keys** tab: create/revoke keys, scope them (full or feed-only), set expiry and per-key rate limits, and watch a usage sparkline. Environment-variable keys appear as read-only bootstrap entries.

---

## Data Retention

- Each run writes Zeek and carved-file outputs into **per-run directories**: `data/zeek/<case>_<uuid8>/` and `data/carved/<case>_<uuid8>/` — concurrent runs never clobber each other.
- Stale run directories are **pruned automatically after 7 days** (on the next run). **Export any evidence you need to keep** — carved payloads, Zeek logs — before they age out.
- OSINT responses and reverse-DNS results are cached in SQLite (rDNS TTL: 7 days) to preserve API quotas; clear them from Config when you need fresh lookups.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Red banner: required binary missing (e.g. `tshark`) | Dependencies not installed | Follow the banner's OS-specific hint, or run `python3 scripts/install.py`; verify with `make doctor`. In Docker this never happens — binaries are baked in |
| YARA panel: "no rules configured" | No rules directory set and `data/yara_rules/` absent | Set Config → YARA Rules to your rules folder, or create `data/yara_rules/` (Docker: `./data/yara_rules`); check the live rule-count feedback |
| OSINT pill ⏳ *GreyNoise rate limited* | Free/community quota exhausted | Wait for the quota window to reset or upgrade the key; cached results (💾) remain usable |
| LM Studio "Test Connection" fails from Docker | Container networking differs from the host; LAN/loopback addresses may not route directly | Use `http://host.docker.internal:1234/v1` (the compose default). The Docker runtime also adapts a host LAN address such as `192.168.2.114:1234` automatically; confirm LM Studio's server is started |
| OSINT pill ➖ *no data* | Provider has no records for these indicators | Nothing to fix — that's an honest negative, not an error |
| PDF generation error (standalone macOS/Linux) | WeasyPrint system libraries missing | macOS: `brew install pango glib cairo`; Linux: install the `libpango`/`libcairo` set (the installer does this). Docker images include them |
| Dashboard panel shows 📭 after loading a case | That artifact isn't persisted in cases | Re-run the original PCAP to regenerate it |
