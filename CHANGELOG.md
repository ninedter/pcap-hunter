# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-07-14

Version 2 turns PCAP Hunter into a more evidence-aware investigation workbench and strengthens both interactive and headless analysis paths.

### Added

- **Dedicated MITRE ATT&CK Analysis workspace** with versioned technique hypotheses, supporting evidence, applicable Detection Strategy context, analyst dispositions, coverage gaps, and ATT&CK Navigator export.
- **Capture-quality telemetry** covering packet and flow scale, parse ratio, capture time window, sampling limits, pipeline warnings, completed stages, and detector availability.
- **Persistent ATT&CK and capture context** in saved analyses and API results; IOC feeds now include related technique IDs across contributing analyses.
- **Validated Streamlit uploads** that stream `.pcap` and `.pcapng` files in bounded chunks, enforce file and batch limits, validate magic bytes, and roll back partial batches.
- **LLM-optional evidence snapshot** so parsed flows, artifacts, correlations, stage status, and warnings remain visible when the narrative is skipped or unavailable.
- **Two additional real-app screenshots** for MITRE Analysis and API Key Management, with isolated capture data, IPv4/IPv6 pixel redaction, and a final OCR audit.

### Changed

- **Integrations API submission lifecycle** now initializes the worker queue only for accepted submissions and removes provisional uploads and cases if queueing or persistence fails.
- **Readiness checks** no longer initialize the background job queue as a side effect.
- **Docker LM Studio routing** adapts loopback and private host addresses to `host.docker.internal` for local-compatible providers.
- **Case analysis updates** use an upsert that replaces stale IOC rows without deleting the parent analysis record.
- **PDF timestamps** are emitted consistently in UTC.
- **Navigator exports** now declare the current Navigator 5.3.2 application version while retaining layer schema 4.5.
- **Version metadata** is unified at `2.0.0` for the package, FastAPI schema, documentation, tag, and GitHub release.

### Fixed

- HTTP payload carving now decodes compact and colon-separated tshark byte-array output before hashing and writing files.
- Capture metrics tolerate flows with missing or malformed timestamps instead of failing the MITRE workspace.
- ATT&CK mappings restored from SQLite remain normalized in session state, so analyst dispositions and notes survive Streamlit reruns.
- The LLM evidence snapshot now reads the canonical `parsed_packet_count` capture metric.
- Rejected API uploads no longer leave orphaned files or empty cases when the queue is full or cannot initialize.

### Docs

- Rewritten README visual tour covering all ten primary tabs with actual Docker UI captures.
- Updated English and Traditional Chinese manuals for MITRE analysis, capture coverage, and Docker-hosted LM Studio routing.
- Updated Integrations API examples for capture metrics, ATT&CK mappings, IOC technique IDs, and cleanup semantics.

## [1.0.0] - 2026-04-22

First stable release. Production-ready installer, hardened pipeline, polished UX, and brand identity.

### Added
- **Brand identity** — logo, favicons (16/32/48/180/512/ico), header mark, and PDF cover-page logo with tagline. Source SVG + `scripts/build_logo_assets.py` to regenerate raster assets.
- **Visual tour in README** — eight redacted screenshots covering every tab, captured by `scripts/capture_screenshots.py` (Playwright + two-pass IP redaction with DOM bounding boxes and tesseract OCR fallback for canvas-rendered grids).
- **Auto-crop screenshot pipeline** — capture script trims trailing whitespace and any post-content duplicate render, so README screenshots stay tight to actual content.
- **PDF report dashboard charts** — protocol distribution, top talkers, flow timeline, network graph, and world map are now embedded directly in the PDF (rendered via kaleido) for static handoff.
- **Cross-platform unified installer** (`scripts/install.py`) — single Python script handles macOS (`brew`), Linux (`apt`), and Windows (`winget` → `choco` → `scoop`). Idiomatic per-platform wrappers (`make install`, `scripts/install.ps1`) all delegate to it. Flags: `--check-only`, `--skip-system`, `--skip-python`, `--dry-run`, `--yes`.
- **Windows installation support** — native install path via PowerShell wrapper that bootstraps Python if missing.
- **Dependency preflight** — startup check shows a red banner at the top of every page if any required system binary is missing, eliminating silent empty-dashboard failures from a missing `tshark` or `zeek`.
- **`make verify` pre-commit gate** — single command runs format check + lint + full test suite. Mirrors CI exactly.
- **Enriched LLM report prompts** — per-section evidence routing with structured context (correlations, beacons, DNS, TLS, OSINT) replaces the prior monolithic prompt.

### Changed
- **PDF cover page redesign** — logo + tagline above the title, with classification banner and metadata block.
- **Kaleido upgraded to 1.x** — 0.x reaches end-of-life September 2025; 1.x is the active branch.
- **Testing discipline overhauled** — production-shape test data (real `CorrelationSignal` dataclasses, real DataFrames, nested dicts the pipeline actually produces) instead of simplified inputs. Documented in `CLAUDE.md` with bug-pattern history. New integration tests for every PDF section and chart.
- **Version bumped to 1.0.0** with consolidated release notes.

### Fixed
- **WeasyPrint PDF export on macOS** failed with `OSError: cannot load library 'libgobject-2.0-0'` because dyld doesn't search `/opt/homebrew/lib` by default. Fix sets `DYLD_FALLBACK_LIBRARY_PATH` before the WeasyPrint import.
- **PDF generation crashed on correlations** with `TypeError: expected str instance, CorrelationSignal found` — `c.signals` is a list of dataclasses, not strings. Fix extracts `.name` before joining.
- **LLM reports showed duplicate section headings** because prompts wrapped section names in `**bold**`, which LLMs echoed back. Fix removes the wrap and adds a leading-title strip as safety net.
- **Pre-deployment hardening pass** — security (input validation, ReDoS prevention), structured logging, type-hint coverage, expanded test coverage.

### Docs
- Visual tour in README with 8 redacted screenshots.
- Updated installation docs with Windows + WSL2 + Docker paths.
- Multi-language user manuals (EN + zh-TW) refreshed.

## [0.6.0-alpha] - 2026-04-07

### Added
- **Parallel Pipeline Execution**:
    - PyShark packet parsing and Zeek log processing now run concurrently via `ThreadPoolExecutor`.
    - HTTP carving runs in parallel with DNS/TLS/Beaconing analysis.
    - Tshark `-c` flag optimization enforces packet limits at the tshark level for zero-waste I/O.
    - Configurable via `PARALLEL_PARSE_ENABLED` and `MAX_PARALLEL_WORKERS` in `app/config.py`.
- **Multi-PCAP Batch Upload**:
    - Upload and analyze multiple PCAP files simultaneously with automatic batch mode detection.
    - Cross-file correlation detects shared IPs, domains, and JA3 fingerprints across files.
    - Per-file summary cards and aggregated batch metrics in the dashboard.
    - Resource limits: 50 files max, 1 GB per file, 5 GB total (configurable).
- **Bulk Reverse DNS Resolution**:
    - Parallel rDNS resolution for all public IPs via ThreadPoolExecutor.
    - Dedicated SQLite cache with 7-day TTL to avoid redundant lookups.
    - Resolved hostnames displayed throughout the dashboard (Top 10 tables, correlation, OSINT).
- **Threat Summary Panel**:
    - Five-metric panel at the top of the dashboard: Risk Level, Total Alerts, Beacon Candidates, YARA Hits, and Cert Issues.
    - Corroboration-based escalation: requires 2+ signal categories for Medium; YARA or high-confidence OSINT for High/Critical.
- **Sankey Flow Diagram**:
    - Client IP → Service Port → Server IP flow visualization alongside the network communication graph.
    - Automatic flow normalization: well-known port side (< 10000) determines server direction.
    - Ephemeral ports (>= 10000) excluded; namespaced nodes prevent cross-column merging.
    - Human-readable port labels (e.g., "443 (HTTPS)", "53 (DNS)").
- **Dashboard Detection Panels**:
    - Beaconing candidates (0.6+ threshold), YARA matches, and TLS certificate risks surfaced directly on the dashboard.
- **Cross-Indicator Correlation Section**:
    - Dedicated dashboard section for the correlation engine's composite threat scores.

### Changed
- **Threat Scoring Overhaul**:
    - Replaced linear summation with independence-complement formula (`1 − Π(1 − wᵢsᵢ)`) for composite scoring.
    - Introduced tiered signal architecture: Tier 1 (OSINT definitive), Tier 2 (behavioral), Tier 3 (contextual).
    - Added strong-signal floors: confirmed VirusTotal detections set minimum score regardless of other factors.
    - Tier 3 signals alone capped at "medium" severity.
- **Beacon False-Positive Reduction**:
    - Infrastructure allowlist (1.1.1.1, 8.8.8.8, 9.9.9.9, etc.) applies ×0.15 penalty.
    - Protocol awareness: ICMP, NTP, mDNS, SSDP, IGMP flagged as inherently periodic (×0.2).
    - Service port penalties: HTTPS (×0.5), IMAPS (×0.2), Apple Push (×0.2), MQTT (×0.3).
    - High-volume large-payload filter (×0.3 when >200 packets + >500 avg bytes).
- **LLM Report Generation**:
    - Restructured system instructions: Characterize → Identify → Assess → Recommend workflow.
    - Added severity calibration guide with concrete examples per severity level.
    - Built-in false-positive awareness section to prevent over-rating benign traffic.
    - Pre-computed correlation verdicts, risk distributions, and top threats passed to LLM context.
- **Dashboard Layout**:
    - Sankey diagram placed alongside the network communication graph.
    - Correlation moved from inline display to its own dedicated section.
    - Beacon display threshold raised from 0.5 to 0.6.

### Fixed
- **Test Suite**: Updated test IPs from infrastructure-allowlisted addresses (1.1.1.1) to private ranges (10.0.0.1) to prevent false test failures.
- **Lint Issues**: Resolved pre-existing E501, F841, unused import, and import sorting issues across multiple modules.

## [0.5.1-alpha] - 2026-01-05

### Added
- **Cascading Home Location Selectors**: Replaced raw coordinate input with intuitive Continent -> Country -> City dropdowns in the Config tab.
- **Granular Data Management**: Added dedicated buttons to clear PCAP data, OSINT cache, and Case/Analysis records independently.
- **Geographic Utilities**: New `geo_data.py` utility handling worldwide city datasets for precise location resolution.

### Changed
- **Dashboard Aesthetics**: 
    - Refined flow timeline with optimized marker sizes, opacity, and professional color palettes.
    - Moved timeline legends to the bottom for a cleaner interactive workspace.
    - Improved sectioning with custom 'card' styles and subtle borders.
- **Filter Persistence**: The "Exclude Private IPs" toggle is now persistent across all chart interactions and integrated into the "Clear All Filters" logic.
- **Enhanced OSINT Table**: Added Country and City columns to the IP OSINT results for better immediate context.

### Fixed
- **LLM Context Overflow**: Implemented aggressive sanitation and list truncation for flow data to prevent token limit issues with large PCAPs.
- **UI Performance**: Updated deprecated Streamlit parameters for better layout stability across different browser widths.
- **Syntax & Safety**: Resolved minor syntax errors in dashboard logic and improved error handling in data clearing operations.
- **Test Coverage**: Added 61 new/updated unit tests covering geographic resolution and repository resets.

## [0.5.0-alpha] - 2026-01-05

### Added
- **MITRE ATT&CK Mapping**: 
    - Automated mapping of detected behaviors and IOCs to the MITRE ATT&CK framework.
    - Identification of Kill Chain phases and overall campaign severity.
- **Attack Narrative Generation**:
    - AI-driven synthesis of timeline events into a coherent security narrative.
    - Professional reporting in multiple languages (English, Chinese, Japanese, etc.).
- **IOC Priority Scoring**:
    - Automated risk assessment system that ranks indicators (Critical to Low) based on OSINT, behavior, and context.
    - Factors include C2 beaconing scores, VirusTotal detections, DGA likelihood, and JA3/JA3S fingerprinting.
- **Case Management System**:
    - A dedicated investigation workspace to track findings, manage observables, and store case notes.
- **Advanced DNS & TLS Forensics**:
    - Enhanced DGA detection using Shannon entropy and tunneling analysis.
    - Comprehensive TLS analysis including certificate chain validation and JA3 fingerprinting.
- **YARA Scanner**:
    - Real-time YARA scanning of files carved from HTTP traffic.
- **PDF Report Export**:
    - Professional, formatted PDF reports containing executive summaries, interactive chart snapshots, and technical details.

### Fixed
- **System Stability**: Resolved missing `pango` dependency issue causing PDF generation failures on macOS.
- **UI Architecture**: Fixed a `NameError` in the main dashboard and restored the missing "LLM Analysis" tab for better flow.
- **Test Integrity**: Fixed environmental issues preventing the execution of the 300+ test suite.

## [0.4.0-alpha] - 2025-12-30

### Added
- **Live Traffic Capture**: 
    - Real-time local traffic capture using `tshark` directly from the Upload interface.
    - Automatic integration of captured PCAPs into the analysis pipeline.
- **Enhanced OSINT & Device ID**:
    - **GeoIP Integration**: Added City and Country of origin for public IPs in OSINT results.
    - **Hardware Identification**: New "Devices/MACs" tab listing MAC addresses and their manufacturers via OUI lookup.
- **Advanced Dashboard Visualizations**:
    - **TopN Analysis**: Tabulated and graphical analysis for top IPs, Ports, Protocols, and Domains.
    - **Interactive Timeline**: Added a range-slider to the flow timeline, enabling dynamic cross-filtering of all dashboard components (Map, Pie Chart, Bubble Chart, Tables).
- **Packet Metrics**: Extracted packet lengths and added a distribution histogram to the dashboard.

### Changed
- **UI Architecture**: Moved the LLM Threat Report to a dedicated "LLM Analysis" tab for better workspace organization.
- **Packet Parsing**: Updated the pipeline to extract Ethernet MAC addresses and individual packet lengths.


## [0.3.0-alpha] - 2025-12-29

### Added
- **Multi-Language Reporting**:
    - Generates threat reports in 9 supported languages: US English, Traditional Chinese (Taiwan), Simplified Chinese (Mainland), Japanese, Korean, Italian, Spanish, French, and German.
    - Includes proper prompt engineering for region-specific terminology (e.g., Taiwan vs Mainland China usage).
- **Report Management**:
    - **Re-run Report**: Added a button to regenerate only the LLM report using existing artifacts, saving time when switching languages or models.
    - **Clear All Data**: New button to wipe all uploaded PCAPs, Zeek logs, and carved files for a clean workspace.
- **Improved Report Reliability**:
    - Refactored report generation to process sections (Executive Summary, Key Findings, etc.) individually, preventing timeouts and token limit issues on long reports.

### Fixed
- **OSINT Dialogs**: Resolved `StreamlitAPIException` when selecting rows in OSINT tables by improving session state tracking for dialogs.
- **Language Persistence**: Fixed an issue where the selected report language would reset during a re-run by adhering to strict session state binding.
- **Section Localization**: Localized all report section headers (e.g., "Key Findings") for all supported languages, ensuring the entire report is translated.
- **Report Truncation**: Increased token limits for "Recommended Actions" and refined prompts to ensure actionable advice is not cut off.

## [0.2.0-alpha] - 2025-12-01

### Added
- **Interactive World Map**:
    - Visualizes traffic flows with variable line thickness based on packet volume.
    - Supports cross-filtering: clicking a location or connection filters the Protocol and Flow charts.
    - Added a "Clear Selection" button to reset the dashboard view.
- **Dashboard Tab**: A new dedicated tab for high-level visualization (Map, Protocols, Flows) and the LLM Report.
- **Robust Binary Discovery**:
    - Automatically detects `tshark` and `zeek` binaries in common macOS locations (e.g., Wireshark.app, Zeek.app).
    - Added visual status indicators in the **Config** tab to show if binaries are found.
- **Runtime Logging**: A new "Runtime Logs" expander in the **Config** tab to capture and display errors during pipeline execution.
- **Unit Tests**: Added comprehensive tests for charts (`tests/test_charts.py`) and filtering logic (`tests/test_utils.py`).

### Changed
- **Performance Optimization**: Replaced `pyshark` with direct `tshark -T fields` execution for packet parsing, significantly improving speed for large PCAPs.
- **UI Refinements**:
    - Renamed "PyShark parsing" to "Parsing Packets" to reflect the backend change.
    - Renamed "Run PyShark" checkbox to "Run Packet Parsing (Tshark)".
    - Improved map prominence by increasing its height and width.
- **Configuration**:
    - Default LM Studio URL updated to `http://localhost:1234/v1`.
    - `DATA_DIR` changed to `./data` to avoid read-only file system issues.

### Fixed
- **Crash on Map Reset**: Fixed `StreamlitValueAssignmentNotAllowedError` by using a dynamic widget key for the map, ensuring clean resets.
- **Binary Detection**: Resolved issues where `tshark` and `zeek` were not found even when installed.

### [0.1.0-alpha] - 2025-11-24
### Added
- **WHOIS Lookup**:
    - Interactive WHOIS modal for IPs and Domains in the OSINT tab.
    - Displays Registrar, Dates, Registrant Info, and Name Servers in a structured layout.
    - Powered by `python-whois` with robust error handling.
- **Reverse DNS**: Added PTR record resolution for public IPs in the OSINT enrichment pipeline.
- **OSINT Tab**: Moved OSINT findings to a dedicated tab with separate views for "IP Addresses" and "Domains".
- **Zeek DNS Integration**: Automatically merges domains found in Zeek's `dns.log` into the OSINT artifacts list.

### Changed
- **UI Layout**:
    - Reorganized main tabs to include "🕵️ OSINT".
    - OSINT results now use interactive DataFrames with click-to-view functionality.
    - WHOIS dialog layout improved to stack fields vertically for better readability.

### Fixed
- **Missing Domains**: Resolved issue where domains from Zeek logs were not appearing in OSINT results.
- **IP WHOIS**: Fixed failures when querying WHOIS for IP addresses by improving the lookup logic and error handling.
