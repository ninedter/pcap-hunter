# PCAP Hunter — complete functionality map

This map is grounded in the current Streamlit application, user manual, configuration surface, and API-key management UI. The redesign keeps the selected Direction 1 visual language while grouping the ten existing tabs into seven clearer destinations, including a restored first-class Dashboard for familiar analyst visualizations.

## New information architecture

| New destination | Existing functionality moved here | Why it belongs here |
| --- | --- | --- |
| Analyze | Upload, manual path, batch validation, analysis options, durable run progress | Everything needed to start and monitor work is one continuous flow. |
| Dashboard | Threat summary, world flow map, protocol distribution, flow timeline, Top 10s, Sankey, network graph, attack timeline, profiling charts | Existing users keep the visual workspace and interactions they already know. |
| Findings | Verdict, risk explanation, IOC search, correlations, checklist | This remains the quick answer-first decision page. |
| Investigate | Evidence, traffic analysis, MITRE ATT&CK, OSINT, raw data | Deep analysis tools share one workspace with a persistent sub-navigation. |
| Reports | LLM report, report-only rerun, PDF, IOC and SIEM exports | Narrative and handoff outputs are separated from raw investigation. |
| Cases | Case list, saved analyses, notes, IOC search, restore to workbench | Persistent investigation management stays a first-class destination. |
| Settings | LLM, OSINT providers, pipeline, tools/YARA, map, API access, data, logs | All configuration and administration lives in one predictable place. |

## Capability-level mapping

### Analyze

| Capability | New placement and interaction |
| --- | --- |
| Multi-PCAP / PCAPNG upload | Large multi-file drop zone with an explicit “Add PCAPs” action and visible batch queue. |
| Manual container path | Secondary path field directly below the drop zone, with allowed-path guidance. |
| Limits and validation | Always-visible limits: 50 files, 1 GB per file, 5 GB total; each queued file receives a validation status. |
| Batch mode | Activates automatically for multiple files and summarizes file count, total size, and cross-file correlation. |
| Invalid or skipped files | Inline file-level validation state, rather than a page-level warning users must interpret. |
| Background LLM report | Toggle beside the run action, with the active provider/model shown. |
| Pipeline profile | Compact summary of enabled stages plus a link to Analysis settings. |
| Durable background execution | Run status explains that the worker survives page reloads and autosaves evidence to a case. |
| Progress | “Run queue” view shows overall progress, per-file status, current stage, and all ten pipeline stages. |
| Completion / failure recovery | Completed evidence links to Findings; failures explain that earlier completed evidence remains in Cases. |

### Findings

| Capability | New placement and interaction |
| --- | --- |
| Risk verdict | Large answer-first verdict with packets/flows analyzed and honest confidence language. |
| Risk explanation | “Why this verdict?” detail panel is attached to the verdict, not buried among charts. |
| Summary metrics | Risk, alerts, beacons, YARA hits, certificate issues, packets, flows, and indicators. |
| IOC search | Persistent search for IPs, domains, hashes, JA3, and URLs with evidence-type filtering. |
| Batch summary | Capture switcher and batch summary appear at the top when multiple files are active. |
| Dashboard handoff | One-click navigation returns analysts to the full visual dashboard without losing the active batch. |
| Correlations and checklist | Recommended actions lead into correlation evidence and a structured hunting checklist. |
| Honest empty states | Every stage distinguishes “ran clean” from “not run / unavailable.” |

### Dashboard

| Capability | Restored placement and interaction |
| --- | --- |
| Threat summary | Risk level, flows, alerts, beacons, YARA hits, and certificate issues remain visible before the charts. |
| Shared filters | Search, protocol, private-IP exclusion, and clear/reset apply to the dashboard’s mapped destinations. |
| World flow map | Full-width interactive map with home location, public destinations, packet-weighted flow paths, hover/click selection, zoom, pan, and selected-flow details. |
| Protocol distribution | Familiar donut chart with clickable protocol context and total flow count. |
| Flow timeline | Time-series overview with flow-per-minute detail. |
| Top 10 analysis | IP and domain modes with ranked bars and a readable companion table. |
| Sankey flow | Client → service → server paths weighted by packet volume. |
| Network graph | Connection-weighted endpoints with assessment coloring and a readable node key. |
| Attack timeline | Time and severity plot for analytical observations. |
| Traffic profiling | Packet-size histogram, inter-arrival histogram, and destination traffic heatmap. |

### Investigate

| Sub-area | Existing capability mapped here |
| --- | --- |
| Evidence | Global IOC search; IP/domain/hash/JA3/URL filters; priority, context, status, and source capture. |
| Traffic | Map, protocol distribution, timeline, Top 10 IP/domain views, Sankey, network graph, packet-size and inter-arrival histograms, traffic heatmap, flow asymmetry, port anomalies, and beacon candidates. |
| MITRE ATT&CK | Hypotheses, confidence, evidence, analyst disposition and note, capture profile, detector coverage/gaps, and Navigator export. |
| Threat Intel | Provider status and coverage, IP triage, domain reputation, WHOIS, passive DNS, detail cards, geo map, ASN grouping, related IOCs, OTX attribution, devices/MACs, analyst notes, and IOC exports. |
| Raw Data | Flow rows, DNS/DGA/tunneling/NXDOMAIN/query velocity, TLS certificates, JA3/JA3S, Zeek logs, carved payloads and hashes, YARA results, correlations, flow asymmetry, and port anomalies. |

### Reports and exports

| Capability | New placement and interaction |
| --- | --- |
| AI threat report | Reports → AI report, with provider/model/language and evidence coverage shown before generation. |
| Report-only rerun | “Regenerate report” updates the narrative without reprocessing the PCAP. |
| Analysis snapshot | Deterministic evidence summary remains visible when no LLM report exists. |
| PDF report | Reports → Exports, with analyst/organization/TLP metadata and generate/download states. |
| Table exports | CSV and JSON actions live with each relevant evidence table. |
| IOC exports | CSV, JSON, STIX 2.0/2.1, and clipboard-ready formats. |
| Security integrations | CEF and ATT&CK Navigator exports are grouped with the target integration. |

### Cases

| Capability | New placement and interaction |
| --- | --- |
| Case list | Search plus status/tag filters, summary metrics, severity, analysis count, and updated date. |
| Create and quick-save | “New case” and “Save current analysis” stay prominent. |
| Cross-case IOC search | Dedicated IOC search mode with type filter and case results. |
| Case detail | Metadata, status/severity/tags, edit, close/reopen, add analysis, and delete confirmation. |
| Saved analyses | Each analysis shows PCAP path/hash, packet/flow/IOC counts, report preview, and “Load into workbench.” |
| Notes | Add and delete timestamped investigation notes. |
| Case IOCs | Consolidated IOC table and CSV export. |

### Settings and administration

| Settings section | Full capability set |
| --- | --- |
| LLM & reports | LM Studio, OpenAI, Anthropic; base URL; API key; model; fetch models; test connection; report language; 10K–1M context window; unlimited mode; report-only rerun. |
| Threat intelligence | OTX, VirusTotal, AbuseIPDB, GreyNoise, Shodan keys; per-provider status; test all; OSINT Top-N; cache enablement. |
| Analysis pipeline | Packet limit; packet pre-count; tshark parsing; Zeek; DNS; TLS; beaconing; HTTP carving; YARA; OSINT; LLM. |
| Tools & YARA | Zeek and tshark binary overrides with health status; recursive YARA rules directory and rule-file count. |
| Map & location | Continent, country, city, resolved latitude/longitude for traffic arcs. |
| API access | Active keys, requests today, expiry warnings, usage charts, environment keys, create/revoke, feed/full scope, expiry, and per-key rate limits. |
| Data & retention | Seven-day run-directory policy; clear PCAP data, OSINT cache, or cases independently with confirmation. |
| Runtime logs | Read-only diagnostic log viewer. |
| Configuration lifecycle | Save, load, apply/reload, and reset defaults; sensitive values described as encrypted at rest. |

## Intentional UX changes

- Settings is a full workspace instead of a small modal because it contains several complete configuration systems.
- Progress is part of Analyze so starting and monitoring a run feels continuous.
- The Dashboard stays top-level because its spatial and comparative visualizations are a learned analyst workflow, not an optional investigation tool.
- MITRE, OSINT, detailed Traffic evidence, and Raw Data remain sub-workspaces under Investigate, reducing duplication without hiding capability.
- API keys move under Settings → API access but remain directly reachable from the settings sidebar.
- Reports owns all narrative and export actions, while evidence stays in Investigate.
