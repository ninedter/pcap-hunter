# PCAP Hunter Feature Roadmap

## Status: Phases 1-3 delivered (v1.0.0, historical)

This document originally laid out Phases 1-3 as *planned* work on the way to
a "v1.0.0 Enterprise Ready" milestone. All of it has since shipped: CSV/JSON
export, encrypted config persistence, OSINT response caching, JA3/JA3S
fingerprinting, DNS/DGA/tunneling analysis, TLS certificate extraction,
multi-PCAP batch analysis, YARA scanning, PDF report generation, and case
management are all in production (see `CHANGELOG.md` for the full history
through `1.0.0`). The section below is kept for historical context only —
it is **not** a live plan, and the module paths it originally proposed
(`app/ui/results_tab.py`, `app/db/cases.py`, `app/models/case.py`, etc.) were
early sketches; the actual implementation landed under different paths
(`app/utils/export.py`, `app/database/`, `app/pipeline/`, `app/ui/layout.py`,
`app/reports/pdf_generator.py`, and friends — see `CLAUDE.md` for the current
architecture map).

---

## Post-1.0 — recently landed

Work completed on top of the 1.0.0 baseline:

- **Correctness fixes** — STIX export hash-type/IPv6/JA3 handling routed
  through one shared helper; JA3 attribution de-duplicated via the
  authoritative `lookup_ja3`; internal/private domains filtered out of OSINT
  enrichment before egress; SQLite `cases.db` runs with WAL + busy-timeout to
  avoid lock errors; attack-timeline persistence and beacon-penalty tuning
  fixes for highly-regular HTTPS flows.
- **MITRE ATT&CK wired end-to-end** — the mapping engine now runs in the
  pipeline runner and persists to `analyses.attack_json`; it's threaded
  through the UI and API caller paths, rendered on the dashboard, included in
  the PDF report, and reflected in the IOC feed's `mitre_techniques` field
  (including for UI-saved analyses, so feed output stays consistent
  regardless of how an analysis was produced).
- **HTTP analysis stage** — a new pipeline stage (`app/pipeline/http_analysis.py`)
  adds user-agent/credential/URI heuristics, feeding cleartext-credential and
  suspicious-UA signals into the correlation engine and the Raw Data tab, with
  HTTPS beaconing detection tuned to reduce false positives on regular,
  high-confidence flows.
- **Integrations API additions (tier-1)** — case management endpoints (list,
  get, patch, delete, notes) under `/api/v1/cases`, a single-IOC exact-match
  lookup endpoint, a CEF-formatted IOC feed (with CRLF escaping to prevent
  syslog log injection), and an SSRF-safe job-completion webhook dispatched
  from the queue worker.
- **CI hardening** — a coverage floor (`--cov-fail-under=58`) enforced in the
  test job, an advisory `pip-audit` job plus Dependabot config for pip and
  GitHub Actions updates, and a Docker build-and-test job that builds the
  `test`-stage image (with real Zeek) and runs the in-image suite as a
  second, non-required signal alongside the host-based `test` job.
- **Demo capture** — a synthetic `pcaps/demo.pcap` (DNS/HTTP/beacon traffic)
  plus a "load demo capture" button for a first-run experience without
  needing a real PCAP on hand.

---

## Future ideas (not yet started)

Genuine candidates for future work — none of these are in progress:

- Lateral-movement / SMB traffic detection
- JA4 / JARM fingerprinting (JA3/JA3S only today)
- IPv6-aware OSINT enrichment (current provider integrations are IPv4-centric)
- MISP and Sigma export formats (STIX 2.0/2.1, ATT&CK Navigator, and CSV/JSON
  are already supported)
- Per-case configuration profiles (today's config is global, one machine-wide
  `ConfigManager` instance)
- Multi-user support with role-based access control and an audit trail
  (the app currently assumes a single local analyst)
- Configurable case/analysis retention policy (currently manual "clear data"
  actions only; no automatic expiry)
