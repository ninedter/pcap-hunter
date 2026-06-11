# CLAUDE.md — PCAP Hunter

## Project Overview

PCAP Hunter is an AI-enhanced threat hunting workbench for SOC analysts. It combines network analysis tools (Zeek, Tshark, PyShark) with LLMs and OSINT APIs to ingest, analyze, and extract actionable intelligence from PCAP files. Built with Streamlit for the web UI.

## Quick Reference

```bash
make install          # pip install -r requirements.txt
make run              # streamlit run app/main.py (port 8501)
make test             # PYTHONPATH=. pytest tests/ -v --cov=app
make lint             # ruff check .
make format           # ruff format .
make clean            # Remove caches
make docker-up        # Build + run the UI in Docker (http://localhost:8501)
make docker-verify    # Format + lint + full test suite INSIDE the image
```

Always run tests with `PYTHONPATH=.` — this is required for absolute imports to resolve.

### Docker is the canonical build-and-verify path

**Any local verification that requires a build must go through Docker**
(`make docker-up` to run the app, `make docker-verify` for the gate). The
host machine has multiple coexisting Python installs (framework + Homebrew),
so host-side "it works here" proves nothing about a clean environment —
a fresh-install breakage shipped exactly that way once. `make verify` on the
host remains fine for fast iteration; anything build-shaped (dependency
changes, install paths, release checks, user-facing verification) runs in
the container.

API keys saved inside the container persist in the `pcap-hunter-home` volume
(mounted at `/home/runner`, with a pinned `hostname:` so the config encryption
key stays stable); LM Studio on the host is reachable via
`host.docker.internal` — the compose file defaults `LM_BASE_URL` accordingly.

## Architecture

```
app/
├── main.py              # Streamlit entry point (session state, 9-tab UI)
├── config.py            # App defaults & constants (thresholds, paths)
├── analysis/            # Scoring, correlation, flow analysis, narration
├── database/            # SQLite case management (models.py, repository.py)
├── llm/                 # OpenAI-compatible API client (LM Studio supported)
├── pipeline/            # 10-stage analysis pipeline (pcap → report)
├── reports/             # PDF generation (WeasyPrint + Jinja2)
├── security/            # OPSEC hardening (sanitization, secure HTTP)
├── threat_intel/        # MITRE ATT&CK mapping engine
├── ui/                  # Streamlit components (layout, charts, config, cases)
└── utils/               # Shared utilities (export, crypto, network, YARA)
tests/                   # 22+ test modules, one per major component
docs/                    # EN + zh-TW user manuals, roadmap, test plan
data/                    # Runtime artifacts (carved/, zeek/, *.db) — gitignored
```

### 10-Stage Pipeline

1. `pcap_count.py` — Fast packet counting (tshark)
2. `pyshark_pass.py` — Deep packet parsing (up to 200K packets)
3. `zeek.py` — Automated Zeek execution and log parsing
4. `dns_analysis.py` — DGA detection, DNS tunneling, fast flux
5. `tls_certs.py` — TLS/SSL certificate chain validation
6. `beacon.py` — C2 beaconing detection (statistical analysis)
7. `carve.py` — HTTP payload extraction with SHA256 hashing
8. `yara_scan.py` — YARA rule-based file scanning
9. `osint.py` — Multi-provider OSINT enrichment (VT, AbuseIPDB, Shodan, etc.)
10. LLM synthesis — AI-powered threat report generation

Stages 2–3 (PyShark, Zeek) run in parallel; after that parse join, stages 4–7
(DNS, TLS, beaconing, carving) run concurrently. Zeek and carve write into
per-run output dirs (`data/zeek|carved/<case>_<uuid8>/`) so concurrent runs
never clobber each other; stale run dirs are pruned after 7 days.

## Tech Stack

- **Python 3.11+**, Streamlit 1.36+, Pandas 2.2+, NumPy 1.26+
- **Network**: Zeek, Tshark, PyShark 0.6+, Scapy 2.5+
- **LLM**: OpenAI SDK 1.30+ (LM Studio compatible)
- **OSINT**: VirusTotal, AbuseIPDB, GreyNoise, OTX, Shodan, MaxMind GeoIP
- **Security**: cryptography 42.0+ (PBKDF2 encrypted config)
- **Export**: WeasyPrint (PDF), STIX 2.0/2.1, ATT&CK Navigator, CSV/JSON
- **Dev**: Ruff (lint+format), Pytest 8.0+, pytest-cov, GitHub Actions CI

## Code Conventions

### Style

- **Formatter/Linter**: Ruff — line length 120, double quotes, 4-space indent
- **Lint rules**: E, F, I, W (see `pyproject.toml` for per-file ignores)
- **Type hints**: Used extensively; `from __future__ import annotations` for forward compat
- **Docstrings**: Google-style (Args/Returns sections) on public functions

### Naming

- Modules: `snake_case.py` (e.g., `ioc_scorer.py`, `dns_analysis.py`)
- Classes: `PascalCase` (e.g., `IOCScorer`, `ConfigManager`)
- Functions: `snake_case` (e.g., `rank_beaconing`, `validate_domain`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_DOMAIN_LENGTH`, `DATA_DIR`)
- Private: leading underscore (e.g., `_sanitize_for_llm`)

### Imports

- Always use **absolute imports**: `from app.pipeline.beacon import rank_beaconing`
- Standard library → third-party → local app modules (enforced by ruff `I` rule)
- Backward-compatible re-exports exist in `app/utils/common.py`

### Error Handling

- Custom exceptions inherit from `Exception` (e.g., `CarveError`)
- Use `logging` module, not print statements
- Streamlit phases use `phase.done()` for completion tracking

### Data Modeling

- Prefer `dataclass` for structured data
- Enums for fixed categories (e.g., `Severity`, `CaseStatus`)

## Testing

- **Framework**: Pytest with `--cov=app`
- **Location**: `tests/test_<module>.py` — one test file per major module
- **Run**: `make test` or `PYTHONPATH=. pytest tests/ -v --cov=app`
- **Pre-commit gate**: `make verify` — runs format check + lint + full test suite
- **PDF-focused**: `make test-pdf` — PDF generator, chart images, chart rendering, integration
- **Conventions**:
  - Test classes: `Test<Feature>` (e.g., `TestTechniqueMatch`)
  - Test functions: `test_<scenario>` (e.g., `test_periodicity_score_empty`)
  - Test both happy path and edge cases (empty, None, malformed)
  - Use dataclass instances for complex test objects
  - No shared conftest.py fixtures — tests are independent

### Testing discipline (non-negotiable)

**Before every commit, run `make verify`.** It must pass. CI runs the same
checks, so if `make verify` fails locally it will fail in CI.

**Use production-shape test data, not "looks reasonable" dicts.** If the
code consumes `list[CorrelationSignal]` dataclasses, tests must pass actual
dataclasses — not dicts that happen to have similar keys. Simplified
inputs are exactly what let the `', '.join(c.signals)` bug slip past 500+
unit tests into production. See `tests/test_pdf_integration.py` for the
shapes every PDF-related code path should accept.

**When adding a new PDF section, extend the integration test.** A new
`_render_*_section()` in `pdf_generator.py` needs a corresponding assertion
in `test_pdf_integration.py::test_html_contains_every_expected_section`
that verifies the section ID and at least one key token appear in the
output HTML.

**When adding a new chart to the PDF, extend `test_chart_rendering.py`.**
Any chart called from `_render_charts_section` must have a smoke test that
passes production-shape data and asserts the figure renders to PNG via
kaleido. This catches two recurring bug classes:
  1. API drift between the chart function and the PDF call site
  2. Runtime render failures (colorscale issues, unicode, etc.)

**`@pytest.mark.skipif` on macOS — import `pdf_generator` first.** Any
test that skips based on `WEASYPRINT_AVAILABLE` must import `pdf_generator`
**before** touching `weasyprint`, otherwise the dyld path fix hasn't run
yet and the test silently skips on a working system. See the import block
in `tests/test_pdf_generator.py` for the correct pattern.

### Historical bug patterns — don't repeat these

| Bug | Lesson |
|-----|--------|
| LLM sections showed duplicated headings (`## Title\n\nTitle\n\n...`) | Don't wrap section names in `**bold**` in prompts — LLMs echo them back. Strip leading title lines as a safety net. |
| WeasyPrint crashed with `OSError: cannot load library 'libgobject-2.0-0'` | macOS dyld doesn't search `/opt/homebrew/lib` by default. Set `DYLD_FALLBACK_LIBRARY_PATH` before the `weasyprint` import. Catch `(ImportError, OSError)`, not just `ImportError`. |
| PDF generation crashed with `TypeError: expected str instance, CorrelationSignal found` | `c.signals` is `list[CorrelationSignal]`, not `list[str]`. Extract `.name` before joining. |
| PDF tests silently skipped on macOS despite working app | Test module imported `weasyprint` directly before `pdf_generator`, so DYLD fix hadn't run. Always import `pdf_generator` first. |
| Empty dashboard after PCAP upload | `tshark` wasn't installed. Pre-flight check in `app/main.py` now shows a red banner. |
| Chart API mismatch between function and call site | `plot_top_n_charts` expects a flat `dict[str, int]`, not nested. `plot_network_graph` takes `flows` positionally. Smoke tests in `test_chart_rendering.py` catch this. |

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`):
- Triggers on push/PR to `main`
- Python 3.11, Ubuntu latest
- Steps: install deps → pytest with coverage → ruff check → ruff format --check

## Configuration

- Defaults in `app/config.py` (thresholds, paths, URLs)
- Persistent config: `~/.pcap_hunter_config.json` (via `ConfigManager`)
- API keys encrypted with machine-derived PBKDF2 key
- Environment variable overrides: `OTT_KEY`, `VT_KEY`, `SHODAN_KEY`, etc.
- LLM defaults: `http://localhost:1234/v1` (LM Studio)

## Key Thresholds (config.py)

- DGA entropy: 4.0 bits
- Fast flux: domain resolving to 10+ IPs
- Flow asymmetry: 10:1 outbound/inbound ratio, 1MB minimum
- C2 common ports: {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}
- Default PyShark limit: 200,000 packets
- OSINT top IPs default: 50
- `MAX_FLOW_SAMPLES`: 5,000 per-flow packet timestamps/lengths (true totals kept in `count`/`first_ts`/`last_ts`)
- `RUN_DIR_RETENTION_SECONDS`: 7 days — per-run `data/zeek|carved/<run_id>/` dirs pruned on the next run
- Subprocess timeouts: `ZEEK_TIMEOUT_SECONDS` 600, `PCAP_COUNT_TIMEOUT_SECONDS` 120, `CARVE_TIMEOUT_SECONDS` 300, `TLS_EXTRACT_TIMEOUT_SECONDS` 300, `LLM_PROBE_TIMEOUT_SECONDS` 15

## Git Conventions

- Branch: `main` (production)
- Commit messages: conventional-commits style — `feat:`, `fix:`, `docs:`, `style:`, `chore:`
- Lowercase descriptions after prefix
- Always run `make test` and `make lint` before committing

## Security Considerations

- Never commit API keys or `.env` files
- Config encryption via `ConfigManager` for sensitive keys
- CSV injection protection in all exports
- Input validation for domains, IPs (ReDoS prevention)
- Hardened HTTP sessions via `opsec.py`
- YARA rules loaded from user-supplied paths — validate carefully

## Adding a New Pipeline Stage

1. Create `app/pipeline/<stage_name>.py` with the analysis logic
2. Add phase tracking via `app/pipeline/state.py`
3. Wire into `app/main.py` pipeline execution flow
4. Add corresponding UI rendering in `app/ui/layout.py`
5. Create `tests/test_<stage_name>.py` with edge case coverage
6. Update `app/config.py` if new thresholds/defaults needed

## Adding a New OSINT Provider

1. Add API integration in `app/pipeline/osint.py`
2. Add config key in `app/config.py` and `cfg_<provider>_key` encryption in `ConfigManager`
3. Add UI controls in `app/ui/config_ui.py`
4. Update IOC scoring weights in `app/analysis/ioc_scorer.py`
5. Add tests in `tests/` and update documentation
