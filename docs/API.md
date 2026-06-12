# PCAP Hunter Integrations API

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1-6BA539.svg)](https://spec.openapis.org/oas/v3.1.0)

The Integrations API lets external platforms (SOAR, SIEM, log analysis tools, custom scripts) submit PCAPs for analysis and consume extracted IOCs as a feed. It runs as a separate `uvicorn` process alongside the Streamlit UI, sharing the same pipeline, case database, and configuration.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [API Key Management](#api-key-management)
- [Endpoints Reference](#endpoints-reference)
  - [Health](#health)
  - [PCAP Ingestion](#pcap-ingestion)
  - [Job Tracking](#job-tracking)
  - [Case Management](#case-management)
  - [IOC Feed](#ioc-feed)
  - [Admin / Key Management](#admin--key-management)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [Configuration Reference](#configuration-reference)
- [SIEM Integration Examples](#siem-integration-examples)
- [Architecture Notes](#architecture-notes)

---

## Quick Start

### 1. Set a bootstrap API key and start the server

```bash
export PCAP_HUNTER_API_KEY=your-secret-key-here
uvicorn app.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

> The module exposes only the `create_app()` factory — the `--factory` flag is required. `uvicorn app.api.app:app` will not start.

Or with the Makefile:

```bash
PCAP_HUNTER_API_KEY=changeme make run-api
```

### 2. Verify the server is healthy

```bash
curl http://localhost:8000/healthz
# {"status": "ok"}

curl http://localhost:8000/readyz
# {"status": "ready"}
```

### 3. Submit a PCAP for analysis

```bash
curl -X POST http://localhost:8000/api/v1/pcaps \
  -H "Authorization: Bearer your-secret-key-here" \
  -F "pcap=@traffic.pcap" \
  -F "name=Incident 2026-0042"
```

Response (202 Accepted):

```json
{
  "job_id": "j_a1b2c3d4",
  "case_id": "e5f6a7b8",
  "status": "queued",
  "links": {
    "status": "/api/v1/jobs/j_a1b2c3d4",
    "result": "/api/v1/jobs/j_a1b2c3d4/result",
    "case": "/api/v1/cases/e5f6a7b8"
  }
}
```

> Job IDs carry a `j_` prefix; case IDs are bare 8-character hex strings (no `c_` prefix).

### 4. Poll for completion

```bash
curl http://localhost:8000/api/v1/jobs/j_a1b2c3d4 \
  -H "Authorization: Bearer your-secret-key-here"
```

### 5. Retrieve the IOC feed

```bash
curl "http://localhost:8000/api/v1/iocs.json?min_score=50" \
  -H "Authorization: Bearer your-secret-key-here"
```

---

## Authentication

Every request (except `/healthz`, `/readyz`, and the documentation endpoints) requires a Bearer token in the `Authorization` header:

```
Authorization: Bearer <token>
```

### Auth Sources (checked in order)

| Priority | Source | Token Format | How to Set |
|----------|--------|-------------|------------|
| 1 | Environment variable (main) | Any string | `PCAP_HUNTER_API_KEY=...` |
| 2 | Environment variable (feed) | Any string | `PCAP_HUNTER_FEED_KEY=...` |
| 3 | Database-backed keys | `phk_` prefix + 32 hex chars | Created via admin endpoints or Streamlit UI |

Environment-variable keys are checked first using constant-time comparison (no database query). If neither matches, the token is SHA-256 hashed and looked up in the key database.

### Scopes

| Scope | Access | Typical Use |
|-------|--------|-------------|
| `full` | All endpoints | SOAR integrations, admin scripts |
| `feed` | IOC feed endpoints only (`/api/v1/iocs.*`) | SIEM pull agents, threat intel platforms |

- `PCAP_HUNTER_API_KEY` grants `full` scope.
- `PCAP_HUNTER_FEED_KEY` grants `feed` scope.
- Database keys carry their scope in the key record.

### Startup Requirement

The API **refuses to start** if no authentication source is configured (no env vars and no DB keys). This prevents accidentally running an unauthenticated API.

Two softer conditions log a **startup warning** instead of refusing to boot:

- **No full-scope source** — no `PCAP_HUNTER_API_KEY` env var and no active full-scope DB key. The server starts (feed keys may still work), but ingress and admin endpoints reject every request until a full-scope source exists. The warning includes recovery instructions.
- **Keyless boot** — neither env var is set and auth relies entirely on DB-backed keys. This is a common symptom of re-upping a compose stack without re-exporting the key env vars; check the warning if clients suddenly start receiving 401s after a restart.

### Unauthenticated Documentation Endpoints

`/docs` (Swagger UI), `/redoc`, and the OpenAPI JSON (`/api/v1/openapi.json`) are **intentionally unauthenticated** — front the API with a reverse proxy if exposing it beyond localhost.

---

## API Key Management

Database-backed keys provide per-key tracking, expiration, rate limiting, and revocation without restarting the server.

### Key Format

Keys use the format `phk_<32 hex chars>` (36 characters total). Example:

```
phk_a1b2c3d4e5f6789012345678abcdef01
```

- Only the SHA-256 hash is stored in the database (never the raw key).
- The prefix `phk_a1b2` is stored for display in key lists.
- The raw key is shown **exactly once** at creation time.

### Create a Key via API

```bash
curl -X POST http://localhost:8000/api/v1/admin/keys \
  -H "Authorization: Bearer your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "splunk-feed-puller",
    "scope": "feed",
    "description": "Splunk SOAR IOC feed integration",
    "rate_limit_rpm": 60,
    "expires_in_days": 365
  }'
```

Response (201 Created):

```json
{
  "id": "k_a1b2c3d4e5f6",
  "key": "phk_a1b2c3d4e5f6789012345678abcdef01",
  "name": "splunk-feed-puller",
  "prefix": "phk_a1b2",
  "scope": "feed",
  "expires_at": "2027-05-25T00:00:00Z",
  "rate_limit_rpm": 60
}
```

> **Save the `key` value immediately.** It cannot be retrieved later.

### Create a Key via Streamlit UI

Navigate to the **API Keys** tab in the Streamlit interface to create, view, and revoke keys with a visual management interface.

### Key Lifecycle

| State | Meaning |
|-------|---------|
| `active` | Normal operation |
| `expiring_soon` | Expires within 7 days |
| `expired` | Past expiration date; requests are rejected |
| `revoked` | Manually revoked; requests are rejected |

---

## Endpoints Reference

### Health

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/healthz` | GET | None | Liveness probe |
| `/readyz` | GET | None | Readiness probe (checks DB + disk space) |

```bash
curl http://localhost:8000/readyz
```

The readiness check verifies database connectivity and that at least 1 GiB of disk space is available.

---

### PCAP Ingestion

#### `POST /api/v1/pcaps`

Submit a PCAP file for background analysis.

**Auth:** `full` scope required

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `pcap` | file | Yes | | PCAP or pcapng file |
| `name` | string | No | filename | Case title |
| `tags` | string | No | `[]` | JSON array or comma-separated list |
| `severity_hint` | string | No | | `low`, `medium`, `high`, or `critical` |
| `osint_enabled` | boolean | No | `true` | Run OSINT enrichment after analysis (see below) |
| `llm_enabled` | boolean | No | `true` | Accepted for forward compatibility — LLM reports are **not yet supported headless** (see below) |
| `pyshark_packet_limit` | integer | No | 200000 | Cap on packets to deep-parse |

**OSINT enrichment (`osint_enabled`):** when enabled, the worker enriches the top public IPs after analysis using provider keys from the saved Streamlit config (`cfg_*_key` values) or, as a fallback, the environment (`OTX_KEY`, `VT_KEY`, `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `SHODAN_KEY`). If no provider keys are configured, the job still completes — with the warning code `osint_not_configured` in the result. Note: the API path always queries providers fresh; the OSINT response cache is not used headless.

**LLM reports (`llm_enabled`):** LLM report generation is not yet supported on the API path. The field is accepted so existing clients keep working, but jobs complete with the warning code `llm_unsupported_on_api_path` in the result — including default submissions, since the field defaults to `true`.

**Response:** 202 Accepted

```json
{
  "job_id": "j_a1b2c3d4",
  "case_id": "e5f6a7b8",
  "status": "queued",
  "links": {
    "status": "/api/v1/jobs/j_a1b2c3d4",
    "result": "/api/v1/jobs/j_a1b2c3d4/result",
    "case": "/api/v1/cases/e5f6a7b8"
  }
}
```

**Validation:**

- Maximum file size: 2 GiB (configurable via `PCAP_HUNTER_API_MAX_PCAP_BYTES`)
- File must begin with a valid PCAP/pcapng magic signature
- Queue depth is capped (default 100; configurable via `PCAP_HUNTER_API_QUEUE_DEPTH`)

**Error codes:** `pcap_too_large` (413), `pcap_invalid_format` (415), `queue_full` (503)

---

### Job Tracking

#### `GET /api/v1/jobs/{job_id}`

**Auth:** `full` scope required

**Response:**

```json
{
  "job_id": "j_a1b2c3d4",
  "case_id": "e5f6a7b8",
  "status": "running",
  "progress": {
    "stage": "Zeek processing",
    "stages_done": 3,
    "stages_total": 10,
    "percent": 30
  },
  "submitted_at": "2026-05-25T10:00:00Z",
  "started_at": "2026-05-25T10:00:01Z",
  "finished_at": null,
  "error": null
}
```

**Job statuses:** `queued` | `running` | `done` | `failed` | `cancelled`

Finished jobs always report `progress.percent = 100` and `stage = "Complete"` — progress is reconciled atomically with the status flip at completion, so a job whose optional stages were skipped never freezes at a partial percentage.

#### `GET /api/v1/jobs/{job_id}/result`

Returns the full pipeline result as JSON once the job completes.

| Status | Meaning |
|--------|---------|
| 200 | Result available |
| 404 | Job not found |
| 409 | Job not finished yet — or finished in a terminal-but-resultless state (`failed` or `cancelled`); these permanently return 409 because no result will ever exist. The problem body carries an additive `current_status` field (e.g. `"current_status": "failed"`) so callers can distinguish in-progress polling from a permanent failure. |
| 410 | Result expired (GC'd per retention policy) |

**Response body** (abridged):

```json
{
  "case_id": "e5f6a7b8",
  "analysis_id": "9c2d1e0f-4a7",
  "packet_count": 4821,
  "duration_seconds": 12.4,
  "stages_run": ["pcap_count", "pyshark_pass", "zeek", "dns_analysis", "tls_certs", "beacon", "carve", "yara_scan", "osint"],
  "warnings": ["llm_unsupported_on_api_path"],
  "summary_narrative": null,
  "mitre_techniques": [],
  "dns_analysis": {},
  "tls_analysis": {},
  "beacon_df_records": []
}
```

**`analysis_id` is always set on success.** The worker persists the analysis and its extracted IOCs to the case database after the pipeline finishes — this is what feeds the [IOC Feed](#ioc-feed) endpoints. If persistence fails, the job still completes (`status: done`) but with the warning `analysis_persistence_failed` and a null `analysis_id`; the raw pipeline result remains available from this endpoint.

**Worker warning codes** (in `warnings`):

| Code | Meaning |
|------|---------|
| `analysis_persistence_failed` | Pipeline succeeded but the analysis could not be saved; `analysis_id` is null and the IOC feed will not include this run |
| `osint_not_configured` | `osint_enabled` was true but no OSINT provider keys are configured (saved config or env) |
| `osint_failed` | OSINT enrichment raised an error; analysis completed without enrichment |
| `yara_failed` | YARA scan over carved files raised an error |
| `llm_unsupported_on_api_path` | `llm_enabled` was true; LLM report generation is not yet supported headless |

Stage-level pipeline warnings may also appear (`pcap_count_unavailable`, `pyshark_failed`, `pyshark_no_data`, `zeek_failed`, `zeek_no_logs`, `dns_analysis_failed`, `tls_certs_failed`, `beacon_failed`, `carve_failed`) — each marks a stage that failed or produced no data without aborting the run.

---

### Case Management

#### `GET /api/v1/cases/{case_id}`

**Auth:** `full` scope required

Returns the case record including IOCs, severity, tags, and analysis metadata.

#### `GET /api/v1/cases/{case_id}/report.pdf`

**Auth:** `full` scope required

Renders the case's PDF report **on demand** from its most recent persisted analysis and returns it as `application/pdf`.

- Rendered PDFs are cached under `PCAP_HUNTER_API_REPORTS_DIR` (default `data/reports/`; legacy alias `PCAP_HUNTER_REPORTS_DIR`) and served from cache on subsequent requests.
- The cache is regenerated automatically when a newer analysis lands on the case (file mtime is compared against the latest analysis's `analyzed_at`).

| Status | Code | Meaning |
|--------|------|---------|
| 200 | | PDF rendered (or served from cache) |
| 404 | `case_not_found` | Case ID does not exist |
| 404 | `report_no_analysis` | Case exists but has no persisted analysis to render |
| 503 | `pdf_unavailable` | PDF rendering libraries (weasyprint/pango) are not installed on this host |
| 500 | `pdf_render_failed` | Rendering raised an error |

#### `DELETE /api/v1/cases/{case_id}`

**Auth:** `full` scope required

Deletes a case and **all** of its associated data — a full cascade:

- Database rows: analyses, IOCs, notes, tag links, and jobs belonging to the case
- Files: the uploaded PCAP, the cached PDF report, and the case's per-run Zeek/carve output directories

Returns 204 No Content on success. Queued jobs are cancelled as part of the delete; running jobs block it:

| Status | Code | Meaning |
|--------|------|---------|
| 204 | | Case and all associated data deleted. File cleanup (PCAP, PDF cache, run dirs) is best-effort — any leftover files age out via GC TTLs. |
| 404 | `case_not_found` | Case ID does not exist |
| 409 | `case_has_running_job` | A job is running — also returned when a *queued* job slips into `running` mid-delete (the cancel loses the race) |
| 500 | `case_delete_failed` | Database deletion failed; file cleanup is aborted and no files are removed |

---

### IOC Feed

All feed endpoints require `feed` scope (or `full`) and support conditional requests via ETag.

#### `GET /api/v1/iocs.json`

Returns IOCs as a JSON array.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `since` | string | | ISO 8601 cutoff date (e.g., `2026-05-01T00:00:00Z`) |
| `min_score` | integer | 0 | Minimum threat score (0-100) |
| `type` | string | | Comma-separated IOC types: `ip`, `domain`, `url`, `hash` |
| `tag` | string | | Filter by case tag |
| `case_id` | string | | Restrict to a single case |
| `limit` | integer | 1000 | Results per page (1-10000) |
| `cursor` | string | | Pagination cursor from previous response |

**Response:**

```json
{
  "iocs": [
    {
      "type": "ip",
      "value": "198.51.100.42",
      "score": 75,
      "severity": "high",
      "tags": ["malware", "c2-beacon"],
      "first_seen": "2026-05-20T10:00:00Z",
      "last_seen": "2026-05-25T14:30:00Z",
      "case_ids": ["e5f6a7b8"],
      "mitre_techniques": []
    }
  ],
  "count": 42,
  "next_cursor": "100"
}
```

**Feed semantics:**

- **Deduplication:** the same indicator appearing in multiple analyses collapses to a single row carrying the **maximum** severity/score observed across them; `first_seen`/`last_seen` span all sightings and `case_ids` lists every contributing case.
- **Filtering:** `min_score` is applied in SQL (not post-filtered), so it composes correctly with `limit`/`cursor` — pages are always full up to `limit` and no matching rows are dropped at page boundaries.
- **Ordering:** deterministic — `last_seen` descending, then indicator value ascending as a tie-breaker. Stable ordering makes cursor pagination reliable.

**Caching:** Responses include `ETag`, `Cache-Control: private, max-age=60`, and `Last-Modified` (RFC 7231 IMF-fixdate, e.g. `Thu, 11 Jun 2026 14:30:00 GMT`, derived from the newest `last_seen` in the response). Send `If-None-Match` to receive 304 Not Modified when data hasn't changed.

#### `GET /api/v1/iocs.csv`

Same filters as the JSON endpoint. Returns CSV with headers:

```
type,value,score,severity,tags,first_seen,last_seen,case_ids,mitre_techniques
```

Formula-like values (`=`, `+`, `-`, `@`) are prefixed with a single quote to prevent CSV injection in spreadsheet applications.

#### `GET /api/v1/iocs.stix`

Returns a STIX 2.1 bundle with indicator objects. IOC types map to STIX patterns:

| IOC Type | STIX Pattern |
|----------|-------------|
| IP | `[ipv4-addr:value = '...']` |
| Domain | `[domain-name:value = '...']` |
| URL | `[url:value = '...']` |
| Hash | `[file:hashes.'SHA-256' = '...']` |

---

### Admin / Key Management

All admin endpoints require `full` scope.

#### `POST /api/v1/admin/keys`

Create a new API key.

**Request:**

```json
{
  "name": "production-soar",
  "scope": "full",
  "description": "Tines SOAR integration key",
  "rate_limit_rpm": 120,
  "expires_in_days": 90
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable key name |
| `scope` | string | Yes | `full` or `feed` |
| `description` | string | No | Admin notes |
| `rate_limit_rpm` | integer | No | Requests per minute (null = unlimited) |
| `expires_in_days` | integer | No | Days until expiration (null = never) |

**Response:** 201 Created (includes raw key, shown only once)

#### `GET /api/v1/admin/keys`

List all keys. Add `?include_revoked=true` to include revoked keys.

#### `GET /api/v1/admin/keys/{key_id}`

Get a single key's details (no raw key or hash).

#### `PATCH /api/v1/admin/keys/{key_id}`

Update key properties (name, scope, description, rate_limit_rpm, expires_at). Set `rate_limit_rpm` to `0` to clear the limit.

#### `DELETE /api/v1/admin/keys/{key_id}`

Revoke a key (soft delete). The key immediately stops working.

**Lockout warning:** if a PATCH (e.g. scope change to `feed`, or setting an immediate expiry) or DELETE removes the **last full-scope auth source** (no `PCAP_HUNTER_API_KEY` env var and no remaining active full-scope DB key), the mutation still succeeds but the response gains an additive `"warning"` field with recovery instructions:

```json
{
  "status": "revoked",
  "id": "k_a1b2c3d4e5f6",
  "warning": "No full-scope auth source remains — ingress and admin endpoints (including key creation) will reject every request. Recover by setting PCAP_HUNTER_API_KEY and restarting, or by creating a full-scope key in the Streamlit 'API Keys' tab."
}
```

The same condition is logged server-side. Feed endpoints keep working for feed-scope keys; everything else rejects until a full-scope source exists again.

#### `GET /api/v1/admin/keys/{key_id}/usage`

Per-key daily request counts. Add `?days=7` to control the lookback window (1-365, default 30).

```json
{
  "key_id": "k_abc123",
  "usage": [
    { "date": "2026-05-25", "requests": 1234 },
    { "date": "2026-05-24", "requests": 890 }
  ]
}
```

#### `GET /api/v1/admin/usage/summary`

Aggregated daily usage across all keys.

---

## Rate Limiting

Database-backed keys can have a per-key rate limit (requests per minute). The rate limiter uses a 60-second sliding window tracked in memory.

| Key Source | Rate Limiting |
|------------|---------------|
| Environment variable (`PCAP_HUNTER_API_KEY`) | Unlimited |
| Environment variable (`PCAP_HUNTER_FEED_KEY`) | Unlimited |
| Database key with `rate_limit_rpm` set | Enforced |
| Database key with `rate_limit_rpm` null | Unlimited |

When the limit is exceeded, the API responds with:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 42
Content-Type: application/problem+json

{
  "type": "https://pcap-hunter.io/errors/rate_limit_exceeded",
  "title": "Too Many Requests",
  "status": 429,
  "detail": "Rate limit exceeded. Retry after 42 seconds.",
  "code": "rate_limit_exceeded"
}
```

---

## Error Handling

**All** errors use RFC 7807 `application/problem+json` format — including framework-generated ones: request validation failures (422), method-not-allowed (405), and unknown routes (404) are converted to problem documents, never bare FastAPI/Starlette JSON.

```json
{
  "type": "https://pcap-hunter.io/errors/invalid_key",
  "title": "Unauthorized",
  "status": 401,
  "detail": "The provided API key is invalid or has been revoked.",
  "instance": "/api/v1/pcaps",
  "code": "invalid_key",
  "request_id": "req_a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

- **401 responses carry `WWW-Authenticate: Bearer`** (RFC 6750 §3).
- **Routing-derived codes are snake_case** — e.g. a 405 yields `code: method_not_allowed`.
- **Validation errors (422)** use `code: validation_error` and add an `errors` array of `{loc, msg, type}` entries. The raw submitted input values are deliberately omitted so secrets never echo back into error bodies:

```json
{
  "type": "https://pcap-hunter.io/errors/validation_error",
  "title": "Unprocessable Entity",
  "status": 422,
  "detail": "Request validation failed.",
  "instance": "/api/v1/admin/keys",
  "code": "validation_error",
  "request_id": "...",
  "errors": [
    { "loc": ["body", "scope"], "msg": "String should match pattern '^(full|feed)$'", "type": "string_pattern_mismatch" }
  ]
}
```

### Error Code Reference

| Code | Status | Description |
|------|--------|-------------|
| `missing_or_malformed_auth` | 401 | No `Authorization` header or invalid format |
| `invalid_key` | 401 | Key not found, revoked, or expired |
| `insufficient_scope` | 403 | Valid key but lacks required scope |
| `rate_limit_exceeded` | 429 | Per-key rate limit exceeded |
| `pcap_too_large` | 413 | File exceeds `max_pcap_bytes` |
| `pcap_invalid_format` | 415 | Missing valid PCAP/pcapng magic signature |
| `queue_full` | 503 | Job queue at capacity |
| `job_not_found` | 404 | Job ID does not exist |
| `result_not_ready` | 409 | Job has not finished yet |
| `result_expired` | 410 | Result removed by retention policy |
| `case_not_found` | 404 | Case ID does not exist |
| `report_no_analysis` | 404 | Case exists but has no persisted analysis to render a PDF from |
| `pdf_unavailable` | 503 | PDF rendering libraries (weasyprint/pango) not installed |
| `pdf_render_failed` | 500 | PDF rendering raised an error |
| `case_has_running_job` | 409 | Cannot delete a case with a running job (including a queued job that started mid-delete) |
| `case_delete_failed` | 500 | Database deletion failed; file cleanup aborted |
| `key_not_found` | 404 | API key ID does not exist |
| `validation_error` | 422 | Request body/query validation failed (see `errors` array) |
| `method_not_allowed` | 405 | HTTP method not supported on this route |
| `not_found` | 404 | Unknown route (no handler matched the path) |

### Request Tracing

Every response includes an `X-Request-ID` header. Send your own via the request to correlate with your logs:

```bash
curl -H "X-Request-ID: my-trace-001" ...
```

---

## Configuration Reference

All settings are read from environment variables. Defaults are suitable for local development.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_HOST` | `127.0.0.1` | Bind address |
| `PCAP_HUNTER_API_PORT` | `8000` | Bind port |
| `PCAP_HUNTER_API_WORKERS` | CPU count / 2 | Uvicorn workers |
| `PCAP_HUNTER_API_CORS_ORIGINS` | (none) | Comma-separated allowed origins |
| `PCAP_HUNTER_API_REQUIRE_HTTPS` | `false` | Reject non-HTTPS requests |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_KEY` | (none) | Bootstrap key with `full` scope |
| `PCAP_HUNTER_FEED_KEY` | (none) | Bootstrap key with `feed` scope |

### Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_MAX_PCAP_BYTES` | 2 GiB | Maximum upload size |
| `PCAP_HUNTER_API_QUEUE_DEPTH` | 100 | Maximum queued jobs |
| `PCAP_HUNTER_API_UPLOAD_TIMEOUT_SEC` | 600 | Upload timeout (seconds) |

### Retention

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_PCAP_TTL_DAYS` | 7 | Days to keep uploaded PCAPs |
| `PCAP_HUNTER_API_ARTIFACT_TTL_DAYS` | 30 | Days to keep carved artifacts |
| `PCAP_HUNTER_API_JOB_TTL_DAYS` | 30 | Days to keep finished job records |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_DB_PATH` | `data/api_keys.db` | API key + case database path |
| `PCAP_HUNTER_API_UPLOADS_DIR` | `data/api_uploads` | Where submitted PCAPs are stored |
| `PCAP_HUNTER_API_ARTIFACTS_DIR` | `data/carved` | Carved-artifact root swept by GC |
| `PCAP_HUNTER_API_REPORTS_DIR` | `data/reports` | Cache directory for on-demand PDF reports (legacy alias: `PCAP_HUNTER_REPORTS_DIR`) |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_LOG_FORMAT` | `text` | Set to `json` for structured log lines (one JSON object per line) |
| `PCAP_HUNTER_LOG_LEVEL` | `INFO` | Standard Python level names (`DEBUG`, `WARNING`, ...) |

Application logs — including the per-request audit line (`method path -> status (ms) request_id=... key_name=...`) — are emitted by the `app.*` loggers, which the app wires up at startup so they stay visible under uvicorn and in Docker (uvicorn configures only its own loggers by default).

---

## SIEM Integration Examples

### Splunk SOAR (Phantom)

Configure an HTTP action in your Splunk SOAR playbook:

```python
# Submit PCAP artifact to PCAP Hunter
url = "http://pcap-hunter:8000/api/v1/pcaps"
headers = {"Authorization": "Bearer " + vault.get("pcap_hunter_key")}
files = {"pcap": open(artifact.pcap_path, "rb")}
data = {"name": f"SOAR-{container.id}", "tags": json.dumps(["automated", "soar"])}
response = requests.post(url, headers=headers, files=files, data=data)
job_id = response.json()["job_id"]
```

### Elastic Security / Logstash

Use the `http_poller` input to pull the IOC feed:

```ruby
# `since` must be ISO 8601 — the API compares it lexically against stored timestamps,
# so Logstash-style relative strings (e.g. "now-24h") silently return an empty feed.
# Template the cutoff from your pipeline's clock; the example below uses a fixed date.
input {
  http_poller {
    urls => {
      pcap_hunter => {
        method => get
        url => "http://pcap-hunter:8000/api/v1/iocs.json?min_score=50&since=2026-06-01T00:00:00Z"
        headers => { "Authorization" => "Bearer ${PCAP_HUNTER_FEED_KEY}" }
      }
    }
    schedule => { cron => "*/5 * * * *" }
    codec => "json"
  }
}
```

### Graylog / Wazuh

Pull the CSV feed on a cron schedule and load into your threat intel lookup table:

```bash
#!/bin/bash
# /etc/cron.d/pcap-hunter-ioc-sync
curl -s "http://pcap-hunter:8000/api/v1/iocs.csv?min_score=25" \
  -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
  -H "If-None-Match: $LAST_ETAG" \
  -o /var/lib/graylog/threat-intel/pcap-hunter-iocs.csv \
  -D /tmp/pcap-hunter-headers.txt

# Save ETag for next run
grep -i etag /tmp/pcap-hunter-headers.txt | awk '{print $2}' > /var/lib/graylog/.pcap-hunter-etag
```

### n8n / Tines / Generic Webhook

```bash
# Complete workflow: submit -> poll -> extract IOCs
JOB=$(curl -s -X POST http://localhost:8000/api/v1/pcaps \
  -H "Authorization: Bearer $KEY" \
  -F "pcap=@suspect.pcap" | jq -r .job_id)

# Poll until done (also break on failed/cancelled — both permanently return 409 on /result)
while true; do
  STATUS=$(curl -s http://localhost:8000/api/v1/jobs/$JOB \
    -H "Authorization: Bearer $KEY" | jq -r .status)
  [ "$STATUS" = "done" ] && break
  [ "$STATUS" = "failed" ] && { echo "Job failed"; exit 1; }
  [ "$STATUS" = "cancelled" ] && { echo "Job cancelled"; exit 1; }
  sleep 10
done

# Fetch result
curl -s http://localhost:8000/api/v1/jobs/$JOB/result \
  -H "Authorization: Bearer $KEY" | jq .
```

---

## Architecture Notes

### Process Model

The API runs as a separate `uvicorn` process (default port 8000) alongside the Streamlit UI (port 8501). Both share:

- The same SQLite case database
- The same `~/.pcap_hunter_config.json` settings
- The same 10-stage analysis pipeline (`app.pipeline.runner.run_pipeline`)

API-submitted PCAPs create regular Cases that appear in the Streamlit Cases tab.

### Background Processing

PCAP analysis runs in a `ProcessPoolExecutor` (default 2 workers). Each worker:

1. Receives a job submission with PCAP path and options
2. Calls `run_pipeline()` with a `CallbackProgress` adapter
3. Updates job progress in the database at each stage transition
4. Stores the full result JSON on completion

### Garbage Collection

An hourly background task (`_gc_loop`) automatically cleans up:

- Uploaded PCAPs older than `pcap_ttl_days` (default 7)
- Carved artifacts older than `artifact_ttl_days` (default 30) — each pipeline
  run writes into its own subdirectory (`data/carved/<run_id>/`), and GC removes
  both expired loose files and expired run directories. Independently of GC, the
  pipeline runner also prunes run directories older than 7 days
  (`RUN_DIR_RETENTION_SECONDS`) at the start of each new run, so artifacts are
  effectively retained for 7 days regardless of the API TTL.
- Finished job records older than `job_ttl_days` (default 30)
- **Rows orphaned by deleted cases** — analyses (plus their IOCs and notes), case-level notes, tag links, and jobs whose case no longer exists are reconciled out of the database on every sweep (`orphaned_rows_deleted` counter in the GC log line). This heals historical deletes that removed only the case row and would otherwise leave stale indicators serving in the IOC feed forever.

### Usage Tracking

Request counts are accumulated in memory and flushed to the SQLite database every 60 seconds. This avoids per-request database writes while maintaining audit trails.

### Security Measures

- **Constant-time key comparison** (`secrets.compare_digest`) for env-var keys
- **SHA-256 hashing** for database key storage (raw keys are never persisted)
- **Per-key sliding-window rate limiting** (in-memory, 60-second window)
- **Request ID tracing** with sanitized input (`X-Request-ID`)
- **CSV injection prevention** in feed exports
- **PCAP magic validation** before queuing analysis
- **Parameterized SQL** throughout the key repository
- **Structured audit logging** for all key CRUD operations
- **CORS origin allowlist** (not wildcard)
- **Sanitized error responses** (no internal paths or stack traces)

---

## Database Schema

### `api_keys` Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | `k_` prefix + UUID hex |
| `key_hash` | TEXT UNIQUE | SHA-256 hex of raw key |
| `key_prefix` | TEXT | First 8 chars for display |
| `name` | TEXT | Human-readable name |
| `scope` | TEXT | `full` or `feed` |
| `description` | TEXT | Admin notes |
| `created_at` | TIMESTAMP | Creation time |
| `expires_at` | TIMESTAMP | Optional expiration |
| `revoked_at` | TIMESTAMP | Soft-delete marker |
| `last_used_at` | TIMESTAMP | Last request timestamp |
| `total_requests` | INTEGER | Cumulative count |
| `rate_limit_rpm` | INTEGER | Requests per minute (NULL = unlimited) |
| `source` | TEXT | `admin` or `api` |

### `api_key_usage` Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `key_id` | TEXT FK | References `api_keys.id` |
| `date` | TEXT | `YYYY-MM-DD` |
| `requests` | INTEGER | Daily count |
