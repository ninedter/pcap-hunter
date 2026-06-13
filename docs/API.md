# PCAP Hunter Integrations API

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1-6BA539.svg)](https://spec.openapis.org/oas/v3.1.0)

The Integrations API lets external platforms (SOAR, SIEM, log analysis tools, custom scripts) submit PCAPs for analysis and consume extracted IOCs as a feed. It runs as a separate `uvicorn` process alongside the Streamlit UI, sharing the same pipeline, case database, and configuration.

| | |
|---|---|
| **API version** | `1.0.0` |
| **Base URL** | `http://<host>:8000` — all business endpoints live under `/api/v1`; health probes (`/healthz`, `/readyz`) are at the root |
| **Interactive docs** | Swagger UI at `/docs`, ReDoc at `/redoc`, OpenAPI 3.1 JSON at `/api/v1/openapi.json` (all unauthenticated) |
| **Auth scheme** | `Authorization: Bearer <key>` |
| **Errors** | RFC 7807 `application/problem+json`, everywhere |

> **Timestamp format:** unless noted otherwise, all timestamps in request and response bodies are **ISO 8601 in server-local time without a timezone suffix** (e.g. `2026-06-12T09:14:02.731842`). The `Last-Modified` response header is the only RFC 7231 GMT date.

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
export PCAP_HUNTER_API_KEY="$(openssl rand -hex 32)"
uvicorn app.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

> The module exposes only the `create_app()` factory — the `--factory` flag is required. `uvicorn app.api.app:app` will not start.

Or with the Makefile:

```bash
PCAP_HUNTER_API_KEY=changeme make run-api       # production-ish: 127.0.0.1:8000
PCAP_HUNTER_API_KEY=changeme make run-api-dev   # --reload + debug logging
```

Or with Docker Compose (the `pcap-hunter-api` service binds `127.0.0.1:8000` on the host):

```bash
PCAP_HUNTER_API_KEY="$(openssl rand -hex 32)" docker compose up -d pcap-hunter-api
```

> The compose file passes `PCAP_HUNTER_API_KEY`/`PCAP_HUNTER_FEED_KEY` through from your shell with an empty default. If you re-`up` the stack without exporting them, the container boots keyless and either refuses to start (no DB keys exist) or relies entirely on DB-backed keys — see [Startup Requirement](#startup-requirement).

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
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
  -F "pcap=@traffic.pcap" \
  -F "name=Incident 2026-0042"
```

Response (202 Accepted):

```json
{
  "job_id": "j_7d4e9f21",
  "case_id": "c4a1b2d9",
  "status": "queued",
  "links": {
    "status": "/api/v1/jobs/j_7d4e9f21",
    "result": "/api/v1/jobs/j_7d4e9f21/result",
    "case": "/api/v1/cases/c4a1b2d9"
  }
}
```

> Job IDs carry a `j_` prefix; case IDs are bare 8-character hex strings (no `c_` prefix).

### 4. Poll for completion

```bash
curl http://localhost:8000/api/v1/jobs/j_7d4e9f21 \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY"
```

### 5. Retrieve the IOC feed

```bash
curl "http://localhost:8000/api/v1/iocs.json?min_score=50" \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY"
```

There is also an end-to-end smoke test you can run against a live local server: `make smoke-api` (wraps `scripts/api_smoke_test.sh`).

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

Environment-variable keys are checked first using constant-time comparison (no database query). If neither matches, the token is SHA-256 hashed and looked up in the key database. Expired and revoked DB keys fail with the same `invalid_key` error as unknown tokens — callers deliberately cannot distinguish key states.

### Scopes

| Scope | Access | Typical Use |
|-------|--------|-------------|
| `full` | All endpoints | SOAR integrations, admin scripts |
| `feed` | IOC feed endpoints only (`/api/v1/iocs.*`) | SIEM pull agents, threat intel platforms |

- `PCAP_HUNTER_API_KEY` grants `full` scope.
- `PCAP_HUNTER_FEED_KEY` grants `feed` scope.
- Database keys carry their scope in the key record.
- `full` implies `feed` — a full-scope key can pull the IOC feed.

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
phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8
```

- Only the SHA-256 hash is stored in the database (never the raw key).
- The prefix (first 8 characters, e.g. `phk_4f8a`) is stored for display in key lists.
- The raw key is shown **exactly once** at creation time.
- Key IDs use the format `k_<8 hex chars>` (e.g. `k_3f9c2b1a`).

### Create a Key via API

```bash
curl -X POST http://localhost:8000/api/v1/admin/keys \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
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
  "id": "k_3f9c2b1a",
  "key": "phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8",
  "name": "splunk-feed-puller",
  "prefix": "phk_4f8a",
  "scope": "feed",
  "expires_at": "2027-06-12T09:00:00.118264",
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

All routes implemented by the server, by router group:

| Group | Method | Path | Auth |
|-------|--------|------|------|
| Health | GET | `/healthz` | none |
| Health | GET | `/readyz` | none |
| PCAP Ingestion | POST | `/api/v1/pcaps` | `full` |
| Job Tracking | GET | `/api/v1/jobs/{job_id}` | `full` |
| Job Tracking | GET | `/api/v1/jobs/{job_id}/result` | `full` |
| Case Management | GET | `/api/v1/cases/{case_id}` | `full` |
| Case Management | GET | `/api/v1/cases/{case_id}/report.pdf` | `full` |
| Case Management | DELETE | `/api/v1/cases/{case_id}` | `full` |
| IOC Feed | GET | `/api/v1/iocs.json` | `feed` |
| IOC Feed | GET | `/api/v1/iocs.csv` | `feed` |
| IOC Feed | GET | `/api/v1/iocs.stix` (alias: `/api/v1/iocs/stix`) | `feed` |
| Admin | POST | `/api/v1/admin/keys` | `full` |
| Admin | GET | `/api/v1/admin/keys` | `full` |
| Admin | GET | `/api/v1/admin/keys/{key_id}` | `full` |
| Admin | PATCH | `/api/v1/admin/keys/{key_id}` | `full` |
| Admin | DELETE | `/api/v1/admin/keys/{key_id}` | `full` |
| Admin | GET | `/api/v1/admin/keys/{key_id}/usage` | `full` |
| Admin | GET | `/api/v1/admin/usage/summary` | `full` |

(The framework also serves `GET /docs`, `GET /redoc`, and `GET /api/v1/openapi.json` — see [Authentication](#unauthenticated-documentation-endpoints).)

---

### Health

#### `GET /healthz`

Liveness probe. Confirms the process is up and serving HTTP — it touches no database and requires no authentication, so it is safe (and cheap) to poll at high frequency from container orchestrators or load balancers. Read-only and idempotent; the only way it fails is if the process itself is down.

**Parameters:** none.

**Sample request:**

```bash
curl http://localhost:8000/healthz
```

**Sample response — 200 OK:**

```json
{
  "status": "ok"
}
```

**Error responses:** none — an unreachable process yields a connection error, not an HTTP status.

#### `GET /readyz`

Readiness probe. Verifies the API can actually do work: it opens the case database and executes `SELECT 1`, and checks that at least **1 GiB** of free disk space exists on the volume holding the database. Use it as the gate for routing traffic (e.g. Kubernetes `readinessProbe`, compose healthcheck). No authentication required; read-only and idempotent.

**Parameters:** none.

**Sample request:**

```bash
curl http://localhost:8000/readyz
```

**Sample response — 200 OK:**

```json
{
  "status": "ready"
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 503 | `http_error` | One or more checks failed; the problem body carries an additive `checks_failed` array naming each failing check |

```json
{
  "type": "https://pcap-hunter.io/errors/http_error",
  "title": "Service Unavailable",
  "status": 503,
  "detail": "",
  "instance": "/readyz",
  "code": "http_error",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234",
  "checks_failed": ["disk: 524288000 bytes free"]
}
```

---

### PCAP Ingestion

#### `POST /api/v1/pcaps`

Submit a PCAP file for background analysis. The upload is streamed to disk in 1 MiB chunks (under `PCAP_HUNTER_API_UPLOADS_DIR`, default `data/api_uploads/<case_id>.pcap`), size-checked during the stream and magic-checked afterwards — oversized or non-PCAP uploads are deleted immediately and rejected. On acceptance the endpoint **creates a new case** (visible in the Streamlit Cases tab with `source = api`) and **enqueues a job** on the analysis queue, then returns `202 Accepted` with polling links. Requires `full` scope. **Not idempotent** — every successful call creates a fresh case and job, even for a byte-identical file. Note one edge: if the queue is full, the 503 is raised *after* the case row and upload file were created; the orphaned upload ages out via the PCAP TTL, and the empty case remains until deleted.

**Auth:** `full` scope required

**Content-Type:** `multipart/form-data`

**Parameters (form fields):**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `pcap` | file | Yes | | PCAP or pcapng file. Must start with a valid pcap/pcapng magic signature; max size `PCAP_HUNTER_API_MAX_PCAP_BYTES` (default 2 GiB) |
| `name` | string | No | upload filename, else `api-<case_id>` | Case title |
| `tags` | string | No | `[]` | JSON array (e.g. `["soar","edr"]`) or comma-separated list (`soar,edr`) |
| `severity_hint` | string | No | `medium` | `low`, `medium`, `high`, or `critical`; unrecognized values fall back to `medium` |
| `osint_enabled` | boolean | No | `true` | Run OSINT enrichment after analysis (see below) |
| `llm_enabled` | boolean | No | `true` | Accepted for forward compatibility — LLM reports are **not yet supported headless** (see below) |
| `pyshark_packet_limit` | integer | No | server default (200,000) | Cap on packets to deep-parse |

**OSINT enrichment (`osint_enabled`):** when enabled, the worker enriches the top public IPs after analysis using provider keys from the saved Streamlit config (`cfg_*_key` values) or, as a fallback, the environment (`OTX_KEY`, `VT_KEY`, `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `SHODAN_KEY`). If no provider keys are configured, the job still completes — with the warning code `osint_not_configured` in the result. Note: the API path always queries providers fresh; the OSINT response cache is not used headless.

**LLM reports (`llm_enabled`):** LLM report generation is not yet supported on the API path. The field is accepted so existing clients keep working, but jobs complete with the warning code `llm_unsupported_on_api_path` in the result — including default submissions, since the field defaults to `true`.

**Sample request:**

```bash
curl -X POST http://localhost:8000/api/v1/pcaps \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8" \
  -F "pcap=@suspicious-traffic.pcap" \
  -F "name=Incident 2026-0042" \
  -F 'tags=["soar:tines","source:edr_alert"]' \
  -F "severity_hint=high" \
  -F "osint_enabled=true" \
  -F "pyshark_packet_limit=100000"
```

**Sample response — 202 Accepted:**

```json
{
  "job_id": "j_7d4e9f21",
  "case_id": "c4a1b2d9",
  "status": "queued",
  "links": {
    "status": "/api/v1/jobs/j_7d4e9f21",
    "result": "/api/v1/jobs/j_7d4e9f21/result",
    "case": "/api/v1/cases/c4a1b2d9"
  }
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | No/malformed `Authorization` header, or unknown/expired/revoked key |
| 403 | `insufficient_scope` | Valid key but only `feed` scope |
| 413 | `pcap_too_large` | Upload exceeded `PCAP_HUNTER_API_MAX_PCAP_BYTES`; the partial file is deleted |
| 415 | `pcap_invalid_format` | First bytes are not a known pcap/pcapng magic; the file is deleted |
| 422 | `validation_error` | Malformed form field (e.g. non-boolean `osint_enabled`) |
| 429 | `rate_limit_exceeded` | DB key over its per-minute limit (`Retry-After` header set) |
| 503 | `queue_full` | Active jobs ≥ `PCAP_HUNTER_API_QUEUE_DEPTH`; response carries `Retry-After: 60` |

Example `413`:

```json
{
  "type": "https://pcap-hunter.io/errors/pcap_too_large",
  "title": "Payload Too Large",
  "status": 413,
  "detail": "pcap_too_large",
  "instance": "/api/v1/pcaps",
  "code": "pcap_too_large",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234"
}
```

Example `503` (sent with header `Retry-After: 60`):

```json
{
  "type": "https://pcap-hunter.io/errors/queue_full",
  "title": "Service Unavailable",
  "status": 503,
  "detail": "queue_full",
  "instance": "/api/v1/pcaps",
  "code": "queue_full",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234"
}
```

---

### Job Tracking

#### `GET /api/v1/jobs/{job_id}`

Poll the status of an analysis job. Returns the job's lifecycle state, stage-level progress (the worker updates the database at every pipeline stage transition), timestamps, and — for failed jobs — a structured error. Read-only and idempotent; safe to poll every few seconds. Requires `full` scope. `progress.percent` is computed as `stages_done / stages_total * 100`; finished jobs always report `percent = 100` and `stage = "Complete"` because progress is reconciled atomically with the status flip at completion (a job whose optional stages were skipped never freezes at a partial percentage).

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `job_id` | path | string | Yes | Job ID from the submission response (`j_` + 8 hex chars) |

**Sample request:**

```bash
curl http://localhost:8000/api/v1/jobs/j_7d4e9f21 \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Job statuses:** `queued` | `running` | `done` | `failed` | `cancelled`

**Sample response — 200 OK (queued):**

```json
{
  "job_id": "j_7d4e9f21",
  "case_id": "c4a1b2d9",
  "status": "queued",
  "progress": {
    "stage": null,
    "stages_done": 0,
    "stages_total": 10,
    "percent": 0
  },
  "submitted_at": "2026-06-12T09:14:02.731842",
  "started_at": null,
  "finished_at": null,
  "error": null
}
```

**Sample response — 200 OK (running):**

```json
{
  "job_id": "j_7d4e9f21",
  "case_id": "c4a1b2d9",
  "status": "running",
  "progress": {
    "stage": "Zeek processing",
    "stages_done": 3,
    "stages_total": 10,
    "percent": 30
  },
  "submitted_at": "2026-06-12T09:14:02.731842",
  "started_at": "2026-06-12T09:14:03.108277",
  "finished_at": null,
  "error": null
}
```

**Sample response — 200 OK (done):**

```json
{
  "job_id": "j_7d4e9f21",
  "case_id": "c4a1b2d9",
  "status": "done",
  "progress": {
    "stage": "Complete",
    "stages_done": 10,
    "stages_total": 10,
    "percent": 100
  },
  "submitted_at": "2026-06-12T09:14:02.731842",
  "started_at": "2026-06-12T09:14:03.108277",
  "finished_at": "2026-06-12T09:15:41.557209",
  "error": null
}
```

**Sample response — 200 OK (failed):**

```json
{
  "job_id": "j_7d4e9f21",
  "case_id": "c4a1b2d9",
  "status": "failed",
  "progress": {
    "stage": "Parsing Packets",
    "stages_done": 2,
    "stages_total": 10,
    "percent": 20
  },
  "submitted_at": "2026-06-12T09:14:02.731842",
  "started_at": "2026-06-12T09:14:03.108277",
  "finished_at": "2026-06-12T09:14:19.882347",
  "error": {
    "code": "pipeline_error",
    "detail": "tshark exited with code 2"
  }
}
```

> A second failure code exists: `interrupted_restart` — set at API startup for jobs that were `running` with a stale heartbeat when the server restarted ("API restarted with this job in flight; resubmit the PCAP to retry.").

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `job_not_found` | No job with this ID (also after job records age out — see retention) |

#### `GET /api/v1/jobs/{job_id}/result`

Fetch the full pipeline result once the job has finished successfully. The result is the JSON blob the worker stored at completion (`Content-Type: application/json`) — packet counts, stages run, warnings, DNS/TLS findings, and beaconing records. Until the job reaches `done` this returns `409` with the job's `current_status`; jobs that finished `failed` or `cancelled` *permanently* return `409` because no result will ever exist for them. Read-only and idempotent. Requires `full` scope.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `job_id` | path | string | Yes | Job ID (`j_` + 8 hex chars) |

**Sample request:**

```bash
curl http://localhost:8000/api/v1/jobs/j_7d4e9f21/result \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Sample response — 200 OK** (`dns_analysis`/`tls_analysis` are nested per-stage detail objects, abridged here; they are `{}` when the stage found nothing):

```json
{
  "case_id": "c4a1b2d9",
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

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `job_not_found` | No job with this ID |
| 409 | `result_not_ready` | Job not in `done` state — in progress, **or** terminally `failed`/`cancelled` (permanent 409). The body carries an additive `current_status` field so callers can distinguish |
| 410 | `result_expired` | Job is `done` but its stored result blob has been removed (retention/cleanup) |

Example `409`:

```json
{
  "type": "https://pcap-hunter.io/errors/result_not_ready",
  "title": "Conflict",
  "status": 409,
  "detail": "",
  "instance": "/api/v1/jobs/j_7d4e9f21/result",
  "code": "result_not_ready",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234",
  "current_status": "running"
}
```

---

### Case Management

#### `GET /api/v1/cases/{case_id}`

Fetch the full case record — title, status, severity, tags, plus every persisted analysis (with its extracted IOCs) and case notes embedded. API-submitted cases are created with `status = in_progress` and the requested `severity_hint`; the same record is visible in the Streamlit Cases tab. Read-only and idempotent. Requires `full` scope. Note that embedded `analyses[]` can be large (the `features` object holds the full feature extraction); fetch the job result instead if you only need pipeline output.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `case_id` | path | string | Yes | Case ID (8 hex chars, no prefix) |

**Sample request:**

```bash
curl http://localhost:8000/api/v1/cases/c4a1b2d9 \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Sample response — 200 OK** (`features`/`osint` abridged):

```json
{
  "id": "c4a1b2d9",
  "title": "Incident 2026-0042",
  "description": "",
  "status": "in_progress",
  "severity": "high",
  "created_at": "2026-06-12T09:14:02.731842",
  "updated_at": "2026-06-12T09:15:41.557209",
  "closed_at": null,
  "tags": ["soar:tines", "source:edr_alert"],
  "analyses": [
    {
      "id": "9c2d1e0f-4a7",
      "case_id": "c4a1b2d9",
      "pcap_path": "data/api_uploads/c4a1b2d9.pcap",
      "pcap_hash": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
      "packet_count": 4821,
      "analyzed_at": "2026-06-12T09:15:40.992103",
      "features": {},
      "osint": {},
      "report": "",
      "yara_results": null,
      "dns_analysis": null,
      "tls_analysis": null,
      "iocs": [
        {
          "id": 17,
          "ioc_type": "ip",
          "value": "198.51.100.42",
          "context": "beaconing destination",
          "severity": "high"
        }
      ]
    }
  ],
  "notes": []
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `case_not_found` | Case ID does not exist |

#### `GET /api/v1/cases/{case_id}/report.pdf`

Render the case's PDF report **on demand** from its most recent persisted analysis and return it as `application/pdf` (served as an attachment named `case_<case_id>.pdf`). Requires `full` scope.

Side effects and caching:

- Rendered PDFs are cached under `PCAP_HUNTER_API_REPORTS_DIR` (default `data/reports/`; legacy alias `PCAP_HUNTER_REPORTS_DIR`) and served from cache on subsequent requests, so repeated calls are cheap.
- The cache is regenerated automatically when a newer analysis lands on the case (file mtime is compared against the latest analysis's `analyzed_at`).
- Writes are atomic (temp file + rename), so a concurrent reader never sees a torn PDF.
- The PDF rendering stack (WeasyPrint) is imported lazily on the first cache miss — it is not required for the API to boot.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `case_id` | path | string | Yes | Case ID (8 hex chars) |

**Sample request:**

```bash
curl -o case_c4a1b2d9.pdf http://localhost:8000/api/v1/cases/c4a1b2d9/report.pdf \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Sample response — 200 OK:** binary PDF body (`Content-Type: application/pdf`, `Content-Disposition: attachment; filename="case_c4a1b2d9.pdf"`).

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `case_not_found` | Case ID does not exist |
| 404 | `report_no_analysis` | Case exists but has no persisted analysis to render |
| 500 | `pdf_render_failed` | Rendering raised an error |
| 503 | `pdf_unavailable` | PDF rendering libraries (weasyprint/pango) are not installed on this host |

Example `503`:

```json
{
  "type": "https://pcap-hunter.io/errors/pdf_unavailable",
  "title": "Service Unavailable",
  "status": 503,
  "detail": "PDF rendering libraries (weasyprint/pango) are not installed on this host.",
  "instance": "/api/v1/cases/c4a1b2d9/report.pdf",
  "code": "pdf_unavailable",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234"
}
```

#### `DELETE /api/v1/cases/{case_id}`

Delete a case and **all** of its associated data — a full cascade. Requires `full` scope.

What gets removed:

- Database rows: analyses, IOCs, notes, tag links, and jobs belonging to the case (IOCs from this case disappear from the feed)
- Files: the uploaded PCAP, the cached PDF report, and the case's per-run Zeek/carve output directories

Queued jobs are **cancelled** as part of the delete (race-free compare-and-set); a running job **blocks** it with `409`. The database delete is the source of truth — file cleanup is best-effort and any leftover files age out via the GC TTLs. **Not idempotent:** a second DELETE for the same ID returns `404`.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `case_id` | path | string | Yes | Case ID (8 hex chars) |

**Sample request:**

```bash
curl -X DELETE http://localhost:8000/api/v1/cases/c4a1b2d9 \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Sample response — 204 No Content:** empty body.

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `case_not_found` | Case ID does not exist (including repeat deletes) |
| 409 | `case_has_running_job` | A job is running — also returned when a *queued* job slips into `running` mid-delete (the cancel loses the race). The body carries an additive `job_id` field |
| 500 | `case_delete_failed` | Database deletion failed; file cleanup is aborted and no files are removed |

Example `409`:

```json
{
  "type": "https://pcap-hunter.io/errors/case_has_running_job",
  "title": "Conflict",
  "status": 409,
  "detail": "",
  "instance": "/api/v1/cases/c4a1b2d9",
  "code": "case_has_running_job",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234",
  "job_id": "j_7d4e9f21"
}
```

---

### IOC Feed

All feed endpoints require `feed` scope (a `full`-scope key also works), are read-only/idempotent, and support conditional requests via ETag. All three formats accept the **same query parameters** and apply the same dedup/ordering semantics — they differ only in serialization.

**Shared query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `since` | string | | ISO 8601 cutoff; only IOCs whose analysis ran at/after this instant. Compared **lexically** against stored local-time ISO timestamps — pass the same format (e.g. `2026-06-01T00:00:00`); relative strings like `now-24h` silently match nothing |
| `min_score` | integer | `0` | Minimum threat score, 0–100 (422 outside that range) |
| `type` | string | | Comma-separated IOC types: `ip`, `domain`, `url`, `hash` |
| `tag` | string | | Only IOCs from cases carrying this tag |
| `case_id` | string | | Restrict to a single case |
| `limit` | integer | `1000` | Results per page, 1–10000 (422 outside that range) |
| `cursor` | string | | Pagination cursor from the previous response's `next_cursor` (an absolute row offset; non-numeric values are treated as `0`) |

**Feed semantics:**

- **Scoring:** each indicator's `score` derives from the **worst** severity recorded across its sightings: `low` = 25, `medium` = 50, `high` = 75, `critical` = 100; `severity` is the matching label.
- **Deduplication:** the same indicator appearing in multiple analyses collapses to a single row carrying that maximum severity/score; `first_seen`/`last_seen` span all sightings and `case_ids` lists every contributing case.
- **Filtering:** `min_score` is applied in SQL (not post-filtered), so it composes correctly with `limit`/`cursor` — pages are always full up to `limit` and no matching rows are dropped at page boundaries.
- **Ordering:** deterministic — `last_seen` descending, then indicator value ascending as a tie-breaker. Stable ordering makes cursor pagination reliable.
- **Pagination:** `next_cursor` is non-null exactly when the page came back full (`count == limit`); pass it as `cursor` for the next page. (CSV/STIX responses don't carry a cursor — page by incrementing `cursor` by `limit` while pages stay full.)

**Caching:** responses include `ETag` (SHA-256 of the body), `Cache-Control: private, max-age=60`, and `Last-Modified` (RFC 7231 IMF-fixdate, e.g. `Fri, 12 Jun 2026 01:14:02 GMT`, derived from the newest `last_seen` in the response). Send `If-None-Match` with the saved ETag to receive `304 Not Modified` (empty body) when data hasn't changed.

#### `GET /api/v1/iocs.json`

The primary machine-readable feed. Returns deduplicated indicators with scores, severities, tags, sighting timestamps, and contributing case IDs, plus a pagination cursor. Use it for SOAR enrichment lookups, scheduled SIEM pulls, and any client that wants structured fields.

**Auth:** `feed` scope (or `full`)

**Sample request:**

```bash
curl "http://localhost:8000/api/v1/iocs.json?min_score=50&type=ip,domain&limit=100" \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Sample response — 200 OK:**

```json
{
  "iocs": [
    {
      "type": "ip",
      "value": "198.51.100.42",
      "severity": "high",
      "score": 75,
      "tags": ["malware", "c2-beacon"],
      "first_seen": "2026-06-10T08:02:11.402199",
      "last_seen": "2026-06-12T09:15:40.992103",
      "case_ids": ["c4a1b2d9"],
      "mitre_techniques": []
    },
    {
      "type": "domain",
      "value": "updates.evil-cdn.example",
      "severity": "critical",
      "score": 100,
      "tags": ["malware"],
      "first_seen": "2026-06-11T17:44:03.215587",
      "last_seen": "2026-06-11T17:44:03.215587",
      "case_ids": ["b91e0f2c", "c4a1b2d9"],
      "mitre_techniques": []
    }
  ],
  "count": 2,
  "next_cursor": null
}
```

**Sample response — 304 Not Modified** (request carried a matching `If-None-Match`): empty body, `ETag` header repeated.

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 422 | `validation_error` | Query constraint violated (e.g. `min_score=200`, `limit=0`) |
| 429 | `rate_limit_exceeded` | DB key over its per-minute limit |

Example `422`:

```json
{
  "type": "https://pcap-hunter.io/errors/validation_error",
  "title": "Unprocessable Entity",
  "status": 422,
  "detail": "Request validation failed.",
  "instance": "/api/v1/iocs.json",
  "code": "validation_error",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234",
  "errors": [
    { "loc": ["query", "min_score"], "msg": "Input should be less than or equal to 100", "type": "less_than_equal" }
  ]
}
```

#### `GET /api/v1/iocs.csv`

The same feed as CSV (`Content-Type: text/csv`) — built for lookup tables: Splunk lookups, Graylog CSV adapters, Wazuh CDB lists. Same query parameters, dedup, ordering, and ETag caching as the JSON feed. List-valued fields (`tags`, `case_ids`, `mitre_techniques`) are `;`-joined inside one CSV column. Values that a spreadsheet would interpret as a formula (leading `=`, `+`, `-`, `@`) are prefixed with a single quote to prevent CSV injection.

**Auth:** `feed` scope (or `full`)

**Sample request:**

```bash
curl "http://localhost:8000/api/v1/iocs.csv?min_score=25" \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Sample response — 200 OK** (`text/csv`):

```csv
type,value,score,severity,tags,first_seen,last_seen,case_ids,mitre_techniques
ip,198.51.100.42,75,high,malware;c2-beacon,2026-06-10T08:02:11.402199,2026-06-12T09:15:40.992103,c4a1b2d9,
domain,updates.evil-cdn.example,100,critical,malware,2026-06-11T17:44:03.215587,2026-06-11T17:44:03.215587,b91e0f2c;c4a1b2d9,
```

**Error responses:** same as `iocs.json` (401 / 422 / 429), plus `405 method_not_allowed` for non-GET methods (applies to every endpoint).

#### `GET /api/v1/iocs.stix`

The same feed as a **STIX 2.1 bundle** of `indicator` objects, for STIX-native platforms (OpenCTI, MISP, TAXII ingest scripts). Also served at the alias path **`GET /api/v1/iocs/stix`** (identical behavior). Same query parameters and caching as the other formats. Indicator IDs are deterministic (UUIDv5 of the indicator value), so re-pulls produce stable IDs; IOC types map to STIX patterns:

| IOC Type | STIX Pattern |
|----------|-------------|
| `ip` | `[ipv4-addr:value = '...']` |
| `domain` | `[domain-name:value = '...']` |
| `url` | `[url:value = '...']` |
| `hash` | `[file:hashes.'SHA-256' = '...']` |

IOC rows of any other type (e.g. `ja3`) have no STIX pattern mapping and are omitted from the bundle.

**Auth:** `feed` scope (or `full`)

**Sample request:**

```bash
curl "http://localhost:8000/api/v1/iocs.stix?min_score=75" \
  -H "Authorization: Bearer phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8"
```

**Sample response — 200 OK** (`Content-Type: application/json`):

```json
{
  "type": "bundle",
  "id": "bundle--f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--1ed5f9f2-3c2b-5a7e-9f31-8d2a4c6b0e17",
      "created": "2026-06-10T08:02:11.402199",
      "modified": "2026-06-12T09:15:40.992103",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '198.51.100.42']",
      "valid_from": "2026-06-10T08:02:11.402199",
      "labels": ["malicious-activity"]
    }
  ]
}
```

**Error responses:** same as `iocs.json` (401 / 422 / 429).

---

### Admin / Key Management

All admin endpoints require `full` scope.

#### `POST /api/v1/admin/keys`

Create a new database-backed API key. The server generates the key material (`phk_` + 32 hex chars), stores only its SHA-256 hash, and returns the raw key **exactly once** in this response — it cannot be retrieved again. Use this to mint scoped, expiring, rate-limited credentials for each integration instead of sharing the bootstrap env-var key. New keys are usable immediately, no restart needed. Not idempotent — each call creates a distinct key.

**Auth:** `full` scope required

**Content-Type:** `application/json`

**Parameters (JSON body):**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | | Human-readable key name (1–100 chars) |
| `scope` | string | No | `feed` | `full` or `feed` |
| `description` | string | No | `""` | Admin notes (max 500 chars) |
| `rate_limit_rpm` | integer | No | `null` (unlimited) | Requests per minute (≥ 1) |
| `expires_in_days` | integer | No | `null` (never) | Days until expiration (≥ 1) |

**Sample request:**

```bash
curl -X POST http://localhost:8000/api/v1/admin/keys \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-soar",
    "scope": "full",
    "description": "Tines SOAR integration key",
    "rate_limit_rpm": 120,
    "expires_in_days": 90
  }'
```

**Sample response — 201 Created** (the only response that ever contains `key`):

```json
{
  "id": "k_3f9c2b1a",
  "key": "phk_4f8a2b9c1d3e5f60718293a4b5c6d7e8",
  "name": "production-soar",
  "prefix": "phk_4f8a",
  "scope": "full",
  "expires_at": "2026-09-10T09:00:00.118264",
  "rate_limit_rpm": 120
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 422 | `validation_error` | Missing `name`, `scope` not `full`/`feed`, `rate_limit_rpm < 1`, etc. |

#### `GET /api/v1/admin/keys`

List all API keys, newest first. Neither the raw key nor its hash is ever included — only the display prefix. By default revoked keys are hidden; pass `include_revoked=true` for a complete audit view. Read-only and idempotent.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Default | Description |
|-------|----|------|----------|---------|-------------|
| `include_revoked` | query | boolean | No | `false` | Include revoked keys in the listing |

**Sample request:**

```bash
curl "http://localhost:8000/api/v1/admin/keys?include_revoked=true" \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY"
```

**Sample response — 200 OK** (a JSON array; empty array `[]` when no keys exist):

```json
[
  {
    "id": "k_3f9c2b1a",
    "prefix": "phk_4f8a",
    "name": "production-soar",
    "scope": "full",
    "description": "Tines SOAR integration key",
    "created_at": "2026-06-12T09:00:00.118264",
    "expires_at": "2026-09-10T09:00:00.118264",
    "revoked_at": null,
    "last_used_at": "2026-06-12T09:14:02.731842",
    "total_requests": 1234,
    "rate_limit_rpm": 120,
    "status": "active",
    "source": "admin"
  },
  {
    "id": "k_8d21c0fe",
    "prefix": "phk_77ab",
    "name": "old-splunk-key",
    "scope": "feed",
    "description": "",
    "created_at": "2026-04-02T15:21:08.004913",
    "expires_at": null,
    "revoked_at": "2026-06-01T10:05:44.310229",
    "last_used_at": "2026-06-01T09:58:12.661408",
    "total_requests": 88012,
    "rate_limit_rpm": 60,
    "status": "revoked",
    "source": "admin"
  }
]
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 422 | `validation_error` | Non-boolean `include_revoked` |

#### `GET /api/v1/admin/keys/{key_id}`

Get a single key's metadata (same shape as one entry of the list response — never the raw key or hash). The `status` field is derived live: `active`, `expiring_soon` (within 7 days of expiry), `expired`, or `revoked`. Read-only and idempotent.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `key_id` | path | string | Yes | Key ID (`k_` + 8 hex chars) |

**Sample request:**

```bash
curl http://localhost:8000/api/v1/admin/keys/k_3f9c2b1a \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY"
```

**Sample response — 200 OK:**

```json
{
  "id": "k_3f9c2b1a",
  "prefix": "phk_4f8a",
  "name": "production-soar",
  "scope": "full",
  "description": "Tines SOAR integration key",
  "created_at": "2026-06-12T09:00:00.118264",
  "expires_at": "2026-09-10T09:00:00.118264",
  "revoked_at": null,
  "last_used_at": "2026-06-12T09:14:02.731842",
  "total_requests": 1234,
  "rate_limit_rpm": 120,
  "status": "active",
  "source": "admin"
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `key_not_found` | No key with this ID |

Example `404`:

```json
{
  "type": "https://pcap-hunter.io/errors/key_not_found",
  "title": "Not Found",
  "status": 404,
  "detail": "No key with id 'k_deadbeef'.",
  "instance": "/api/v1/admin/keys/k_deadbeef",
  "code": "key_not_found",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234"
}
```

#### `PATCH /api/v1/admin/keys/{key_id}`

Partially update a key's mutable fields — name, scope, description, rate limit, expiry. Omitted fields are left unchanged. Changes take effect on the next request that uses the key (no restart). Setting `rate_limit_rpm` to `0` **clears** the limit to unlimited; setting `expires_at` to a past instant expires the key immediately. If the change removes the last full-scope auth source, the response gains a `warning` field (see [lockout warning](#delete-apiv1adminkeyskey_id) below). Requires `full` scope.

**Auth:** `full` scope required

**Content-Type:** `application/json`

**Parameters:**

| Field | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `key_id` | path | string | Yes | Key ID (`k_` + 8 hex chars) |
| `name` | body | string | No | New name (1–100 chars) |
| `scope` | body | string | No | `full` or `feed` |
| `description` | body | string | No | New description (max 500 chars) |
| `rate_limit_rpm` | body | integer | No | New limit (≥ 1); `0` clears to unlimited |
| `expires_at` | body | string | No | New expiry as an ISO 8601 datetime (e.g. `2027-01-01T00:00:00`) |

**Sample request:**

```bash
curl -X PATCH http://localhost:8000/api/v1/admin/keys/k_3f9c2b1a \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"rate_limit_rpm": 0, "description": "rate limit lifted for migration"}'
```

**Sample response — 200 OK** (full updated key record):

```json
{
  "id": "k_3f9c2b1a",
  "prefix": "phk_4f8a",
  "name": "production-soar",
  "scope": "full",
  "description": "rate limit lifted for migration",
  "created_at": "2026-06-12T09:00:00.118264",
  "expires_at": "2026-09-10T09:00:00.118264",
  "revoked_at": null,
  "last_used_at": "2026-06-12T09:14:02.731842",
  "total_requests": 1234,
  "rate_limit_rpm": null,
  "status": "active",
  "source": "admin"
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 400 | `invalid_expires_at` | `expires_at` is not a valid ISO 8601 datetime string |
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `key_not_found` | No key with this ID |
| 422 | `validation_error` | Field constraint violated (e.g. `scope: "admin"`, empty `name`) |

Example `400`:

```json
{
  "type": "https://pcap-hunter.io/errors/invalid_expires_at",
  "title": "Bad Request",
  "status": 400,
  "detail": "expires_at must be a valid ISO 8601 datetime string.",
  "instance": "/api/v1/admin/keys/k_3f9c2b1a",
  "code": "invalid_expires_at",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234"
}
```

#### `DELETE /api/v1/admin/keys/{key_id}`

Revoke a key (soft delete — the record is kept for audit, with `revoked_at` set). The key stops authenticating immediately and its in-memory rate-limit window is cleared. Revocation is permanent; there is no un-revoke. **Idempotent in effect:** revoking an already-revoked key returns `200` again. Requires `full` scope.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Description |
|-------|----|------|----------|-------------|
| `key_id` | path | string | Yes | Key ID (`k_` + 8 hex chars) |

**Sample request:**

```bash
curl -X DELETE http://localhost:8000/api/v1/admin/keys/k_3f9c2b1a \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY"
```

**Sample response — 200 OK:**

```json
{
  "status": "revoked",
  "id": "k_3f9c2b1a"
}
```

**Lockout warning:** if a PATCH (e.g. scope change to `feed`, or setting an immediate expiry) or DELETE removes the **last full-scope auth source** (no `PCAP_HUNTER_API_KEY` env var and no remaining active full-scope DB key), the mutation still succeeds but the response gains an additive `"warning"` field with recovery instructions:

```json
{
  "status": "revoked",
  "id": "k_3f9c2b1a",
  "warning": "No full-scope auth source remains — ingress and admin endpoints (including key creation) will reject every request. Recover by setting PCAP_HUNTER_API_KEY and restarting, or by creating a full-scope key in the Streamlit 'API Keys' tab."
}
```

The same condition is logged server-side. Feed endpoints keep working for feed-scope keys; everything else rejects until a full-scope source exists again.

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `key_not_found` | No key with this ID |

#### `GET /api/v1/admin/keys/{key_id}/usage`

Per-key daily request counts for capacity planning and anomaly spotting. Days with zero requests are omitted (no zero-filled rows); entries are ordered by date **ascending**. Counts are flushed from memory to the database every 60 seconds, so the current minute's requests may not be visible yet. Read-only and idempotent.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Default | Description |
|-------|----|------|----------|---------|-------------|
| `key_id` | path | string | Yes | | Key ID (`k_` + 8 hex chars) |
| `days` | query | integer | No | `30` | Lookback window in days (1–365) |

**Sample request:**

```bash
curl "http://localhost:8000/api/v1/admin/keys/k_3f9c2b1a/usage?days=7" \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY"
```

**Sample response — 200 OK:**

```json
{
  "key_id": "k_3f9c2b1a",
  "usage": [
    { "date": "2026-06-11", "requests": 890 },
    { "date": "2026-06-12", "requests": 1234 }
  ]
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 404 | `key_not_found` | No key with this ID |
| 422 | `validation_error` | `days` outside 1–365 |

#### `GET /api/v1/admin/usage/summary`

Aggregated daily request counts **across all DB-backed keys** (env-var key traffic is not tracked here). Same windowing and flush semantics as the per-key endpoint. Read-only and idempotent.

**Auth:** `full` scope required

**Parameters:**

| Param | In | Type | Required | Default | Description |
|-------|----|------|----------|---------|-------------|
| `days` | query | integer | No | `30` | Lookback window in days (1–365) |

**Sample request:**

```bash
curl "http://localhost:8000/api/v1/admin/usage/summary?days=30" \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY"
```

**Sample response — 200 OK:**

```json
{
  "usage": [
    { "date": "2026-06-10", "requests": 4102 },
    { "date": "2026-06-11", "requests": 3987 },
    { "date": "2026-06-12", "requests": 2210 }
  ]
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 401 | `missing_or_malformed_auth` / `invalid_key` | Auth failure |
| 403 | `insufficient_scope` | Feed-scope key |
| 422 | `validation_error` | `days` outside 1–365 |

---

## Rate Limiting

Database-backed keys can have a per-key rate limit (requests per minute). The rate limiter uses a 60-second sliding window tracked in memory (state resets on server restart).

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
  "detail": "Rate limit exceeded. Retry after 42s.",
  "instance": "/api/v1/iocs.json",
  "code": "rate_limit_exceeded",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234"
}
```

Revoking a key clears its rate-limit window immediately.

---

## Error Handling

**All** errors use RFC 7807 `application/problem+json` format — including framework-generated ones: request validation failures (422), method-not-allowed (405), and unknown routes (404) are converted to problem documents, never bare FastAPI/Starlette JSON.

```json
{
  "type": "https://pcap-hunter.io/errors/invalid_key",
  "title": "Unauthorized",
  "status": 401,
  "detail": "invalid_key",
  "instance": "/api/v1/pcaps",
  "code": "invalid_key",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234"
}
```

- **401 responses carry `WWW-Authenticate: Bearer`** (RFC 6750 §3).
- **429 and `queue_full` 503 responses carry `Retry-After`.**
- **Routing-derived codes are snake_case** — e.g. a 405 yields `code: method_not_allowed`; an unmatched path yields `code: not_found`.
- **Endpoint-specific extras are additive** — some errors append fields beside the standard envelope: `current_status` (result 409), `job_id` (case-delete 409), `checks_failed` (readyz 503), `errors` (422).
- **Validation errors (422)** use `code: validation_error` and add an `errors` array of `{loc, msg, type}` entries. The raw submitted input values are deliberately omitted so secrets never echo back into error bodies:

```json
{
  "type": "https://pcap-hunter.io/errors/validation_error",
  "title": "Unprocessable Entity",
  "status": 422,
  "detail": "Request validation failed.",
  "instance": "/api/v1/admin/keys",
  "code": "validation_error",
  "request_id": "9f2c1ab4e8d34c61a2f0b7c5d9e81234",
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
| `rate_limit_exceeded` | 429 | Per-key rate limit exceeded (`Retry-After` header) |
| `pcap_too_large` | 413 | File exceeds `max_pcap_bytes` |
| `pcap_invalid_format` | 415 | Missing valid PCAP/pcapng magic signature |
| `queue_full` | 503 | Job queue at capacity (`Retry-After: 60` header) |
| `job_not_found` | 404 | Job ID does not exist |
| `result_not_ready` | 409 | Job has not finished (or finished `failed`/`cancelled`); additive `current_status` field |
| `result_expired` | 410 | Result removed by retention policy |
| `case_not_found` | 404 | Case ID does not exist |
| `report_no_analysis` | 404 | Case exists but has no persisted analysis to render a PDF from |
| `pdf_unavailable` | 503 | PDF rendering libraries (weasyprint/pango) not installed |
| `pdf_render_failed` | 500 | PDF rendering raised an error |
| `case_has_running_job` | 409 | Cannot delete a case with a running job; additive `job_id` field |
| `case_delete_failed` | 500 | Database deletion failed; file cleanup aborted |
| `key_not_found` | 404 | API key ID does not exist |
| `invalid_expires_at` | 400 | `expires_at` in a key PATCH is not valid ISO 8601 |
| `validation_error` | 422 | Request body/query validation failed (see `errors` array) |
| `method_not_allowed` | 405 | HTTP method not supported on this route |
| `not_found` | 404 | Unknown route (no handler matched the path) |
| `http_error` | varies | Generic fallback for errors without a specific code — notably the readyz 503 (additive `checks_failed` field) |

### Request Tracing

Every response includes an `X-Request-ID` header (a generated UUID hex when you don't send one). Send your own via the request to correlate with your logs — values are sanitized to `[a-zA-Z0-9-_.]` and truncated to 128 chars:

```bash
curl -H "X-Request-ID: my-trace-001" ...
```

The same ID is echoed in the `request_id` field of every error body and in the server-side audit log line.

---

## Configuration Reference

All settings are read from environment variables at startup. Defaults are suitable for local development.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_HOST` | `127.0.0.1` | Bind address setting. Note: the bundled launchers (`make run-api`, compose) pass `--host` explicitly to uvicorn — set both if you change one |
| `PCAP_HUNTER_API_PORT` | `8000` | Bind port setting (same caveat as host) |
| `PCAP_HUNTER_API_WORKERS` | half the CPU count (min 1) | **Analysis worker processes** for the job queue's `ProcessPoolExecutor` — not uvicorn web workers |
| `PCAP_HUNTER_API_CORS_ORIGINS` | (none — CORS disabled) | Comma-separated allowed origins. When set, CORS allows methods `GET, POST, DELETE` and headers `Authorization, Content-Type, If-None-Match, X-Request-ID`, without credentials |
| `PCAP_HUNTER_API_REQUIRE_HTTPS` | `false` | Reserved — parsed but **not currently enforced**; terminate TLS at a reverse proxy |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_KEY` | (none) | Bootstrap key with `full` scope |
| `PCAP_HUNTER_FEED_KEY` | (none) | Bootstrap key with `feed` scope |

### Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_MAX_PCAP_BYTES` | `2147483648` (2 GiB) | Maximum upload size |
| `PCAP_HUNTER_API_QUEUE_DEPTH` | `100` | Maximum active (queued + running) jobs |
| `PCAP_HUNTER_API_UPLOAD_TIMEOUT_SEC` | `600` | Reserved — parsed but **not currently enforced** |

### Retention

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_PCAP_TTL_DAYS` | `7` | Days to keep uploaded PCAPs |
| `PCAP_HUNTER_API_ARTIFACT_TTL_DAYS` | `30` | Days to keep carved artifacts — applies to both loose files and per-run output directories under the artifacts root, and to cached PDF reports (regenerated on demand). See [Garbage Collection](#garbage-collection) for the interaction with the runner's own 7-day run-dir pruning |
| `PCAP_HUNTER_API_JOB_TTL_DAYS` | `30` | Days to keep finished job records (afterwards `GET /jobs/{id}` returns 404) |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_API_DB_PATH` | (unset — two files) | When unset, cases live in `data/cases.db` and API keys in `data/api_keys.db`. When set, **both** repositories use this single SQLite file |
| `PCAP_HUNTER_API_UPLOADS_DIR` | `data/api_uploads` | Where submitted PCAPs are stored |
| `PCAP_HUNTER_API_ARTIFACTS_DIR` | `data/carved` | Carved-artifact root swept by GC |
| `PCAP_HUNTER_API_REPORTS_DIR` | `data/reports` | Cache directory for on-demand PDF reports (legacy alias: `PCAP_HUNTER_REPORTS_DIR`) |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_HUNTER_LOG_FORMAT` | `text` | Set to `json` for structured log lines (one JSON object per line) |
| `PCAP_HUNTER_LOG_LEVEL` | `INFO` | Standard Python level names (`DEBUG`, `WARNING`, ...) |

Application logs — including the per-request audit line (`method path -> status (ms) request_id=... key_name=...`) — are emitted by the `app.*` loggers, which the app wires up at startup so they stay visible under uvicorn and in Docker (uvicorn configures only its own loggers by default). The audit line identifies the caller as `env:main`, `env:feed`, the DB key's name, or `-`.

---

## SIEM Integration Examples

Full guides live in [`docs/api/integrations/`](api/integrations/): [Splunk](api/integrations/splunk.md) · [Elastic](api/integrations/elastic.md) · [Graylog](api/integrations/graylog.md) · [Wazuh](api/integrations/wazuh.md).

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
        url => "http://pcap-hunter:8000/api/v1/iocs.json?min_score=50&since=2026-06-01T00:00:00"
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

PCAP analysis runs in a `ProcessPoolExecutor` (`PCAP_HUNTER_API_WORKERS` processes; default half the CPU count, min 1). Each worker:

1. Receives a job submission with PCAP path and options
2. Calls `run_pipeline()` with a `CallbackProgress` adapter
3. Updates job progress in the database at each stage transition (plus a heartbeat)
4. Stores the full result JSON on completion

At startup the API recovers state: any job stuck in `running` with a heartbeat older than 120 seconds (i.e. it was in flight when the previous process died) is flipped to `failed` with error code `interrupted_restart`.

### Garbage Collection

An hourly background task (`_gc_loop`) automatically cleans up:

- Uploaded PCAPs older than `pcap_ttl_days` (default 7)
- Carved artifacts older than `artifact_ttl_days` (default 30) — each pipeline
  run writes into its own subdirectory (`data/carved/<run_id>/`), and GC removes
  both expired loose files and expired run directories (symlinks are never
  followed). Independently of GC, the pipeline runner also prunes run
  directories older than 7 days (`RUN_DIR_RETENTION_SECONDS`) at the start of
  each new run, so artifacts are effectively retained for 7 days regardless of
  the API TTL.
- Cached PDF reports older than `artifact_ttl_days` — safe to reap because the report endpoint regenerates on demand
- Finished job records older than `job_ttl_days` (default 30)
- **Rows orphaned by deleted cases** — analyses (plus their IOCs and notes), case-level notes, tag links, and jobs whose case no longer exists are reconciled out of the database on every sweep (`orphaned_rows_deleted` counter in the GC log line). This heals historical deletes that removed only the case row and would otherwise leave stale indicators serving in the IOC feed forever.

### Usage Tracking

Request counts are accumulated in memory and flushed to the SQLite database every 60 seconds (and once more at shutdown). This avoids per-request database writes while maintaining audit trails.

### Security Measures

- **Constant-time key comparison** (`secrets.compare_digest`) for env-var keys
- **SHA-256 hashing** for database key storage (raw keys are never persisted)
- **Indistinguishable key failures** — expired, revoked, and unknown keys all return the same `invalid_key` error
- **Per-key sliding-window rate limiting** (in-memory, 60-second window)
- **Request ID tracing** with sanitized input (`X-Request-ID`)
- **CSV injection prevention** in feed exports
- **PCAP magic validation** before queuing analysis
- **Parameterized SQL** throughout the key repository
- **Structured audit logging** for all key CRUD operations
- **CORS origin allowlist** (not wildcard; disabled entirely when unset)
- **Sanitized error responses** (no internal paths, stack traces, or echoed input values)

---

## Database Schema

### `api_keys` Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | `k_` + 8 hex chars |
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
