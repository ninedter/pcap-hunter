# PCAP Hunter Integrations API

Programmatic access to PCAP Hunter for SOAR, SIEM, and log analysis platforms: submit PCAPs for pipeline analysis, poll jobs, fetch results and PDF reports, manage API keys, and pull extracted IOCs as JSON / CSV / STIX 2.1 feeds.

**Full endpoint reference (every endpoint with parameters, sample requests, and sample JSON responses): [docs/API.md](../API.md).**

## Quick start

```bash
export PCAP_HUNTER_API_KEY="$(openssl rand -hex 32)"
export PCAP_HUNTER_FEED_KEY="$(openssl rand -hex 32)"
make run-api      # starts on http://127.0.0.1:8000
```

Or in Docker: `docker compose up -d pcap-hunter-api` (binds `127.0.0.1:8000`; export the key env vars first).

Browse the auto-generated docs:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- OpenAPI 3.1 JSON: `http://127.0.0.1:8000/api/v1/openapi.json`

## Authentication

Wire format: `Authorization: Bearer <key>`. **At least one auth source must exist** (an env-var key or a database-backed key) or the API refuses to start.

| Source | Scope | Allows |
|---|---|---|
| `PCAP_HUNTER_API_KEY` env var | full | submit, jobs, cases, admin, feed |
| `PCAP_HUNTER_FEED_KEY` env var | feed | only `/api/v1/iocs.*` |
| Database-backed keys (`phk_...`) | full or feed | per key record |

Database-backed keys are created via `POST /api/v1/admin/keys` or **Settings → API access** in the production workbench, and support per-key expiry, rate limits (RPM), usage tracking, and revocation — see [API Key Management](../API.md#api-key-management).

## Submit a PCAP

```bash
curl -X POST http://127.0.0.1:8000/api/v1/pcaps \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
  -F "pcap=@/path/to/capture.pcap" \
  -F "name=incident-1234" \
  -F 'tags=["soar:tines","source:edr_alert"]' \
  -F "osint_enabled=true"
```

Response (`202 Accepted`):
```json
{
  "job_id":  "j_a1b2c3d4",
  "case_id": "abcd1234",
  "status":  "queued",
  "links": { "status": "/api/v1/jobs/j_a1b2c3d4", "result": "...", "case": "..." }
}
```

## Poll for completion

```bash
while [ "$(curl -sH "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
            http://127.0.0.1:8000/api/v1/jobs/$JOB_ID | jq -r .status)" != "done" ]; do
    sleep 5
done
```

(Also break on `failed`/`cancelled` — those never become `done`.)

## Fetch the result

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
     http://127.0.0.1:8000/api/v1/jobs/$JOB_ID/result | jq .
```

## Pull the IOC feed

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.json?since=2026-04-01T00:00:00&min_score=50&type=ip,domain"
```

(`since` is compared lexically against stored local-time ISO timestamps — pass ISO 8601, not relative strings like `now-24h`.)

CSV (for Splunk lookups, Wazuh CDB):
```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.csv" > iocs.csv
```

STIX 2.1 bundle (for OpenCTI, MISP) — also served at the alias `/api/v1/iocs/stix`:
```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.stix" > iocs.stix.json
```

## Conditional GET

The IOC endpoints support `If-None-Match` for cheap polling:

```bash
ETAG=$(curl -sI -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
        http://127.0.0.1:8000/api/v1/iocs.json | grep -i ^etag | cut -d' ' -f2 | tr -d '\r')
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     -H "If-None-Match: $ETAG" \
     -o /dev/null -w "%{http_code}\n" \
     http://127.0.0.1:8000/api/v1/iocs.json
# -> 304
```

## Errors

All errors are RFC 7807 `application/problem+json`:

```json
{
  "type": "https://pcap-hunter.io/errors/pcap_invalid_format",
  "title": "Unsupported Media Type",
  "status": 415,
  "detail": "pcap_invalid_format",
  "instance": "/api/v1/pcaps",
  "code": "pcap_invalid_format",
  "request_id": "abc-123"
}
```

See the [error code reference](../API.md#error-code-reference) for every code.

## Integration guides

- [Graylog](integrations/graylog.md)
- [Splunk](integrations/splunk.md)
- [Elastic](integrations/elastic.md)
- [Wazuh](integrations/wazuh.md)
