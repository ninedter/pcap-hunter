# PCAP Hunter Integrations API

Programmatic access to PCAP Hunter for SOAR, SIEM, and log analysis platforms.

## Quick start

```bash
export PCAP_HUNTER_API_KEY="$(openssl rand -hex 32)"
export PCAP_HUNTER_FEED_KEY="$(openssl rand -hex 32)"
make run-api      # starts on http://127.0.0.1:8000
```

Browse the auto-generated docs:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## Authentication

Two keys, configured via env vars. **At least one must be set** or the API refuses to start.

| Env var | Scope | Allows |
|---|---|---|
| `PCAP_HUNTER_API_KEY` | full | submit, read, delete, feed |
| `PCAP_HUNTER_FEED_KEY` | feed | only `/api/v1/iocs.*` |

Wire format: `Authorization: Bearer <key>`.

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

## Fetch the result

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
     http://127.0.0.1:8000/api/v1/jobs/$JOB_ID/result | jq .
```

## Pull the IOC feed

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.json?since=2026-04-01&min_score=50&type=ip,domain"
```

CSV (for Splunk lookups, Wazuh CDB):
```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.csv" > iocs.csv
```

STIX 2.1 bundle (for OpenCTI, MISP):
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
  "detail": "...",
  "instance": "/api/v1/pcaps",
  "code": "pcap_invalid_format",
  "request_id": "abc-123"
}
```

## Integration guides

- [Graylog](integrations/graylog.md)
- [Splunk](integrations/splunk.md)
- [Elastic](integrations/elastic.md)
- [Wazuh](integrations/wazuh.md)
