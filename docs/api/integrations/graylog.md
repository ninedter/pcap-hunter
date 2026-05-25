# Graylog Integration

PCAP Hunter exposes a JSON IOC feed that Graylog can consume two ways:
- **HTTP JSONPath Lookup Table** -- synchronous per-event enrichment
- **Periodic CSV pull via cron + Lookup Table** -- bulk watchlist

## Option A -- HTTP JSONPath Lookup Table

1. **System > Lookup Tables > Data Adapters > Create**
2. Type: **HTTP JSONPath**
3. URL: `http://pcap-hunter.internal:8000/api/v1/iocs.json?case_id=${key}`
4. Headers:
    ```
    Authorization: Bearer ${SECRET}
    ```
5. Path: `$.iocs[*]`
6. Map result to a Graylog message field via Pipeline Rule.

## Option B -- Periodic CSV pull

```bash
# /etc/cron.d/pcap-hunter-feed
*/15 * * * * graylog curl -fsS -H "Authorization: Bearer $FEED_KEY" \
    "http://pcap-hunter.internal:8000/api/v1/iocs.csv?since=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
    -o /etc/graylog/lookups/pcap_iocs.csv
```

Then **System > Lookup Tables > Data Adapters > Create > CSV File** pointing at `/etc/graylog/lookups/pcap_iocs.csv`.
