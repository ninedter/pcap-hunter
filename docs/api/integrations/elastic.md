# Elastic Integration

## Enrich processor with periodic CSV ingestion

1. Pull the feed periodically:
    ```bash
    */15 * * * * curl -fsS -H "Authorization: Bearer $FEED_KEY" \
        http://pcap-hunter.internal:8000/api/v1/iocs.csv \
        | curl -X POST "https://elastic:9200/_bulk" -H "Content-Type: application/x-ndjson" \
                -u elastic:$ES_PASS --data-binary @-
    ```
2. Create an enrich policy on `value` field.
3. Use the enrich processor in your ingest pipeline:
    ```json
    {
      "enrich": {
        "policy_name": "pcap_hunter_iocs",
        "field": "destination.ip",
        "target_field": "threat.pcap_hunter"
      }
    }
    ```
