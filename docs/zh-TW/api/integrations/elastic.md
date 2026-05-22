# Elastic 整合

## 透過定時 CSV 匯入搭配 Enrich Processor

1. 定時拉取摘要：
    ```bash
    */15 * * * * curl -fsS -H "Authorization: Bearer $FEED_KEY" \
        http://pcap-hunter.internal:8000/api/v1/iocs.csv \
        | curl -X POST "https://elastic:9200/_bulk" -H "Content-Type: application/x-ndjson" \
                -u elastic:$ES_PASS --data-binary @-
    ```
2. 在 `value` 欄位上建立 enrich policy。
3. 在 ingest pipeline 中使用 enrich processor：
    ```json
    {
      "enrich": {
        "policy_name": "pcap_hunter_iocs",
        "field": "destination.ip",
        "target_field": "threat.pcap_hunter"
      }
    }
    ```
