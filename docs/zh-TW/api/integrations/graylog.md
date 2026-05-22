# Graylog 整合

PCAP Hunter 提供 JSON IOC 摘要，可透過以下兩種方式與 Graylog 整合：
- **HTTP JSONPath Lookup Table** — 即時逐事件擴充
- **定時 CSV 拉取 + Lookup Table** — 批次威脅清單

## 方案 A — HTTP JSONPath Lookup Table

1. **System > Lookup Tables > Data Adapters > Create**
2. 類型：**HTTP JSONPath**
3. 網址：`http://pcap-hunter.internal:8000/api/v1/iocs.json?case_id=${key}`
4. 標頭：
    ```
    Authorization: Bearer ${SECRET}
    ```
5. 路徑：`$.iocs[*]`
6. 透過 Pipeline Rule 將結果對應到 Graylog 訊息欄位。

## 方案 B — 定時 CSV 拉取

```bash
# /etc/cron.d/pcap-hunter-feed
*/15 * * * * graylog curl -fsS -H "Authorization: Bearer $FEED_KEY" \
    "http://pcap-hunter.internal:8000/api/v1/iocs.csv?since=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" \
    -o /etc/graylog/lookups/pcap_iocs.csv
```

接著前往 **System > Lookup Tables > Data Adapters > Create > CSV File**，指向 `/etc/graylog/lookups/pcap_iocs.csv`。
