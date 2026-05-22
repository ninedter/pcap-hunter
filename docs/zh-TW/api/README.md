# PCAP Hunter 整合 API

讓 SOAR、SIEM 與日誌分析平台以程式方式存取 PCAP Hunter。

## 快速開始

```bash
export PCAP_HUNTER_API_KEY="$(openssl rand -hex 32)"
export PCAP_HUNTER_FEED_KEY="$(openssl rand -hex 32)"
make run-api      # 啟動於 http://127.0.0.1:8000
```

瀏覽自動產生的 API 文件：
- Swagger UI：`http://127.0.0.1:8000/docs`
- ReDoc：`http://127.0.0.1:8000/redoc`

## 認證

透過環境變數設定兩組金鑰。**至少需設定一組**，否則 API 將拒絕啟動。

| 環境變數 | 權限範圍 | 允許操作 |
|---|---|---|
| `PCAP_HUNTER_API_KEY` | 完整 (full) | 提交、讀取、刪除、訂閱摘要 |
| `PCAP_HUNTER_FEED_KEY` | 摘要 (feed) | 僅限 `/api/v1/iocs.*` |

格式：`Authorization: Bearer <金鑰>`。

## 提交 PCAP 檔案

```bash
curl -X POST http://127.0.0.1:8000/api/v1/pcaps \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
  -F "pcap=@/path/to/capture.pcap" \
  -F "name=incident-1234" \
  -F 'tags=["soar:tines","source:edr_alert"]' \
  -F "osint_enabled=true"
```

回應 (`202 Accepted`)：
```json
{
  "job_id":  "j_a1b2c3d4",
  "case_id": "abcd1234",
  "status":  "queued",
  "links": { "status": "/api/v1/jobs/j_a1b2c3d4", "result": "...", "case": "..." }
}
```

## 輪詢完成狀態

```bash
while [ "$(curl -sH "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
            http://127.0.0.1:8000/api/v1/jobs/$JOB_ID | jq -r .status)" != "done" ]; do
    sleep 5
done
```

## 取得分析結果

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
     http://127.0.0.1:8000/api/v1/jobs/$JOB_ID/result | jq .
```

## 拉取 IOC 摘要

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.json?since=2026-04-01&min_score=50&type=ip,domain"
```

CSV（適用於 Splunk lookups、Wazuh CDB）：
```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.csv" > iocs.csv
```

STIX 2.1 bundle（適用於 OpenCTI、MISP）：
```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.stix" > iocs.stix.json
```

## 條件式 GET

IOC 端點支援 `If-None-Match` 以減少輪詢成本：

```bash
ETAG=$(curl -sI -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
        http://127.0.0.1:8000/api/v1/iocs.json | grep -i ^etag | cut -d' ' -f2 | tr -d '\r')
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     -H "If-None-Match: $ETAG" \
     -o /dev/null -w "%{http_code}\n" \
     http://127.0.0.1:8000/api/v1/iocs.json
# -> 304
```

## 錯誤處理

所有錯誤皆回傳 RFC 7807 `application/problem+json` 格式：

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

## 整合指南

- [Graylog](integrations/graylog.md)
- [Splunk](integrations/splunk.md)
- [Elastic](integrations/elastic.md)
- [Wazuh](integrations/wazuh.md)
