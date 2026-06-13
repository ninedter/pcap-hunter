# PCAP Hunter 整合 API

讓 SOAR、SIEM 與日誌分析平台以程式方式存取 PCAP Hunter：提交 PCAP 進行管道分析、輪詢工作、取得結果與 PDF 報告、管理 API 金鑰，並以 JSON / CSV / STIX 2.1 摘要格式拉取提取出的 IOC。

> **📖 完整的端點參考文件——每個端點的詳細說明、請求範例與回應範例——請見 [docs/API.md](../../API.md)（英文）。**

## 快速開始

```bash
export PCAP_HUNTER_API_KEY="$(openssl rand -hex 32)"
export PCAP_HUNTER_FEED_KEY="$(openssl rand -hex 32)"
make run-api      # 啟動於 http://127.0.0.1:8000
```

或使用 Docker：`docker compose up -d pcap-hunter-api`（綁定 `127.0.0.1:8000`；請先匯出上述金鑰環境變數）。

瀏覽自動產生的 API 文件：
- Swagger UI：`http://127.0.0.1:8000/docs`
- ReDoc：`http://127.0.0.1:8000/redoc`
- OpenAPI 3.1 JSON：`http://127.0.0.1:8000/api/v1/openapi.json`

## 認證

傳輸格式：`Authorization: Bearer <金鑰>`。**至少必須存在一個認證來源**（環境變數金鑰或資料庫金鑰），否則 API 會拒絕啟動。

| 來源 | 權限範圍 | 允許操作 |
|---|---|---|
| `PCAP_HUNTER_API_KEY` 環境變數 | 完整（full） | 提交、工作、案件、管理、摘要 |
| `PCAP_HUNTER_FEED_KEY` 環境變數 | 摘要（feed） | 僅限 `/api/v1/iocs.*` |
| 資料庫金鑰（`phk_...`） | 完整或摘要 | 依各金鑰記錄而定 |

資料庫金鑰可透過 `POST /api/v1/admin/keys` 或 Streamlit 的 **API Keys** 分頁建立，支援逐金鑰到期時間、速率限制（RPM）、使用量追蹤與撤銷——詳見 [API Key Management](../../API.md#api-key-management)（英文）。

## 提交 PCAP 檔案

```bash
curl -X POST http://127.0.0.1:8000/api/v1/pcaps \
  -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
  -F "pcap=@/path/to/capture.pcap" \
  -F "name=incident-1234" \
  -F 'tags=["soar:tines","source:edr_alert"]' \
  -F "osint_enabled=true"
```

回應（`202 Accepted`）：
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

（也請對 `failed`/`cancelled` 中止迴圈——這兩種狀態永遠不會變成 `done`。）

## 取得分析結果

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_API_KEY" \
     http://127.0.0.1:8000/api/v1/jobs/$JOB_ID/result | jq .
```

## 拉取 IOC 摘要

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.json?since=2026-04-01T00:00:00&min_score=50&type=ip,domain"
```

（`since` 會與儲存的本地時間 ISO 時間戳記做字典序比較——請傳入 ISO 8601 格式，不要使用 `now-24h` 之類的相對字串。）

CSV（適用於 Splunk lookups、Wazuh CDB）：
```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.csv" > iocs.csv
```

STIX 2.1 bundle（適用於 OpenCTI、MISP）——也可透過別名路徑 `/api/v1/iocs/stix` 取得：
```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_FEED_KEY" \
     "http://127.0.0.1:8000/api/v1/iocs.stix" > iocs.stix.json
```

## 條件式 GET

IOC 端點支援 `If-None-Match`，可降低輪詢成本：

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
  "detail": "pcap_invalid_format",
  "instance": "/api/v1/pcaps",
  "code": "pcap_invalid_format",
  "request_id": "abc-123"
}
```

完整的錯誤代碼清單請見[錯誤代碼參考](../../API.md#error-code-reference)（英文）。

## 整合指南

- [Graylog](integrations/graylog.md)
- [Splunk](integrations/splunk.md)
- [Elastic](integrations/elastic.md)
- [Wazuh](integrations/wazuh.md)
