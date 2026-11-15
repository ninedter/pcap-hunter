# 使用代理程式進行威脅獵捕

> **[English version](../AGENT_USAGE.md)**

PCAP Hunter 提供限定案件範圍的 REST API 與本機 stdio MCP 轉接器。案件授權、權限、有效期限，以及請求與提交的上限，都由分析人員控制。每一次代理程式提交擷取檔時，受信任的啟動器都會建立一個全新的離線容器。每個解析器只能看到自己的唯讀擷取檔與專屬的暫存空間；它沒有網路，也拿不到提供者憑證、案件資料庫、共用的暫存佇列或 Docker socket。

## 建立存取權

1. 在本機工作台開啟 **Settings → Agent access**。
2. 選取代理程式可以讀取的案件。讀取案件、證據與工作狀態的權限預設為勾選。
3. 只有在需要時才啟用擷取檔提交或草稿註記。代理程式的提交一律停用 OSINT 與 LLM 呼叫；代理程式無法選擇提供者端點。
4. 建立憑證，並將它複製到代理主機的祕密設定中——憑證只會顯示一次，開頭為 `pha_`，預設七天後到期。
5. 調查結束後，在同一個畫面撤銷存取權。每一次 API 操作都會檢查憑證是否已撤銷或到期。

這類憑證對舊有的管理／刪除／設定端點沒有任何權限。既有的 `full` 與 `feed` 整合金鑰維持原本的行為。本機瀏覽器工作台信任本機用戶端，因此必須維持只繫結在 loopback 位址。

## REST 範例

請透過 shell 或祕密管理工具提供 `PCAP_HUNTER_AGENT_KEY`；不要把它的值寫進指令歷史紀錄或原始碼檔案。

```bash
curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  http://127.0.0.1:8000/api/v1/agent/cases

curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  http://127.0.0.1:8000/api/v1/cases/CASE_ID/analyses

curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/manifest

curl -H "Authorization: Bearer $PCAP_HUNTER_AGENT_KEY" \
  'http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/evidence?limit=100&type=ip'
```

請持續讀取 `next_cursor` 直到它為 null，過程中維持相同的分析與篩選條件。游標經過簽署，並且綁定代理程式、快照與篩選條件。查詢回應會區分「已保存的完整清單」與「不完整／未知的封包解析」。在部分解析的結果中找不到相符資料，並不能證明威脅不存在。

`/flows` 支援 `source`、`destination` 與 `protocol` 的完全比對篩選，以及帶有明確 UTC 時差的 ISO 8601 `start` 與 `end` 時間戳記。兩個查詢端點每頁最多回傳 200 筆。回應大小上限為 1 MiB，單筆過大的紀錄會回傳明確的錯誤。未知的參數會被拒絕。

每筆證據紀錄都包含其 ID、所屬分析、不可變的快照、來源擷取檔雜湊，以及 `investigate_url`。在本機工作台開啟該連結，即可檢視同一筆紀錄，包含較早保存的分析。Investigate 提供伺服器端分頁，並可選取已保存的分析。

## 連接 MCP 主機

轉接器使用官方 Python MCP SDK 2.3.0，而且只透過 stdio 執行。請在 **API 容器**內執行它，因為在那裡 loopback 的 8000 連接埠可以連到需要驗證的服務。請透過 MCP 主機的環境變數／祕密機制提供專用金鑰。

主機設定可以這樣啟動它：

```json
{
  "mcpServers": {
    "pcap-hunter": {
      "command": "docker",
      "args": ["compose", "exec", "-T", "-e", "PCAP_HUNTER_AGENT_KEY", "pcap-hunter-api", "python", "-m", "app.agents.mcp"]
    }
  }
}
```

請從 compose 專案目錄啟動主機，或在 Docker 參數中加入已確認的 compose 檔與專案名稱。若是自訂的本機測試部署，請使用維運人員提供的 Compose 路徑／專案（存在時會私下記錄在 `.codex/LOCAL_TEST.md`）。主機必須將 `PCAP_HUNTER_AGENT_KEY` 匯出給 Docker 用戶端。一般已安裝的 Python 環境也可以搭配 `PCAP_HUNTER_AGENT_URL=http://127.0.0.1:8000` 執行 `python -m app.agents.mcp`。

轉接器會查詢憑證擁有的權限，並且只公開對應的工具。API 在工具被呼叫時會獨立執行同樣的權限檢查。即使主機快取了工具清單，已撤銷的金鑰也會立即失效。未啟用任何遠端 MCP HTTP 服務。

| 權限 | 工具 |
| --- | --- |
| `cases:read` | `list_cases`、`get_case_summary`、`list_analyses` |
| `evidence:read` | `get_analysis_manifest`、`query_evidence`、`query_flows`、`get_evidence`、`get_indicator_context` |
| `jobs:read` | `get_job_status` |
| `captures:submit` | `submit_capture`、`cancel_job` |
| `notes:append` | `append_investigation_draft` |
| `reports:read` | `get_report`（經授權的 PDF 下載路徑） |

透過 MCP 提交擷取檔時，只接受使用者提供的 Base64 擷取檔位元組，上限約 1 MiB，絕不接受本機檔案路徑或 URL。較大的擷取檔請改用 REST multipart 上傳（上限 100 MiB，同時受伺服器設定的上傳限制約束）。

## 受控的寫入與重試

REST 提交使用 `POST /api/v1/agent/captures`，只帶 `pcap` 這一個 multipart 欄位。必須附上 `Idempotency-Key` 標頭，長度 8–128 個字元，可使用英文字母、數字與 `_ . : -`。以相同的鍵重送相同的擷取檔，會取得同一個工作與案件；以相同的鍵送出不同內容則會被拒絕。新建立的案件只會自動授權給提交它的代理程式。每日提交配額會被持久保存。

每個工作都有專屬的程序、掛載、網路與 IPC 命名空間，根檔案系統唯讀，移除所有 capabilities，套用 Docker 預設的 seccomp，禁止權限提升，並限制為 2 個 CPU、3 GiB 記憶體、256 個程序，以及十分鐘的實際執行時間上限。啟動器會將維運人員設定的映像檔解析為不可變的識別值，並且只掛載該工作的輸入目錄。它透過固定的讀取程式複製大小受限的結果位元組，移除整個工作容器，之後才發佈受信任的隔離收據。API 會限制並驗證這份不可信的 JSON、核對輸入雜湊、保存分析與證據快照，最後才將工作標記為完成。持久保存的請求／結果檔讓 API 重新啟動後仍可收取結果。工作程序中斷後，進行中的封包階段會重新執行；任意的階段輸出不會被當作可信的續傳檢查點。

`POST /api/v1/agent/jobs/JOB_ID/cancel` 只能停止該代理程式自己擁有的工作，並會保留案件與既有的證據。只要取消比結果儲存先完成寫入，就一定以取消為準：已取消的工作不會再產生分析或證據快照。重複送出取消是安全的。

### 工作狀態、進度與失敗代碼

`GET /api/v1/agent/jobs/JOB_ID` 會回傳 `status`、`stage`、`progress_done`、`progress_total`、`analysis_id`（完成後），以及工作失敗時的 `error_code`。

代理程式工作的進度**無法精確反映各個階段**。階段事件只留在工作容器內，受信任的啟動器只會發佈它自己的心跳訊號，因此解析器無法影響工作狀態所回報的內容。執行中的工作在結束前只會顯示單一固定階段 `Offline packet analysis`。請以 `status` 輪詢，不要用階段來估算剩餘時間。

| `error_code` | 意義 |
| --- | --- |
| `agent_job_deadline_exceeded` | 中介程式在工作期限內沒有看到啟動器的任何進展。期限為實際執行時間上限（十分鐘）加上五分鐘的排隊寬限，從「提交時間、該工作自己的啟動器心跳、啟動器的其他任何活動」三者中最晚的一個起算。正常運作、只是忙於其他工作的啟動器不會觸發它；啟動器停止或 Docker daemon 無法使用時才會。此外，工作在提交滿 24 小時後一律判定失敗。 |
| `agent_launcher_failed` | Docker 連續三次拒絕建立或啟動這個工作的容器。每次重試之間會退避等待（5 秒起、逐次加倍、最長 60 秒），期間不會耽誤其他工作。若解析容器啟動後 Docker 才發生失敗，同樣回報此代碼，且只回報一次、不再重試。 |
| `agent_time_budget_exceeded` | 解析器超過實際執行時間上限，已被啟動器停止。 |
| `offline_worker_failed` | 隔離的解析器執行過程中發生的其他任何失敗。 |
| `worker_input_unavailable` | 中介程式無法為啟動器備妥擷取檔。 |

工作失敗後會釋出它佔用的佇列名額。每日提交配額是依「已接受的提交」計算，工作失敗時不會退還。

工作結束（完成、失敗或取消）後，中介程式會移除該工作可拋棄的輸入副本：啟動器以輸出檔確認該工作後立即移除；若啟動器從未開始執行該工作，則在 30 秒寬限後移除；其餘情況要等到該工作的完整期限在沒有任何動靜的情況下過去才移除，因為解析器容器可能仍掛載著它。隨案件保存的原始擷取檔絕不會被更動。

### 稽核失敗

每一個通過驗證的代理程式請求都會寫入稽核紀錄。如果稽核紀錄無法寫入，該請求會**以拒絕方式失敗（fail closed）**：已備妥的回應會被捨棄，代理程式會收到 `503`，內容為 `{"detail": "agent_audit_unavailable"}`，並帶有 `Retry-After: 5` 與 `Cache-Control: no-store`，因此證據絕不會在沒有紀錄的情況下被揭露。已經完成寫入的變更仍會保留。代理程式的寫入都具有冪等性，因此請以相同的 `Idempotency-Key` 重試（或再送一次取消）；重試的請求會被稽核。

草稿註記使用 `POST /api/v1/agent/cases/CASE_ID/drafts`，需帶 `analysis_id`、`snapshot_id`、`content` 與 `evidence_ids`。每一筆引用都必須存在於已授權的案件與快照中。草稿必須附上冪等標頭，並會被標示為**需要分析人員審閱**。草稿不能覆寫註記、變更判定、結案或發佈發現。

## Docker 啟動器設定

Compose 服務 `pcap-hunter-agent-worker` 是受信任的啟動器。**它持有的 Docker socket 等同於對 Docker 主機的控制權**，即使以唯讀方式掛載 socket 也一樣。只有這個小型控制服務會取得 socket；UI、API 與封包解析器都不會取得。請確保啟動器映像檔、環境設定、Compose 檔與 Docker 主機都在維運人員的掌控之下。由封包內容控制的 JSON 只會由大小受限的 API 中介程式解碼，不會由啟動器解碼。

Docker Engine 必須支援 API 1.47、named-volume subpaths，以及預設的 seccomp 設定檔。輸入磁碟區必須屬於同一個 Compose 專案。這些檢查只要有一項不通過，啟動器就會拒絕執行。在 Linux 上請將 `DOCKER_GID` 設為 socket 的群組（`stat -c '%g' /var/run/docker.sock`）；Docker Desktop 使用預設群組 `0`。不支援遠端 Docker 端點。取消、時間上限與啟動器復原只會移除名稱與標籤皆正確的工作容器，絕不會刪除 named volumes。

如果連不上 Docker daemon，啟動器會繼續執行並以指數退避的方式重試（1 秒起、逐次加倍、最長 60 秒），而不是直接結束、被反覆快速重新啟動。每次重試都會先移除先前殘留的工作容器。若設定的映像檔或磁碟區被拒絕，啟動器仍會停止。

## 證據與安全限制

封包字串、偵測器輸出、註記、報告與工具結果都是不可信的資料，它們永遠不能授予權限。請引用證據 ID 與涵蓋範圍的限制，並區分觀察、假設、相互矛盾的證據與未知事項。工作容器無法讀取其他工作尚未處理的擷取檔或暫存檔。容器仍共用 Docker 主機的核心；這道邊界無法防範核心或容器執行環境的逃逸。本機分析人員 UI 仍是受信任的管理介面。

新保存的快照會帶有輸入識別與收件收據、所選的選項、工具版本、可取得時的規則雜湊、階段／警告的中繼資料，以及偵測器產出物的雜湊。歷史分析會明確標示為舊版來源；PCAP Hunter 不會憑空補上缺少的歷史版本資訊。快照與稽核紀錄在應用程式層面只能新增、不能修改。作業系統或資料庫的擁有者仍然可以改動儲存內容，因此這不是具備外部錨定、可防竄改的帳本。

代理程式所提交擷取檔的收件收據（manifest 中的 `provenance`）為結構版本 `"2"`。最上層的欄位——`run_id`、`attempt_id`、`input_bytes`、`options`、`completed_at` 與 `isolation`——來自中介程式或受信任的啟動器。不可信的解析器對自己的所有描述（`schema_version`、`completed_at`、`input_bytes`、`options`、`tool_versions`、`rules_sha256`、`rules_coverage`）都無法查證，只會保留在 `parser_asserted` 之下，大小上限為 16 KiB（超過時會以 `{"omitted": "oversized"}` 取代）。請把 `parser_asserted` 的值視為對方的宣稱，而不是事實。分析的 `analyzed_at` 時間是中介程式收取結果時以自己的時鐘標記的，絕不採用解析器提供的時間。

執行階段的相依套件以雜湊鎖定。PDF 產生只接受大小受限的內嵌 PNG 資源，Plotly 的地理資料已內建，可離線產生圖表。已儲存的憑證會轉換為使用隨機產生、受保護的金鑰檔。備份時請連同設定一併備份該金鑰；只還原 JSON 並不足夠。金鑰遺失或錯誤時，程式會停止解密，而不會默默清除已儲存的值。

本機 compose 設定已停用自動清除已保存的資料。案件檔案、設定與原始擷取檔會留在既有的資料／home 磁碟區中。工作程序的暫存空間與建置快取與已保存的證據分開存放。安全掃描結果與目前已知的發行版限制，會隨候選版本的驗證證據一併記錄；本機預覽版本並不保證不存在任何漏洞。
