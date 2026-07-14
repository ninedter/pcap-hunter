# PCAP Hunter

[![CI](https://github.com/ninedter/pcap-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/ninedter/pcap-hunter/actions/workflows/ci.yml)
[![Release: v2.0.0](https://img.shields.io/badge/release-v2.0.0-7c3aed.svg)](https://github.com/ninedter/pcap-hunter/releases/tag/v2.0.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](../../LICENSE)

> **[English README](../../README.md)**

**PCAP Hunter** 是一個 AI 增強的威脅獵捕工作台，旨在填補手動封包分析與自動化資安監控之間的鴻溝。它讓 SOC 分析師與威脅獵捕人員能夠從原始 PCAP 檔案中快速攝取、分析並提取可執行的情資。

透過結合業界標準的網路分析工具（**Zeek**、**Tshark**、**PyShark**）與**大型語言模型（LLM）**及 **OSINT** API，PCAP Hunter 將封包分析中繁瑣的部分——解析、關聯與情資豐富化——自動化，讓分析師能專注於偵測與回應。

📖 **[使用手冊（繁體中文）](USER_MANUAL.md)** | **[User Manual (English)](../en/USER_MANUAL.md)**

---

## 版本 2 新功能

- **獨立的 MITRE ATT&CK 工作區** — 以證據為本的技術假設、ATT&CK v19.1 中繼資料、分析師處置、擷取涵蓋範圍、可視性缺口與 Navigator 匯出。
- **擷取品質遙測** — 封包/流量規模、解析比率、時間範圍、取樣上限、完成階段與警告會隨 UI/API 結果傳遞，並與案件一同保存。
- **更安全的 PCAP 攝取** — Streamlit 上傳採有限區塊串流，保留 `.pcap`/`.pcapng`，驗證 Magic Bytes、執行批次限制，拒絕時清除不完整檔案。
- **更強的整合 API** — 無介面工作會回傳 ATT&CK 對應與擷取指標，IOC 摘要包含相關技術 ID，失敗提交會清除暫存案件與檔案。
- **不依賴 LLM 的證據檢視** — 即使跳過或無法產生 AI 敘事，確定性的封包、IOC、關聯、階段與警告證據仍然可見。
- **執行與匯出可靠性** — Docker 會將本地 LM Studio 位址轉至主機橋接、HTTP 提取正確解碼 tshark 位元組、案件重存會取代過期 IOC，PDF 時間戳記統一使用 UTC。

---

## 目錄

- [版本 2 新功能](#版本-2-新功能)
- [視覺導覽](#視覺導覽)
- [主要功能](#主要功能)
- [整合 API](#整合-api)
- [系統架構](#系統架構)
- [安裝](#安裝)
- [快速開始](#快速開始)
- [使用指南](#使用指南)
- [設定](#設定)
- [開發](#開發)
- [說明文件](#說明文件)
- [授權條款](#授權條款)

---

## 視覺導覽

以下畫面來自在 Docker 中執行的真實版本 2 Streamlit 應用程式，並以內建範例 PCAP 完成分析。提交前會在圖片像素中遮蔽 IPv4/IPv6 位址、API 機密、電子郵件與本機使用者路徑。

### 1. Upload — 載入一個或多個 PCAP

拖放 `.pcap` / `.pcapng` 檔案，或貼上容器路徑。上傳多個檔案會啟動批次模式並進行跨檔案關聯分析；可關閉的入門導覽面板會引導初次使用者熟悉整個工作流程。

![Upload 分頁](../images/01-upload.png)

### 2. Progress — 透明的 10 階段管道

每個階段都即時回報進度，並提供逐階段的跳過控制。PyShark 與 Zeek 平行執行，接著 DNS、TLS、信標偵測與酬載提取同時展開——你永遠知道目前正在執行什麼、還剩多少進度。

![Progress 分頁](../images/02-progress.png)

### 3. Dashboard — 一目了然的威脅摘要

儀表板優先呈現訊號最強的發現：整體風險等級搭配**「Why this risk level?」可解釋性展開面板**、一行式的**嚴重程度色彩圖例**、警報數量、信標候選（附進度條分數）、YARA 命中與憑證問題。確認乾淨的區塊會明確說明——不會出現語意不明的空白面板。全球流量地圖、協定分佈與標示 UTC 的活動時間軸，讓擷取內容具備完整的視覺脈絡。

![Dashboard 分頁](../images/03-dashboard.png)

### 4. MITRE Analysis — 行為、證據與涵蓋範圍

獨立的 ATT&CK 工作區將對應視為分析師假設，而不是既定事實。它會把網路證據連結至技術與適用的偵測情境，讓分析師記錄處置與筆記，明確顯示偵測缺口，並匯出含版本中繼資料的 ATT&CK Navigator 圖層。

![MITRE Analysis 分頁](../images/10-mitre-analysis.png)

### 5. LLM Analysis — AI 產生的威脅報告

九個章節的敘事報告——從執行摘要到建議行動，外加 **IOC 摘要表**與**以真正 Markdown 表格呈現的風險矩陣（Risk Matrix）**——包含信心度修飾語與 MITRE ATT&CK 對應。可透過 LM Studio 在本地逐節產生，或透過 OpenAI / Anthropic 以單次完整上下文呼叫產生。報告支援 9 種語言，包括繁體中文（zh-TW）。

![LLM Analysis 分頁](../images/04-llm-analysis.png)

即使報告被跳過或無法產生，此分頁仍會顯示解析封包、流量、IOC、關聯、完成階段與管道警告的確定性快照。

### 6. OSINT — 多供應商 IOC 情資豐富化

優先排序的 IOC 表格，將 VirusTotal、AbuseIPDB、GreyNoise、Shodan、OTX 與 VT Domain 的訊號合併為單一檢視。**供應商狀態標籤**誠實回報每個供應商的狀態（正常 / 快取 / 速率受限 / 金鑰遭拒 / 無資料），明確的 **WHOIS 查詢**下拉選單 + 按鈕與點選資料列的對話框相輔相成，IOC 搜尋並提供顯示全部結果的切換開關。子分頁涵蓋網域、詳細資訊卡、地理地圖、基礎設施 ASN 分群、匯出、裝置與筆記。

![OSINT 分頁](../images/05-osint.png)

### 7. Raw Data — Zeek log、流量、提取酬載、YARA 比對

所有底層資料來源一應俱全：流量表（附明確的 **First/Last Seen (UTC)** 時間戳記欄位）、DNS 與 TLS 分析、NXDOMAIN 分析、JA3/JA3S 指紋、Zeek `conn.log`/`dns.log`/`http.log`/`ssl.log`、提取的 HTTP 酬載與 YARA 掃描結果。任何檢視都能匯出為 CSV 或 JSON，內建 CSV 注入防護。

![Raw Data 分頁](../images/06-raw-data.png)

### 8. Cases — 持續性的調查追蹤

將任何擷取與其發現升級為案件。案件包含 IOC、嚴重程度、標籤、調查筆記、ATT&CK 對應、擷取品質指標、狀態與搜尋功能——儲存在本地 SQLite 資料庫。

![Cases 分頁](../images/07-cases.png)

### 9. API Keys — 管理程式化存取

為整合 API 建立、撤銷與監控 API 金鑰。每把金鑰擁有自己的權限範圍（完整或僅限摘要）、選用的到期時間、逐金鑰速率限制與使用量趨勢圖。環境變數金鑰會顯示為唯讀的初始（bootstrap）項目。

![API Keys 分頁](../images/11-api-keys.png)

### 10. Config — 集中式設定

**LLM Integration** 區塊提供三種供應商（LM Studio、OpenAI、Anthropic），**YARA Rules** 區塊提供可設定的規則目錄，OSINT 供應商金鑰搭配 **Test Providers** 即時檢測按鈕，加上世界地圖的自家位置、執行檔路徑與管道門檻值——全部集中一處，各區塊並有獨立的清除按鈕。API 金鑰以 PBKDF2 加密儲存。

![Config 分頁](../images/08-config.png)

#### 選擇 LLM 供應商

挑選最適合你環境的後端：**LM Studio** 適合本地、實體隔離（air-gapped）的分析（逐節分段產生），**OpenAI** / **Anthropic** 則以單次完整上下文呼叫產生雲端報告。每個供應商各自保有金鑰與模型選單。

![LLM 供應商選擇](../images/09-llm-providers.png)

---

## 主要功能

### AI 驅動的威脅分析
- **多供應商 LLM 支援** — 同一個 Config 區塊下三種可互換的後端：
  - **LM Studio**（本地）— 隱私優先、適合實體隔離環境；報告採逐節產生以配合較小的上下文視窗。
  - **OpenAI**（雲端）— 單次完整上下文呼叫，一次送入全部證據語料產生報告。
  - **Anthropic**（雲端）— 透過官方 `anthropic` SDK 使用 Claude（`claude-opus-4-8`、`claude-sonnet-4-6`、`claude-haiku-4-5`），單次呼叫並支援串流。
- **以證據為本的報告** — SOC 就緒的報告，包含嚴重程度校準評估、誤報意識、信心度修飾語、以真正 Markdown 表格呈現的風險矩陣，以及 IOC 摘要表。
- **LLM 選用的證據檢視** — 即使略過或無法使用模型，解析封包、流量、IOC、關聯、階段與警告證據仍然可見。
- **多語言報告** — 9 種語言與地區術語：英文、繁體中文（台灣）、簡體中文、日文、韓文、義大利文、西班牙文、法文、德文。
- **MITRE ATT&CK 分析** — 獨立的行為與涵蓋範圍工作區，將網路證據對應至版本化 ATT&CK 假設、連結適用的 Detection Strategy/Data Component、保存分析師處置並匯出 Navigator 圖層。
- **擷取品質遙測** — 封包/流量規模、解析涵蓋率、時間範圍、取樣上限、管道警告與偵測器可視性缺口會與發現一併保存。
- **攻擊敘事合成** — 將原始事件轉譯為連貫、可執行的資安事件故事。

### IOC 優先級評分
- **分層訊號架構** — 以三層模型動態將指標分級為嚴重（Critical）、高（High）、中（Medium）、低（Low）：
  - **第一層（決定性）**：OSINT 確認（VirusTotal、GreyNoise 判定惡意）— 任何單一第一層命中即設定分數下限。
  - **第二層（行為性）**：C2 信標、流量不對稱、DNS 通道、DGA 網域。
  - **第三層（情境性）**：AbuseIPDB、自簽憑證、過期憑證、YARA 比對。
- 僅有第三層訊號時，等級絕不會超過「中」；「高」或「嚴重」需要跨層級的交叉佐證。
- **可解釋的風險** — 儀表板的「Why this risk level?」展開面板會精確列出促成判定的訊號。

### 跨指標關聯引擎
- **獨立互補公式** — 採用 `1 − Π(1 − wᵢsᵢ)`（貝氏獨立模型）取代線性加總，產生報酬遞減效果，同時讓多個弱訊號得以有意義地疊加。
- **強訊號下限** — 已確認的 VirusTotal 偵測會自動設定最低分數，不受其他因素影響。
- 彙整所有分析模組的訊號（OSINT、信標偵測、DNS、TLS、YARA、流量分析）。
- 為每個指標產生複合威脅分數，附帶判定分類（嚴重 / 高 / 中 / 低）。

### 流量分析與資料外洩偵測
- **資料外洩偵測** — 辨識每對來源/目的端的可疑外送：接收位元組比率（預設門檻：10:1，最低 1 MB）。
- **Port 異常偵測** — 標記非標準 Port 使用、C2 常見 Port（4444、5555、6666 等）及高位 Port 配對。
- **記憶體上限取樣** — 每條流量的封包時間戳記/長度取樣上限為 5,000 筆，而真實的位元組/封包總計與首見/末見時間仍維持精確。

### 多 PCAP 批次處理
- **多檔案上傳** — 同時上傳並分析多個 PCAP 檔案。
- **經驗證的串流攝取** — `.pcap` 與 `.pcapng` 以有限區塊寫入，檢查檔案/批次上限與 Magic Bytes，任何失敗都會回復整批暫存檔。
- **跨檔案關聯** — 偵測跨檔案共用的 IP、網域與 JA3 指紋。
- **合併儀表板** — 彙整結果，附逐檔案詳細資訊卡與批次摘要。
- **資源限制** — 可設定的限制：每檔案 1 GB、最多 50 個檔案、總計 5 GB。

### 並行管道執行
- **PyShark + Zeek 平行執行** — 兩個最重的階段透過 ThreadPoolExecutor 同時執行。
- **四路分析扇出** — 解析合流後，DNS、TLS、信標偵測與 HTTP 酬載提取全部同時執行。
- **每次執行的產物隔離** — Zeek 與酬載提取的輸出寫入 `data/zeek|carved/<case>_<uuid8>/`，同時執行的分析絕不互相覆寫；過期的執行目錄會在 7 天後自動清除。
- **子行程逾時保護** — 每個外部工具呼叫（zeek、tshark 計數/提取/TLS 萃取）都有明確的逾時上限。
- **Tshark `-c` 最佳化** — 封包上限直接在 tshark 層強制執行，I/O 零浪費。

### 深度封包檢測與流量分析
- **多引擎管道**：PyShark 進行細顆粒檢測，Tshark 進行高速統計。
- **協定解析**：自動提取 HTTP、DNS、TLS/SSL、SMB 協定的中繼資料。

### Zeek 整合
- 上傳 PCAP 後自動執行 Zeek — 無需手動下指令。
- 解析並關聯核心 Zeek log：`conn.log`、`dns.log`、`http.log`、`ssl.log`。

### 進階 DNS 與 TLS 鑑識
- **DGA 偵測** — 基於夏農熵（Shannon Entropy）的網域生成演算法識別。
- **DNS 通道偵測** — 偵測高流量 / 異常的 DNS 酬載。
- **Fast Flux 偵測** — 辨識解析至快速變化 IP 位址的網域。
- **JA3/JA3S 指紋識別** — 比對 TLS 指紋與 90 筆以上已知惡意軟體特徵（Cobalt Strike、Trickbot、Emotet、QakBot 等）。
- **憑證分析** — 驗證憑證鏈；偵測自簽及過期憑證。

### C2 信標（Beaconing）偵測
- 統計演算法依據以下項目對流量評分：
  - **週期性** — 通訊間隔的規律性（CV + 熵值評分）。
  - **抖動（Jitter）** — 眾數間隔分析搭配 ±20% 容忍度，用於偵測隨機化的 C2。
  - **傳輸量** — 封包數量與酬載大小的一致性。
- **誤報抑制** — 多層懲罰機制，避免正常流量觸發警報：
  - 基礎設施允許清單（主要公用 DNS 解析器）
  - 協定感知（ICMP、NTP、mDNS、SSDP、IGMP 天生具有週期性）
  - 服務 Port 懲罰（HTTPS、IMAPS、Apple Push、MQTT、SIP）
  - 高流量大酬載過濾（串流/下載 vs. C2）

### 酬載提取（Carving）與 YARA 掃描
- 透過 `tshark` 提取 **HTTP 酬載**，自動計算 SHA256 雜湊。
- **YARA 規則設定** — 將 Config 中的 YARA Rules 區塊指向任何規則目錄（遞迴掃描）；零設定預設值為存在時的 `data/yara_rules/`。
- **安全儲存** — 每次執行專屬的隔離目錄，具備路徑穿越與符號連結防護。

### 誠實、以分析師為本的介面
- **集中式嚴重程度色彩系統** — 同一套色盤驅動所有判定徽章、圖表與狀態標籤，並附一行式圖例供校準。
- **誠實的供應商狀態** — OSINT 供應商狀態標籤區分正常 / 快取 / 速率受限 / 金鑰遭拒 / 無資料，而非籠統的錯誤訊息，並彙整所有查詢指標的狀態；Config 中的 Test Providers 按鈕可即時檢測每個已設定的供應商。
- **情境化空狀態** — 面板會區分「執行完畢且乾淨」與「階段被跳過/失敗」；絕不會出現無聲的空白。
- **人性化表格** — 標示 UTC 的時間戳記、進度條分數欄位、具名的圖表座標軸。
- **交叉篩選** — 地圖、協定圓餅圖與流量時間軸的統一鑽取；「排除私有 IP」在探索期間保持有效。
- **TopN 圖表** — 前幾名 IP、Port、協定、網域，附反向 DNS 主機名稱。
- **世界地圖** — 威脅等級著色、依傳輸量決定粗細的連線弧線、可設定的自家位置。

### OSINT 情資豐富化
整合領先的威脅情資供應商：
- **VirusTotal** — 檔案雜湊與 IP / 網域信譽。
- **AbuseIPDB** — 群眾回報的 IP 濫用報告。
- **GreyNoise** — 網際網路背景雜訊與掃描器識別。
- **OTX (AlienVault)** — 開放威脅交換脈衝與指標。
- **Shodan** — 面向網際網路的裝置詳情與開放 Port。
- **智慧快取** — SQLite 支援的快取，可設定 TTL 以節省 API 配額。
- **批次反向 DNS** — 對所有公開 IP 平行執行 rDNS 解析，搭配 7 天 SQLite 快取。
- **WHOIS 查詢** — 對任何列出的 IP 隨選查詢 WHOIS，可點選資料列或使用明確的下拉選單 + 按鈕。

### 案件管理系統
- 建立、追蹤與結案調查案件。
- 儲存 IOC（IP、網域、雜湊、JA3、URL），附帶嚴重程度與情境說明。
- 調查筆記、標籤分類與搜尋功能。

### 專業 PDF 匯出
- 多頁 PDF 報告，包含執行摘要、關鍵發現、技術分析與建議事項。
- **自我一致的章節登錄** — 章節編號與目錄由同一份登錄產生，因此永遠一致；LLM 撰寫的標題會降階至章節層級之下。
- **風險矩陣與 IOC 摘要** — 在 PDF 中以真正的表格呈現，而非散文。
- **內嵌儀表板圖表** — 協定分佈、流量大戶、流量時間軸、網路圖、世界地圖 — 透過 kaleido 轉為 PNG，便於靜態交付。
- **具時區資訊的時間戳記**，外加可設定的 TLP 分級與分析師中繼資料。

### 匯出格式
- **CSV / JSON** — 匯出任何資料表，內建 CSV 注入防護。
- **STIX 2.0/2.1** — 以標準 STIX 格式匯出指標。
- **ATT&CK Navigator** — 匯出技術對應至 MITRE ATT&CK Navigator。
- **CEF (ArcSight)** — 從關聯、信標、DNS 與 IOC 產生可供 SIEM 攝取的事件。

---

## 整合 API

PCAP Hunter 隨附以 FastAPI 打造的 REST API，與 Streamlit UI 並行運作，讓 SOAR 平台、SIEM 系統與自訂腳本能以程式方式提交 PCAP、輪詢工作進度、取得案件 / PDF 報告，並拉取 IOC 摘要（JSON / CSV / STIX 2.1）。它重複使用與 UI 相同的 10 階段管道、SQLite 案件資料庫與設定；資料庫支援的 API 金鑰可在 API Keys 分頁管理。無介面結果包含擷取品質指標與 ATT&CK 假設，IOC 摘要則包含相關技術 ID；若排程或保存失敗，暫存檔案與案件會一併移除。

```bash
make run-api     # http://localhost:8000
make smoke-api   # 對本地 API 執行端對端冒煙測試
```

> 端點參考、認證、curl 範例與 SIEM 整合指南：
> **[docs/API.md](../API.md)**（英文）與 **[整合 API 說明（繁體中文）](api/README.md)**

---

## 系統架構

```
app/
├── analysis/        # 關聯引擎、流量分析、IOC 評分、敘事產生
├── api/             # FastAPI 整合 API（REST 端點、認證、金鑰管理）
│   ├── routers/     # health、pcaps、jobs、cases、iocs、admin
│   ├── key_auth.py  # 資料庫 + 環境變數認證流程
│   ├── key_repository.py  # SQLite API 金鑰儲存
│   ├── rate_limiter.py    # 逐金鑰滑動視窗速率限制
│   └── queue.py     # 背景管道執行（ProcessPoolExecutor）
├── database/        # 案件管理（SQLite）
├── llm/             # LLM 用戶端 + 多供應商分派（providers.py）
├── pipeline/        # 10 階段分析管道
│   ├── runner.py    # 無介面協調器（平行階段、每次執行專屬目錄）
│   ├── beacon.py    # C2 信標偵測
│   ├── carve.py     # HTTP 酬載提取
│   ├── dns_analysis.py  # DGA、通道偵測、Fast Flux
│   ├── geoip.py     # GeoIP 解析
│   ├── ja3.py       # JA3/JA3S 指紋識別
│   ├── batch.py     # 多 PCAP 批次處理與關聯
│   ├── osint.py     # OSINT 供應商查詢（平行）
│   ├── osint_cache.py   # SQLite OSINT 快取層
│   ├── rdns_cache.py    # SQLite 反向 DNS 快取層
│   ├── tls_certs.py # 憑證驗證
│   └── yara_scan.py # YARA 規則掃描
├── reports/         # PDF 報告產生（WeasyPrint + kaleido 圖表）
├── security/        # OPSEC 強化與資料清理
├── threat_intel/    # MITRE ATT&CK 對應
├── ui/              # Streamlit 介面（10 個分頁、上傳驗證、MITRE 工作區）
├── utils/           # 匯出、GeoIP、設定、執行檔探索、CEF
├── config.py        # 應用程式預設值
└── main.py          # Streamlit 進入點
```

### 分析管道（10 個階段）

1. **封包計數** — 透過 tshark 快速初步計數
2. **封包解析** — 深度檢測最多 200,000 個封包（可設定）
3. **Zeek 處理** — 自動執行 Zeek 並解析 log
4. **DNS 分析** — DGA、通道偵測、Fast Flux、NXDOMAIN、查詢頻率
5. **TLS 憑證分析** — 憑證鏈驗證、自簽 / 過期偵測
6. **信標偵測排名** — 時序模式分析以偵測 C2
7. **HTTP 酬載提取** — 酬載提取並計算 SHA256 雜湊
8. **YARA 掃描** — 基於規則的檔案掃描
9. **OSINT 豐富化** — 多供應商信譽查詢
10. **LLM 報告產生** — AI 驅動的威脅綜整

階段 2–3（PyShark、Zeek）平行執行；解析合流後，階段 4–7（DNS、TLS、信標偵測、酬載提取）同時執行。Zeek 與酬載提取會寫入每次執行專屬的輸出目錄（`data/zeek|carved/<case>_<uuid8>/`），因此同時執行的分析絕不互相覆寫；過期的執行目錄會在 7 天後清除。

---

## 安裝

### 方案 A — Docker（建議）

這是標準的建置與驗證路徑。映像檔已內建 tshark、zeek、WeasyPrint 函式庫與所有 Python 相依套件——主機上只需要安裝 Docker。

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
make docker-up        # 建置 + 啟動 UI → http://localhost:8501
make docker-verify    # 在映像檔內執行格式檢查 + lint + 完整測試套件
make docker-down      # 停止 compose 服務
```

Compose 注意事項：

- `./data` 會掛載進容器，因此 PCAP、提取的檔案、Zeek log 與案件資料庫都存放在主機上。YARA 規則請放在 `./data/yara_rules`；可設定 `PCAP_HUNTER_DATA_BIND` 改用其他主機資料目錄。
- 在 UI 中儲存的 API 金鑰會保存在 `pcap-hunter-home` volume；compose 檔固定了 `hostname:`，確保設定加密金鑰在容器重建後維持穩定。
- 主機上執行的 LM Studio 從容器內即可連線——`LM_BASE_URL` 預設為 `http://host.docker.internal:1234/v1`。
- 第二個 compose 服務（`pcap-hunter-api`）使用同一個映像檔，在 8000 連接埠提供整合 API。

### 方案 B — 獨立安裝

所有安裝邏輯都集中在單一跨平台腳本（`scripts/install.py`），它會偵測你的作業系統與套件管理器、安裝系統執行檔與 Python 套件，最後驗證一切就緒。

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
python3 scripts/install.py
make run              # → http://localhost:8501
```

各平台安裝內容：

| 平台 | 套件管理器 | 系統套件 |
|------|-----------|----------|
| macOS | `brew` | `wireshark`（tshark + capinfos）、`zeek`、`yara`，以及 WeasyPrint PDF 匯出所需的 `pango` + `glib` + `cairo` |
| Linux | `apt-get` | `tshark`、`zeek`、`yara`、`libpcap0.8`，以及 WeasyPrint 執行階段函式庫（`libpango-1.0-0`、`libpangocairo-1.0-0`、`libpangoft2-1.0-0`、`libharfbuzz0b`、`libcairo2`、`libgdk-pixbuf-2.0-0`、`shared-mime-info`、`fonts-dejavu-core`）；非 apt 發行版會提供手動安裝提示（dnf/pacman） |
| Windows | `winget` → `choco` → `scoop` | Wireshark（winget/choco/scoop）、YARA（choco/scoop）；Zeek 沒有原生 Windows 版本——安裝程式會引導你改用 WSL2 或 Docker |

接著它會以 pip 安裝 `requirements.txt`（不需另外安裝 Chromium——鎖定版本的 `kaleido==0.2.1` 自帶無介面渲染器），並執行相依性檢查。必要的 Python 套件會逐一驗證（streamlit、pandas、numpy、pyshark、scapy、openai、anthropic、requests、cryptography、plotly、kaleido、markdown、jinja2、fastapi、uvicorn）；`weasyprint` 與 `yara-python` 列為選用——缺少時應用程式會優雅降級。

偏好平台慣用的工作流程？以下包裝指令全都委派給同一個 `install.py`：

| 平台 | 指令 |
|------|------|
| macOS / Linux | `make install` |
| Windows（PowerShell） | `.\scripts\install.ps1`（先安裝好 Python，再委派執行） |
| 任何平台 | `python3 scripts/install.py` |

### 安裝程式參數

```
python3 scripts/install.py              # 完整安裝 + 驗證
python3 scripts/install.py --check-only # 僅執行相依性檢查
python3 scripts/install.py --skip-system # 僅安裝 Python 套件
python3 scripts/install.py --skip-python # 僅安裝系統執行檔
python3 scripts/install.py --dry-run    # 預覽指令而不執行
python3 scripts/install.py --yes        # 非互動模式（自動確認）
```

### Windows 注意事項

**Zeek 沒有原生 Windows 版本。** 原生 Windows 安裝可執行 tshark 管道，但會跳過 Zeek 協定分析階段。若要在 Windows 上執行完整管道，請使用：

- **Docker**（最簡單）— `make docker-up` 或 `docker compose up --build`
- **WSL2** — `wsl --install -d Ubuntu`，然後在 Ubuntu 內執行 `python3 scripts/install.py`

### 驗證安裝

```bash
make doctor                              # macOS / Linux
python3 scripts/install.py --check-only  # 任何作業系統（含 Windows）
```

應用程式啟動時也會執行此檢查，若缺少任何必要的執行檔，每個頁面頂端都會顯示紅色警示橫幅——你永遠不會遇到無聲的空白儀表板。

---

## 快速開始

```bash
make docker-up   # Docker（建議）→ http://localhost:8501
# — 或 —
make run         # 獨立安裝（先執行 python3 scripts/install.py）
```

在瀏覽器中開啟 `http://localhost:8501`。

---

## 使用指南

1. **上傳** — 在 Upload 分頁拖放一個或多個 `.pcap` 檔案。多個檔案會啟動批次模式並進行跨檔案關聯分析。
2. **設定** — 在 Config 分頁選擇 LLM 供應商（LM Studio / OpenAI / Anthropic）、設定自家位置（洲 > 國家 > 城市）、OSINT API 金鑰，並可選擇性指定 YARA 規則目錄。
3. **分析** — 點擊 **Extract & Analyze** 啟動管道。
4. **監控** — 在 Progress 分頁觀察各階段執行：封包計數 > 解析 + Zeek（平行）> DNS / TLS / 信標偵測 / 酬載提取（同時執行）> YARA > OSINT > LLM 報告。
5. **審閱** — 在 Dashboard、MITRE Analysis、LLM Analysis、OSINT、Raw Data、Cases 分頁瀏覽結果。
6. **匯出** — 下載 CSV/JSON 資料、PDF 報告、STIX 套件、ATT&CK Navigator 圖層或 CEF syslog 事件。

### 重新產生報告

更換了 LLM 供應商、模型或報告語言？點擊 **Re-run Report** 僅重新產生 AI 報告，無需重新處理整個 PCAP。

### 資料管理

使用 Config 分頁中細緻的 **Clear** 按鈕，分別清除 PCAP 資料、OSINT 快取或案件資料庫。

---

## 設定

- 預設值位於 `app/config.py`（門檻值、路徑、URL）
- 持久化設定位於 `~/.pcap_hunter_config.json`（由 `ConfigManager` 管理）
- API 金鑰以機器衍生的 PBKDF2 金鑰加密儲存
- 環境變數覆寫：`OTX_KEY`、`VT_KEY`、`SHODAN_KEY` 等
- LLM 預設值：LM Studio 位於 `http://localhost:1234/v1`
- YARA 規則：目錄留空時，若 `data/yara_rules/` 存在則自動使用

### 主要門檻值

| 設定項 | 預設值 | 用途 |
|--------|--------|------|
| DGA 熵值 | 4.0 位元 | DGA 偵測的夏農熵門檻 |
| Fast Flux | 10 個以上 IP | 每個網域的最少相異 IP 數 |
| 流量不對稱 | 10:1 且 ≥1 MB | 資料外洩候選門檻 |
| C2 常見 Port | 4444、5555、6666、7777、8888、9999、1337、31337 | Port 異常比對清單 |
| PyShark 上限 | 200,000 個封包 | 深度解析上限 |
| 流量取樣上限 | 每條流量 5,000 筆 | 取樣的時間戳記/封包長度（真實總計維持精確） |
| 執行目錄保留 | 7 天 | 每次執行的 `data/zeek\|carved/` 目錄於下次執行時清除 |
| 子行程逾時 | zeek 600 秒；計數 120 秒；酬載提取 / TLS 萃取 300 秒 | 外部工具呼叫皆有逾時上限 |

---

## 開發

### 提交前檢查 — `make verify`

```bash
make verify     # 格式檢查 + lint + 完整測試套件
```

每次提交前都必須執行。CI（GitHub Actions、Python 3.11）會對每次推送 / PR 至 `main` 執行相同檢查。涉及建置的驗證（相依套件變更、安裝路徑、發佈檢查）請使用 `make docker-verify`——它會在執行階段映像檔內執行完全相同的檢查，不受主機 Python 環境影響。

### Make 目標

| 目標 | 功能 |
|------|------|
| `make install` | 完整安裝（系統 + Python）+ 驗證 |
| `make install-system` / `make install-python` | 僅系統執行檔 / 僅 Python 套件 |
| `make check-deps` / `make doctor` | 驗證所有相依套件已就緒 |
| `make run` | 啟動應用程式（先檢查相依套件） |
| `make test` | 執行測試套件並產生覆蓋率報告 |
| `make test-pdf` | 聚焦 PDF + 圖表的測試套件 |
| `make verify` | 提交前檢查：格式 + lint + 完整測試 |
| `make lint` / `make format` | Ruff 檢查 / Ruff 格式化 |
| `make clean` | 清除快取 |
| `make docker-build` | 建置執行階段映像檔（`pcap-hunter:latest`） |
| `make docker-up` | 建置 + 啟動 UI 容器於 :8501 |
| `make docker-down` | 停止 compose 服務 |
| `make docker-verify` | 在映像檔內執行格式 + lint + 完整測試 |
| `make run-api` / `make run-api-dev` | 啟動整合 API 於 :8000（dev 模式加上 --reload） |
| `make smoke-api` | 對本地 API 執行端對端冒煙測試 |
| `make fix-permissions` | 授予 macOS BPF 擷取權限 |

### 重新產生文件截圖

`scripts/capture_screenshots.py` 使用 Playwright 無介面 Chromium（搭配 tesseract 進行 OCR）從真實 Docker Streamlit UI 重新擷取所有 README / 使用手冊截圖，並在圖片像素中遮蔽 IPv4/IPv6 位址、API 機密、電子郵件與本機使用者路徑。最終 OCR 稽核若仍辨識出敏感值會使擷取失敗。

```bash
python3 -m pip install -r requirements-docs.txt
python3 -m playwright install chromium
DOCS_DATA="$(mktemp -d)"
cp data/sample.pcap "$DOCS_DATA/sample.pcap"
PCAP_HUNTER_DATA_BIND="$DOCS_DATA" make docker-up
python3 scripts/capture_screenshots.py --seed-docs-key
```

隔離的資料掛載可避免本機案件、金鑰、快取或先前擷取進入文件。範例 API 金鑰會透過真實 UI 建立，且在截圖前重新載入以清除只顯示一次的完整機密。

### 測試紀律

PCAP Hunter 使用**與生產環境相同形狀的測試資料**，而非簡化的輸入。標準範例請見 `tests/test_pdf_integration.py`——真實的 `CorrelationSignal` dataclass、真實的 pandas DataFrame，以及管道實際產生的巢狀 dict 形狀。新增 PDF 章節或圖表時，請同步擴充對應的整合測試。

---

## 說明文件

- **[User Manual (English)](../en/USER_MANUAL.md)** — 英文使用手冊
- **[使用手冊（繁體中文）](USER_MANUAL.md)** — 繁體中文使用手冊
- **[整合 API 參考文件](../API.md)** — REST 端點、認證、設定（英文）
- **[API 整合指南（繁體中文）](api/README.md)** — SIEM / SOAR 整合範例
- **[English README](../../README.md)** — 英文版說明
- **[CLAUDE.md](../../CLAUDE.md)** — 貢獻者 / AI 指南：慣例、測試紀律、已知錯誤模式
- **[docs/FEATURE-ROADMAP.md](../FEATURE-ROADMAP.md)** — 規劃中的工作

---

## 授權條款

[MIT License](../../LICENSE) — 詳情請見授權檔案。
