# PCAP Hunter 使用手冊

**PCAP Hunter** 是一個 AI 增強的威脅獵捕工作台，旨在填補手動封包分析與自動化資安監控之間的鴻溝。它結合業界標準工具（**Zeek**、**Tshark**、**PyShark**）與 **LLM** 及 **OSINT** 威脅情資，從網路流量中快速攝取、分析並提取可執行的情資。

本手冊以一位新進 SOC 分析師的視角逐步走過整個應用程式：安裝、載入擷取檔、觀察管道執行，然後逐個分頁處理分析結果。

---

## 📚 目錄
1. [快速入門](#快速入門)
   - [Docker 安裝（建議）](#docker-安裝建議)
   - [獨立安裝](#獨立安裝)
   - [初次啟動](#初次啟動)
2. [載入 PCAP](#載入-pcap)
3. [分析管道與 Progress 分頁](#分析管道與-progress-分頁)
4. [儀表板](#儀表板)
5. [MITRE ATT&CK 分析](#mitre-attck-分析)
6. [OSINT 情資豐富化](#osint-情資豐富化)
7. [LLM 分析與 AI 威脅報告](#llm-分析與-ai-威脅報告)
8. [Raw Data 分頁](#raw-data-分頁)
9. [案件管理](#案件管理)
10. [匯出與 PDF 報告](#匯出與-pdf-報告)
11. [設定](#設定)
12. [資料保留](#資料保留)
13. [疑難排解](#疑難排解)

---

## 快速入門

### Docker 安裝（建議）

Docker 映像檔已內建 tshark、Zeek、WeasyPrint PDF 函式庫與所有 Python 相依套件——主機上只需要安裝 Docker。

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
make docker-up        # 建置 + 啟動 UI → http://localhost:8501
make docker-down      # 結束時停止服務
```

注意事項：

- **`./data` 會掛載進容器** — PCAP、提取的檔案、Zeek log 與案件資料庫都存放在主機上，容器重啟後依然存在。YARA 規則請放在 `./data/yara_rules`。
- **在 UI 中儲存的 API 金鑰會持久保存**在 `pcap-hunter-home` Docker volume 中。compose 檔固定了容器的 `hostname:`，確保機器衍生的設定加密金鑰在容器重建後維持穩定。
- **主機上執行的 LM Studio 從容器內即可連線** — `LM_BASE_URL` 預設為 `http://host.docker.internal:1234/v1`。
- 第二個 compose 服務（`pcap-hunter-api`）使用同一個映像檔，在 8000 連接埠提供整合 API。

### 獨立安裝

單一跨平台安裝程式會偵測你的作業系統與套件管理器、安裝系統執行檔（tshark、Zeek、YARA、WeasyPrint 函式庫）與 Python 套件，最後驗證一切就緒：

```bash
git clone https://github.com/ninedter/pcap-hunter.git
cd pcap-hunter
python3 scripts/install.py
make run              # → http://localhost:8501
```

`make install`（macOS/Linux）與 `.\scripts\install.ps1`（Windows PowerShell）是同一個腳本的包裝指令。實用參數：`--check-only`、`--skip-system`、`--skip-python`、`--dry-run`、`--yes`。

> **Windows 注意：** Zeek 沒有原生 Windows 版本。原生安裝可執行 tshark 管道，但會跳過 Zeek 階段——若要完整管道，請使用 Docker 或 WSL2。

### 初次啟動

- 在第一次完成分析之前，Upload 分頁會顯示可關閉的 **Getting started** 入門導覽面板：載入 PCAP、點擊 **Extract & Analyze**、觀察 **Progress**，然後審閱 **Dashboard**。點擊 **"Got it — don't show again"** 即可隱藏。
- 應用程式啟動時會執行相依性檢查，若缺少必要的執行檔（例如 `tshark`），每個頁面都會顯示**紅色警示橫幅**——你永遠不會遇到無聲的空白儀表板。手動檢查：`make doctor` 或 `python3 scripts/install.py --check-only`。

---

## 載入 PCAP

開啟 **Upload** 分頁。

- **拖放**一個或多個 `.pcap` / `.pcapng` 檔案。瀏覽器上傳器接受**每個檔案最大 200 MB**。
- **更大的檔案——使用路徑欄位。** 在 *"...or type a container path"* 欄位輸入路徑後按 Enter。路徑必須指向允許目錄內的 `.pcap`/`.pcapng` 檔案：`data/`、`pcaps/` 或 `/data/`。在 Docker 中，主機的 `./data` 已掛載進容器——把大型擷取檔放進 `./data/`，再以 `/data/<檔名>.pcap` 參照即可。
- **批次模式**會在上傳多個檔案時自動啟動：每個檔案獨立執行完整管道，接著跨檔案關聯分析會偵測跨擷取檔共用的 IP、網域與 JA3 指紋。限制：50 個檔案、每個檔案 1 GB、總計 5 GB。

點擊 **Extract & Analyze** 開始分析。

工作會立刻排入佇列並建立自動保存的 Case。即使按下 Streamlit 右上角的 **Stop** 或重新載入瀏覽器，分析仍會在獨立工作行程中繼續。七天內重新開啟應用程式會自動接回最近的 UI 工作；已完成的證據也可隨時從 **Cases** 重新開啟。

---

## 分析管道與 Progress 分頁

PCAP Hunter 執行 10 階段管道：

| # | 階段 | 功能 |
|---|------|------|
| 1 | 封包計數 | 透過 tshark 快速初步計數 |
| 2 | 封包解析 | PyShark 深度檢測（預設上限 200,000 個封包） |
| 3 | Zeek 處理 | 自動執行 Zeek 並解析 `conn`/`dns`/`http`/`ssl` log |
| 4 | DNS 分析 | DGA、通道偵測、Fast Flux、NXDOMAIN、查詢頻率 |
| 5 | TLS 憑證分析 | 憑證鏈驗證、自簽 / 過期偵測 |
| 6 | 信標偵測排名 | 統計式 C2 週期性 / 抖動 / 傳輸量評分 |
| 7 | HTTP 酬載提取 | 酬載提取並計算 SHA256 雜湊 |
| 8 | YARA 掃描 | 對提取檔案進行規則式掃描 |
| 9 | OSINT 豐富化 | 多供應商信譽查詢 |
| 10 | LLM 報告產生 | AI 威脅綜整 |

**執行形態：** 階段 2–3（PyShark、Zeek）**平行執行**；兩者完成後，階段 4–7（DNS、TLS、信標偵測、酬載提取）**同時**展開。Progress 分頁會監看可復原的背景工作：

- 整體進度條與逐檔案列會顯示目前階段及工作狀態。
- Streamlit 右上角的 **Stop** 只會暫停頁面顯示，不會取消工作行程或刪除已完成階段。
- 提交前可在 **Config** 啟用或停用管道元件；**Upload** 另有是否產生 LLM 報告的核取方塊。
- 最後一個階段 **LLM Report Analysis** 會在工作行程中執行，報告也會與分析一同保存。

管道完成後，保存的結果會復原至 Dashboard、MITRE Analysis、LLM Analysis、OSINT 與 Raw Data。

---

## 儀表板

**Dashboard** 分頁是你的指揮中心。由上而下：

### 威脅摘要

五個一目了然的指標：**Risk Level**（風險等級）、**Total Alerts**（總警報數）、**Beacon Candidates**（信標候選）、**YARA Hits**（YARA 命中）與 **Cert Issues**（憑證問題），下方緊接一行式的**嚴重程度色彩圖例**，讓你校準頁面上每個徽章與圖表的顏色。

### 「Why this risk level?」可解釋性面板

展開摘要下方的 **Why this risk level?** 面板，即可精確看到哪些訊號促成了這個判定。風險等級就是**實際觸發的最高層級**，升級規則如下：

- **第一層（決定性）** — OSINT 確認（例如 VirusTotal 偵測、GreyNoise 判定*惡意*）。任何單一第一層命中即設定分數下限。
- **第二層（行為性）** — C2 信標、流量不對稱、DNS 通道、DGA 網域。
- **第三層（情境性）** — AbuseIPDB 回報、自簽 / 過期憑證、YARA 比對。
- 僅有第三層訊號時**絕不會超過 Medium**；High/Critical 需要跨層級的交叉佐證。

如果沒有任何訊號觸發，面板會直接說明："✅ No threat signals fired — nothing exceeded thresholds"。

### 誠實的空狀態

每個面板都會區分兩種截然不同的「這裡沒東西」：

- **✅ 已執行且結果乾淨** — 該階段確實執行完畢，沒有發現任何問題。這是貨真價實的陰性結果。
- **📭 未執行 / 無資料** — 該階段被跳過、執行失敗，或其資料未被保存（例如 "📭 DNS analysis was skipped for this run."）。這不能當作「沒有威脅」的證據。

把 ✅ 視為一個答案，把 📭 視為結案前必須補齊的缺口。

## MITRE ATT&CK 分析

**MITRE ATT&CK Analysis** 是獨立於 Dashboard 的工作區。它會把網路證據對應成**分析假設**，並為每項技術顯示支援證據與信心等級；同時呈現偵測器涵蓋範圍與可見性缺口，避免把未執行的階段誤認為乾淨結果。

此頁面刻意限定在擷取檔範圍內：單靠 PCAP 無法證明程序來源、使用者身分、授權狀態、主機持久化或感測器以外的流量。確認技術前，請回看原始流量並補充端點遙測。**Coverage & Gaps** 子分頁會記錄封包解析涵蓋率、擷取時間窗、流量總量、取樣限制、階段警告與偵測器可見性；**Exports** 子分頁可下載含目前 ATT&CK 版本資訊的 Navigator 圖層。

### 篩選器與圖表

- **世界地圖** — 框選 / 套索選取會交叉篩選整個儀表板；在 Config 設定自家位置可讓連線弧線準確呈現。
- **協定圓餅圖** — 點擊切片即可依協定篩選。
- **流量時間軸** — 拖曳即可縮放至特定時間視窗。圖表時間軸皆標示 **UTC**。
- **Exclude Private IPs**（排除私有 IP）在探索期間保持有效；**Clear All Filters** 一鍵重置所有篩選。
- **Top 10 表格**：來源 / 目的 IP（附反向 DNS 主機名稱）、Port、協定 / 網域；另有 Sankey 圖與力導向網路圖。

### 流量表

流量表包含明確的 **First Seen (UTC)** 與 **Last Seen (UTC)** 欄位——即使每條流量的封包取樣有上限（每條 5,000 筆），真實的流量起訖時間仍維持精確。

---

## OSINT 情資豐富化

**OSINT** 分頁透過 VirusTotal、AbuseIPDB、GreyNoise、OTX、Shodan 與 VT Domain，對最活躍的公開 IP（預設：前 50 名，可設定）及觀察到的網域進行情資豐富化。

### 供應商狀態標籤——先看這裡

每個被查詢的供應商都會誠實回報狀態，並彙整所有指標的查詢結果：

| 標籤 | 意義 | 處理方式 |
|------|------|----------|
| ✅ *供應商* | 查詢成功 | 各欄位資料可信 |
| 💾 *供應商* | 來自本地 SQLite 快取 | 沒問題——可節省配額；需要最新資料時可在 Config 清除快取 |
| ⏳ *供應商* rate limited | API 配額用罄 | 等待配額視窗重置，或升級金鑰 |
| 🔑 *供應商* key rejected | 認證失敗 | 到 Config → OSINT API Keys 修正金鑰 |
| ➖ *供應商* no data | 供應商有回應，但**對這些指標沒有任何資料** | **不是故障**——這些指標單純不在該來源的資料庫裡 |
| *（無標籤）* | 供應商未設定 / 未查詢 | 想要它的訊號就到 Config 加入金鑰 |

➖ 的區別非常重要：「no data」是運作正常的供應商給出的真實、誠實答案——別誤以為整合壞掉了，也別把它當成指標無害的證明。

### 操作方式

- **IP 分級表** — 逐 IP 的判定結果，合併各供應商分數、rDNS 主機名稱與進度條分數欄位。
- **WHOIS 查詢** — 在**下拉選單中選取 IP 並點擊查詢按鈕**，或直接**點選表格中的資料列**；兩者都會開啟 WHOIS 詳細資訊對話框。
- **網域** — 觀察到的網域之信譽與分類。
- **詳細資訊卡** — 每個指標完整的供應商細項。
- 其他子分頁：地理地圖、基礎設施（ASN 分群）、匯出、裝置、筆記。
- **IOC 搜尋** — 跨所有指標搜尋；**顯示全部結果的切換開關**可突破預設的結果數上限。

---

## LLM 分析與 AI 威脅報告

**LLM Analysis** 分頁產生以管道量化結果為依據的敘事威脅報告。三種可互換的供應商（在 Config → LLM Integration 設定）：

| 供應商 | 執行位置 | 產生方式 |
|--------|----------|----------|
| **LM Studio** | 本地 / 實體隔離 | 逐節分段（chunked）產生，配合較小的上下文視窗 |
| **OpenAI** | 雲端 | 單次完整上下文呼叫——全部證據語料一次送入 |
| **Anthropic** | 雲端 | 透過官方 SDK 的單次完整上下文呼叫並支援串流（`claude-opus-4-8`、`claude-sonnet-4-6`、`claude-haiku-4-5`） |

雲端的前沿模型會在內文加入 **MITRE ATT&CK 技術編號**，並提出**謹慎保留的假設**（「與……一致」、「若……即可確認」），而非過度斷言。

### 報告章節

1. Executive Summary（執行摘要）
2. Threat Correlation（威脅關聯）
3. Indicators & Evidence（指標與證據）
4. OSINT Corroboration（OSINT 佐證）
5. DNS & TLS Analysis（DNS 與 TLS 分析）
6. Beaconing & Network（信標與網路）
7. Risk Assessment（風險評估）— 內含**以真正 Markdown 表格呈現的風險矩陣**（每個類別一列）
8. Recommended Actions（建議行動）
9. IOC Summary（IOC 摘要）— 結構化的 **IOC 表格**（指標、類型、判定、證據）

報告支援 **9 種語言**——美式英文、**繁體中文（zh-tw，台灣用語）**、簡體中文、日文、韓文、義大利文、西班牙文、法文、德文——在 Config 中選擇。

### 重新產生報告

更換了供應商、模型或語言？點擊 **Re-run Report** *僅*重新產生 AI 報告——不會重新處理 PCAP。

---

## Raw Data 分頁

**Raw Data** 分頁公開所有底層資料來源：流量表、DNS 分析（DGA / 通道偵測 / NXDOMAIN）、TLS 憑證與 JA3/JA3S 指紋、Zeek `conn.log` / `dns.log` / `http.log` / `ssl.log`、附 SHA256 雜湊的 HTTP 提取酬載，以及 YARA 掃描結果。任何檢視都能匯出為 CSV 或 JSON，內建 CSV 注入防護。

---

## 案件管理

**Cases** 分頁把一次擷取分析變成可持續追蹤的調查：

- **儲存**目前的分析到案件——IOC、嚴重程度、標籤、調查筆記與狀態都存放在本地 SQLite 資料庫，可跨工作階段搜尋。
- **Load into Dashboard** 會把已儲存案件的結果還原到即時儀表板。

**還原與重置的範圍：** 已儲存的發現（摘要指標、IOC、關聯結果、報告）會還原；*未*保存在案件記錄中的重型產物（例如完整的封包層級資料、已清除的執行目錄）會顯示 **「📭 not available」** 空狀態，直到你重新分析原始 PCAP 為止。儀表板會明確告訴你哪些是哪些——見[誠實的空狀態](#誠實的空狀態)。

---

## 匯出與 PDF 報告

### PDF 報告

在 LLM Analysis 分頁點擊 **Generate PDF Report**。PDF 包含：

- 封面頁，附可設定的 **TLP 分級**與分析師中繼資料。
- **帶編號的章節與相符的目錄**——兩者由同一份章節登錄產生，編號與目錄永遠一致。
- 完整的 AI 敘事報告，**風險矩陣與 IOC 摘要以真正的表格呈現**，外加 YARA 結果與 TLS 發現。
- **內嵌儀表板圖表**（協定分佈、流量大戶、流量時間軸、網路圖、世界地圖），轉為 PNG 呈現。
- 全文使用**具時區資訊的時間戳記**。

### 資料匯出

- **CSV / JSON** — 任何表格，內建 CSV 注入防護。
- **STIX 2.0 / 2.1** — 標準指標套件。
- **ATT&CK Navigator** — 技術對應圖層檔案。
- **CEF (ArcSight)** — 從關聯、信標、DNS 與 IOC 產生可供 SIEM 攝取的事件。

> 需要程式化存取？**整合 API** 在 8000 連接埠提供 PCAP 提交、工作輪詢與 IOC 摘要（JSON / CSV / STIX 2.1）——詳見 [docs/API.md](../API.md)。

---

## 設定

所有設定都在 **Config** 分頁；設定會持久化至 `~/.pcap_hunter_config.json`，API 金鑰以 PBKDF2 加密儲存。

### LLM Integration

- **供應商選擇器**（LM Studio / OpenAI / Anthropic），每個供應商有獨立欄位：base URL、API 金鑰，以及附 **Fetch Models** 按鈕的模型選單。
- **Test Connection** 會實際探測所選供應商並就地回報結果。
- **報告語言** — 即前述的 9 種語言選單。

### OSINT API Keys

- VirusTotal、AbuseIPDB、GreyNoise、OTX、Shodan 的金鑰。環境變數（`VT_KEY`、`SHODAN_KEY` 等）會覆寫已儲存的設定。
- **Test Providers** 會用無害的指標即時檢測每個已設定的供應商，回報與 OSINT 狀態標籤相同的狀態（ok / rate limited / key rejected / …）——輸入新金鑰後請執行一次。

### YARA Rules

- 將 **YARA Rules directory** 指向任何含 `.yar`/`.yara` 規則的資料夾（遞迴掃描）。
- **零設定預設值：** 留空時，若 `data/yara_rules/` 存在則自動使用。在 Docker 中，把規則放在 `./data/yara_rules`——data 資料夾已掛載。
- 欄位下方提供**即時回饋**，顯示在設定路徑找到的規則檔數量，讓你在執行前就確定規則會被載入。

### 其他區塊

- **執行檔路徑** — 覆寫自動偵測到的 `zeek` / `tshark` 位置；System Health 區塊顯示偵測結果。
- **自家位置** — 洲 → 國家 → 城市；作為世界地圖連線弧線的起點。
- **Extraction / Analysis** — 切換管道階段（Zeek、酬載提取、YARA、預先計數、OSINT 快取）與 PyShark 封包上限（預設 200,000）。
- **資料管理** — 各自獨立的 **Clear** 按鈕，分別清除 PCAP 資料、OSINT 快取與案件資料庫。

### API Keys 分頁

整合 API 的程式化金鑰在獨立的 **API Keys** 分頁管理：建立 / 撤銷金鑰、指定權限範圍（完整或僅限摘要）、設定到期時間與逐金鑰速率限制，並查看使用量趨勢圖。環境變數金鑰會顯示為唯讀的初始（bootstrap）項目。

---

## 資料保留

- 每次執行都會把 Zeek 與提取檔案的輸出寫入**每次執行專屬的目錄**：`data/zeek/<case>_<uuid8>/` 與 `data/carved/<case>_<uuid8>/`——同時執行的分析絕不互相覆寫。
- 過期的執行目錄會在 **7 天後自動清除**（於下次執行時觸發）。**請及早匯出需要保留的證據**——提取的酬載、Zeek log——避免到期被清掉。
- OSINT 回應與反向 DNS 結果快取於 SQLite（rDNS TTL：7 天）以節省 API 配額；需要全新查詢時可在 Config 清除。

---

## 疑難排解

| 症狀 | 可能原因 | 解法 |
|------|----------|------|
| 紅色橫幅：缺少必要執行檔（例如 `tshark`） | 相依套件未安裝 | 依照橫幅上的作業系統專屬提示操作，或執行 `python3 scripts/install.py`；以 `make doctor` 驗證。Docker 中不會發生——執行檔已內建 |
| YARA 面板顯示「no rules configured」 | 未設定規則目錄，且 `data/yara_rules/` 不存在 | 將 Config → YARA Rules 指向你的規則資料夾，或建立 `data/yara_rules/`（Docker：`./data/yara_rules`）；留意即時規則數量回饋 |
| OSINT 標籤 ⏳ *GreyNoise rate limited* | 免費 / 社群配額用罄 | 等待配額視窗重置或升級金鑰；快取結果（💾）仍可使用 |
| Docker 環境中 LM Studio「Test Connection」失敗 | 容器網路與主機不同，區域網路或迴路位址可能無法直接路由 | 使用 `http://host.docker.internal:1234/v1`（compose 預設值）。Docker 執行環境也會自動將 `192.168.2.114:1234` 這類主機區域網路位址轉換；確認 LM Studio 伺服器已啟動 |
| OSINT 標籤 ➖ *no data* | 供應商沒有這些指標的紀錄 | 不需處理——這是誠實的陰性結果，不是錯誤 |
| PDF 產生錯誤（獨立安裝的 macOS/Linux） | 缺少 WeasyPrint 系統函式庫 | macOS：`brew install pango glib cairo`；Linux：安裝 `libpango`/`libcairo` 系列（安裝程式會處理）。Docker 映像檔已內含 |
| 載入案件後儀表板面板顯示 📭 | 該產物未保存在案件中 | 重新分析原始 PCAP 即可重新產生 |
