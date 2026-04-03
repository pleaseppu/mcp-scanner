# MCPB 安全掃描工具

針對 MCP Bundle（`.mcpb`）檔案的多層靜態安全掃描 CLI 工具，在部署前偵測供應鏈攻擊、後門程式、惡意程式碼與已知漏洞。

---

## 功能特色

| 層次 | 模組 | 掃描內容 |
|------|------|---------|
| 第一層 | **Trivy** | 相依套件 CVE 漏洞（CRITICAL / HIGH / MEDIUM） |
| 第一層 | **VirusTotal** | SHA256 雜湊值比對（僅查詢，不上傳檔案） |
| 第二層 | **Semgrep — MCPB 自訂規則** | 硬寫入 API key、subprocess shell=True、os.system、環境變數大量讀取、不安全反序列化 |
| 第二層 | **Semgrep — obfuscation** | base64+eval、壓縮解碼後執行、compile 套疊、importlib 動態載入 |
| 第二層 | **Semgrep — p/secrets** | 38+ 種 API 金鑰、Token、密碼型態（Semgrep 官方規則集） |
| 第二層 | **Semgrep — p/typescript** | TypeScript / JavaScript MCP 伺服器（自動偵測，僅在含 .ts/.js 時啟用） |
| 第二層 | **Bandit** | Python 安全靜態分析：eval/exec 危險呼叫、弱加密、XML 注入等 |
| 第二層 | **Cisco MCP Scanner** | YARA 引擎掃描 tool 描述文字、docstring 中的 Prompt Injection 與工具投毒模式 |
| 第二層 | **AI 審查（Maisy）** | Claude 模型全面審查原始碼，判定通過 / 需要審查 / 拒絕 |

---

## 系統需求

- Python 3.11+（Cisco MCP Scanner 需要 python3.11）
- [Trivy](https://github.com/aquasecurity/trivy) — `brew install trivy`
- [Semgrep](https://semgrep.dev) — `brew install semgrep`
- [Bandit](https://bandit.readthedocs.io) — `pip install bandit`
- Cisco MCP Scanner（選用）— 見下方安裝說明
- Python 套件：`pip install -r requirements.txt`

---

## 安裝

```bash
# 1. 取得原始碼
git clone <此 repo>
cd mcpb-scanner

# 2. 安裝 Python 相依套件
pip install -r requirements.txt

# 3. 安裝外部工具
brew install trivy semgrep
pip install bandit

# 4. 安裝 Cisco MCP Scanner（選用，需要 python3.11）
python3.11 -m pip install git+https://github.com/cisco-ai-defense/mcp-scanner.git

# 5. 設定環境變數
cp .env.example .env
# 編輯 .env，填入 API 金鑰
```

---

## 設定（.env）

```dotenv
# Maisy / Claude API — AI 安全審查必要
MAISY_API_URL=https://your-internal-proxy/v1/messages
MAISY_API_KEY=your-api-key
MAISY_MODEL=claude-sonnet-4-20250514   # 可選，預設值如左

# VirusTotal — 雜湊查詢用（不填則略過）
VIRUSTOTAL_API_KEY=your-vt-api-key
```

> **重要**：VirusTotal 整合僅執行 SHA256 雜湊值查詢，**不會上傳任何檔案內容**，確保程式碼不會洩漏至公開資料庫。

---

## 使用方式

```bash
# 基本掃描（終端輸出）
python scanner.py scan ./target.mcpb

# 輸出 PDF 報告
python scanner.py scan ./target.mcpb --output report.pdf

# 輸出 Markdown 報告
python scanner.py scan ./target.mcpb --output report.md

# 略過特定模組
python scanner.py scan ./target.mcpb --skip virustotal ai
python scanner.py scan ./target.mcpb --skip trivy virustotal bandit cisco ai

# 更新所有工具
python scanner.py update

# 只更新指定工具
python scanner.py update semgrep bandit
```

### 退出代碼

| 代碼 | 意義 |
|-----|------|
| `0` | 通過 |
| `1` | 需要審查 或 拒絕 |

可直接整合至 CI/CD pipeline。

---

## 風險評分邏輯

| 事件 | 分類 | 分數 |
|------|------|------|
| Trivy CRITICAL CVE | 拒絕分 | +10 / 筆 |
| Trivy HIGH CVE | 審查分 | +3 / 筆 |
| VirusTotal 惡意 ≥ 3 | 拒絕分 | +30 |
| VirusTotal 惡意 1–2 | 審查分 | +15 |
| Semgrep ERROR | 審查分 | +5 / 筆 |
| Bandit HIGH | 審查分 | +4 / 筆 |
| Cisco YARA HIGH | 拒絕分 | +8 / 筆 |
| Cisco YARA MEDIUM | 審查分 | +5 / 筆 |
| AI 判定拒絕 | 拒絕分 | +20 |
| AI 判定需審查 | 審查分 | +10 |

**拒絕分 ≥ 10 → 拒絕；審查分 ≥ 10 → 需要審查；其餘 → 通過**

AI 審查設計傾向通過：只有在確認存在實質風險時才給出「需要審查」或「拒絕」。

---

## 掃描模組說明

### Trivy（CVE 漏洞）

掃描 `uv.lock`、`requirements.txt`、`pyproject.toml` 等相依檔案，比對 NVD / GitHub Advisory 資料庫。任何 CRITICAL 等級漏洞即觸發拒絕。

### VirusTotal（雜湊查詢）

以 SHA256 向 VirusTotal 公共 API 查詢。檔案不存在於資料庫時回報「尚無紀錄」（非錯誤）。**嚴格禁止上傳檔案**，確保敏感程式碼不外洩。

### Semgrep（靜態分析，多輪）

分四輪執行，結果去重後合併：

1. **MCPB 自訂規則**（`rules/mcpb.yaml`）— 硬寫入憑證、危險執行、資料外洩、Prompt Injection
2. **混淆偵測**（`rules/obfuscation.yaml`）— base64/zlib/gzip + eval、compile 套疊
3. **p/secrets**（Semgrep 官方）— API key、Token、密碼
4. **p/typescript**（僅在偵測到 `.ts`/`.js` 檔案時執行）

### Bandit（Python 安全分析）

Python 專屬靜態安全分析工具，以 MEDIUM 以上嚴重程度、MEDIUM 以上信心度回報問題，涵蓋：

- eval/exec 危險呼叫
- 弱雜湊演算法（MD5、SHA1）
- `subprocess.call(shell=True)`
- XML 實體注入（xml.etree.ElementTree）
- 硬寫入密碼

### Cisco MCP Scanner（YARA）

使用 YARA 引擎掃描 MCP tool 描述文字、函式 docstring 及字串常數，偵測：

- Prompt Injection 模式（「忽略之前的指令」等）
- 工具投毒（Tool Poisoning）— 描述中嵌入隱藏指令
- 可疑的行為要求文字

### AI 安全審查（Maisy / Claude）

將原始碼與 manifest 傳送至 Claude 模型進行全面安全審查，重點檢查：
資料外洩、硬寫入憑證、危險執行、Prompt Injection、憑證蒐集、供應鏈風險、權限提升、過度授權。

使用隨機邊界符隔離不受信任的 MCPB 內容，防止 Prompt Injection 操控審查結果。

---

## 安全性設計

| 攻擊類型 | 防護措施 |
|---------|---------|
| **Zip Slip** | 解壓縮前逐一驗證路徑，拒絕跨目錄路徑 |
| **Zip Bomb** | 限制解壓縮上限 500 MB / 10,000 個檔案 |
| **Prompt Injection** | 使用 `secrets.token_hex(16)` 隨機邊界符隔離不可信內容 |
| **VirusTotal 檔案洩漏** | 僅查詢 SHA256，永不上傳檔案 |
| **Cisco Scanner 記憶體耗盡** | 限制工具數量上限 2,000 筆、描述上限 4,000 字元 |

---

## 目錄結構

```
mcpb-scanner/
├── scanner.py              # CLI 入口
├── modules/
│   ├── extractor.py        # MCPB 解壓縮與解析
│   ├── trivy.py            # Trivy CVE 掃描
│   ├── virustotal.py       # VirusTotal 雜湊查詢
│   ├── semgrep.py          # Semgrep 多輪靜態分析
│   ├── bandit.py           # Bandit Python 安全分析
│   ├── cisco_scanner.py    # Cisco YARA 工具描述掃描
│   └── ai_review.py        # AI 安全審查
├── rules/
│   ├── mcpb.yaml           # MCPB 自訂 Semgrep 規則
│   └── obfuscation.yaml    # 混淆程式碼偵測規則
├── requirements.txt
└── .env.example
```

---

## 授權

內部工具，請勿公開散佈。
