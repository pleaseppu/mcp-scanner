# MCPB Security Scanner

A multi-layer static security scanning CLI tool for MCP Bundle (`.mcpb`) files. Detects supply chain attacks, backdoors, malicious code, and known vulnerabilities before deployment.

---

## Features

| Layer | Module | What It Scans |
|-------|--------|---------------|
| Layer 1 | **Trivy** | Dependency CVEs (CRITICAL / HIGH / MEDIUM) |
| Layer 1 | **VirusTotal** | SHA256 hash lookup only — file content is never uploaded |
| Layer 2 | **Semgrep — MCPB rules** | Hardcoded API keys, shell injection, mass env harvesting, unsafe deserialization |
| Layer 2 | **Semgrep — obfuscation** | base64+eval, compressed-then-executed payloads, chained compile, dynamic importlib |
| Layer 2 | **Semgrep — p/secrets** | 38+ API key, token, and password patterns (Semgrep official registry) |
| Layer 2 | **Semgrep — p/typescript** | TypeScript/JavaScript MCP servers (auto-detected; only runs when .ts/.js files exist) |
| Layer 2 | **Bandit** | Python-specific security analysis: dangerous eval/exec calls, weak crypto, XML injection |
| Layer 2 | **Cisco MCP Scanner** | YARA engine scans tool descriptions and docstrings for Prompt Injection and tool poisoning |
| Layer 2 | **AI Review (Maisy)** | Claude model performs a full source code review and returns Pass / Review Needed / Reject |

---

## Requirements

- Python 3.11+ (Cisco MCP Scanner requires python3.11)
- [Trivy](https://github.com/aquasecurity/trivy) — `brew install trivy`
- [Semgrep](https://semgrep.dev) — `brew install semgrep`
- [Bandit](https://bandit.readthedocs.io) — `pip install bandit`
- Cisco MCP Scanner (optional) — see installation instructions below
- Python packages: `pip install -r requirements.txt`

---

## Installation

```bash
# 1. Clone the repository
git clone <this repo>
cd mcpb-scanner

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install external tools
brew install trivy semgrep
pip install bandit

# 4. Install Cisco MCP Scanner (optional, requires python3.11)
python3.11 -m pip install git+https://github.com/cisco-ai-defense/mcp-scanner.git

# 5. Configure environment variables
cp .env.example .env
# Edit .env and fill in your API keys
```

---

## Configuration (.env)

```dotenv
# Maisy / Claude API — required for AI review
MAISY_API_URL=https://your-internal-proxy/v1/messages
MAISY_API_KEY=your-api-key
MAISY_MODEL=claude-sonnet-4-20250514   # optional, this is the default

# VirusTotal — for hash lookup (skipped if not set)
VIRUSTOTAL_API_KEY=your-vt-api-key
```

> **Important**: The VirusTotal integration performs SHA256 hash lookups only. **File content is never uploaded**, ensuring that proprietary source code does not reach the public VirusTotal database.

---

## Usage

```bash
# Basic scan (terminal output only)
python scanner.py scan ./target.mcpb

# Save PDF report
python scanner.py scan ./target.mcpb --output report.pdf

# Save Markdown report
python scanner.py scan ./target.mcpb --output report.md

# Skip specific modules
python scanner.py scan ./target.mcpb --skip virustotal ai
python scanner.py scan ./target.mcpb --skip trivy virustotal bandit cisco ai

# Update all tools
python scanner.py update

# Update specific tools
python scanner.py update semgrep bandit
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Pass |
| `1` | Review Needed or Reject |

Suitable for direct integration into CI/CD pipelines.

---

## Risk Scoring

| Event | Category | Score |
|-------|----------|-------|
| Trivy CRITICAL CVE | Reject | +10 each |
| Trivy HIGH CVE | Review | +3 each |
| VirusTotal malicious ≥ 3 | Reject | +30 |
| VirusTotal malicious 1–2 | Review | +15 |
| Semgrep ERROR | Review | +5 each |
| Bandit HIGH | Review | +4 each |
| Cisco YARA HIGH | Reject | +8 each |
| Cisco YARA MEDIUM | Review | +5 each |
| AI verdict: Reject | Reject | +20 |
| AI verdict: Review Needed | Review | +10 |

**Reject score ≥ 10 → Reject; Review score ≥ 10 → Review Needed; otherwise → Pass**

The AI reviewer is tuned to lean toward Pass: it only returns "Review Needed" or "Reject" when a genuine risk is identified.

---

## Module Details

### Trivy (CVE Scanning)

Scans `uv.lock`, `requirements.txt`, `pyproject.toml`, and similar dependency files against the NVD and GitHub Advisory databases. Any CRITICAL-severity vulnerability triggers a Reject verdict.

### VirusTotal (Hash Lookup)

Queries the VirusTotal public API using the SHA256 hash of the `.mcpb` file. If the file is not in the database, "no record found" is reported (not an error). **File upload is strictly prohibited** to protect proprietary source code.

### Semgrep (Static Analysis, Multi-pass)

Runs four passes; results are deduplicated and merged:

1. **Custom MCPB rules** (`rules/mcpb.yaml`) — hardcoded credentials, dangerous execution, data exfiltration, Prompt Injection
2. **Obfuscation detection** (`rules/obfuscation.yaml`) — base64/zlib/gzip + eval, chained compile
3. **p/secrets** (Semgrep registry) — API keys, tokens, passwords
4. **p/typescript** (only when `.ts`/`.js` files are detected)

### Bandit (Python Security Analysis)

Python-specific static security analysis tool. Reports issues at MEDIUM severity/confidence or above, covering:

- Dangerous eval/exec calls
- Weak hash algorithms (MD5, SHA1)
- subprocess shell injection
- XML entity injection
- Hardcoded passwords

### Cisco MCP Scanner (YARA)

Uses the YARA engine to scan MCP tool description strings, function docstrings, and string constants for:

- Prompt Injection patterns ("ignore previous instructions", etc.)
- Tool Poisoning — hidden instructions embedded in descriptions
- Suspicious behavioral directives

### AI Security Review (Maisy / Claude)

Sends source code and manifest to a Claude model for a comprehensive security review, checking for: data exfiltration, hardcoded credentials, dangerous execution, Prompt Injection, credential harvesting, supply chain risks, privilege escalation, and over-authorization.

Uses a random boundary token (`secrets.token_hex(16)`) to isolate untrusted MCPB content and prevent Prompt Injection from influencing the review.

---

## Security Design

| Attack Type | Mitigation |
|-------------|------------|
| **Zip Slip** | Each member path is validated before extraction; cross-directory paths are rejected |
| **Zip Bomb** | Extraction is capped at 500 MB / 10,000 files |
| **Prompt Injection** | Random boundary token isolates untrusted MCPB content |
| **VirusTotal File Leak** | Hash lookup only — file content is never transmitted |
| **Cisco Scanner OOM** | Tool list capped at 2,000 entries; description capped at 4,000 characters |

---

## Directory Structure

```
mcpb-scanner/
├── scanner.py              # CLI entry point
├── modules/
│   ├── extractor.py        # MCPB extraction and parsing
│   ├── trivy.py            # Trivy CVE scanning
│   ├── virustotal.py       # VirusTotal hash lookup
│   ├── semgrep.py          # Semgrep multi-pass analysis
│   ├── bandit.py           # Bandit Python security analysis
│   ├── cisco_scanner.py    # Cisco YARA tool-description scanning
│   └── ai_review.py        # AI security review
├── rules/
│   ├── mcpb.yaml           # Custom MCPB Semgrep rules
│   └── obfuscation.yaml    # Obfuscation detection rules
├── requirements.txt
└── .env.example
```

---

## License

Internal tool. Do not distribute publicly.
