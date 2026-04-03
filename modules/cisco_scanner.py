"""Cisco MCP Scanner integration — YARA-based tool description analysis.

Uses cisco-ai-defense/mcp-scanner's YARA engine to scan tool descriptions,
docstrings, and manifest content for prompt injection / tool poisoning patterns.

Requires: pip install git+https://github.com/cisco-ai-defense/mcp-scanner.git
Must be run with python3.11 (not 3.14) due to litellm compatibility.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


# Regex patterns for JS/TS tool description extraction
# Pattern 1: .tool("name", "description", ...) — MCP SDK style
_RE_TOOL_CALL = re.compile(
    r'\.tool\s*\(\s*(?P<q1>["\'])(?P<name>[^"\']{1,100})(?P=q1)'
    r'\s*,\s*(?P<q2>["\'])(?P<desc>[^"\']{20,4000})(?P=q2)',
)
# Pattern 2: description: "..." — object literal style
_RE_DESC_FIELD = re.compile(
    r'\bdescription\s*:\s*(?P<q>["\'])(?P<desc>[^"\']{20,4000})(?P=q)',
)


# python3.11 是 cisco mcp-scanner 的相容版本
_PYTHON = shutil.which("python3.11") or sys.executable


@dataclass
class CiscoFinding:
    tool_name: str
    severity: str
    analyzer: str
    description: str
    matched_text: str


@dataclass
class CiscoResult:
    available: bool
    error: str | None
    findings: list[CiscoFinding] = field(default_factory=list)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() in ("high", "critical"))

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "medium")


def _extract_tool_descriptions(extract_dir: Path, manifest: dict) -> list[dict]:
    """
    從原始碼和 manifest 中提取所有可能作為 MCP tool description 的文字，
    組成 YARA 掃描用的 tools.json 格式。
    """
    tools: list[dict] = []

    # 1. manifest 本身的描述欄位
    tools.append({
        "name": manifest.get("name", "manifest"),
        "description": (
            f"{manifest.get('description', '')} "
            f"{manifest.get('display_name', '')}"
        ).strip(),
        "inputSchema": {"type": "object", "properties": {}},
    })

    # 2. 掃描所有 Python 檔案的 docstring 和長字串常數（加上數量上限防止記憶體爆炸）
    _MAX_TOOLS = 2000
    _MAX_DESC_CHARS = 4000

    for py_file in sorted(extract_dir.rglob("*.py")):
        if len(tools) >= _MAX_TOOLS:
            break
        try:
            source = py_file.read_text(errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if len(tools) >= _MAX_TOOLS:
                break

            # 函式/方法 docstring
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                doc = ast.get_docstring(node)
                if doc and len(doc) > 20:
                    tools.append({
                        "name": f"{py_file.stem}.{node.name}",
                        "description": doc[:_MAX_DESC_CHARS],
                        "inputSchema": {"type": "object", "properties": {}},
                    })

            # 長字串常數（可能是 prompt template 或 tool description）
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if len(val) > 50:
                            tools.append({
                                "name": f"{py_file.stem}.{target.id}",
                                "description": val[:_MAX_DESC_CHARS],
                                "inputSchema": {"type": "object", "properties": {}},
                            })

    return tools


def _extract_tool_descriptions_js(extract_dir: Path) -> list[dict]:
    """Regex-based tool description extraction from JS/TS source files."""
    tools: list[dict] = []
    _MAX_TOOLS = 2000
    _MAX_DESC_CHARS = 4000
    _SKIP_DIRS = frozenset({"node_modules", "dist", "build", ".next", "__pycache__"})
    seen_descs: set[str] = set()

    for pattern in ("*.js", "*.ts", "*.mjs", "*.cjs", "*.jsx", "*.tsx"):
        for js_file in sorted(extract_dir.rglob(pattern)):
            if len(tools) >= _MAX_TOOLS:
                return tools
            if any(part in _SKIP_DIRS for part in js_file.relative_to(extract_dir).parts):
                continue
            try:
                source = js_file.read_text(errors="replace")
            except OSError:
                continue

            stem = js_file.stem

            # .tool("name", "description") — MCP SDK pattern
            for m in _RE_TOOL_CALL.finditer(source):
                if len(tools) >= _MAX_TOOLS:
                    return tools
                desc = m.group("desc")
                if desc not in seen_descs:
                    seen_descs.add(desc)
                    tools.append({
                        "name": f"{stem}.{m.group('name')}",
                        "description": desc[:_MAX_DESC_CHARS],
                        "inputSchema": {"type": "object", "properties": {}},
                    })

            # description: "..." — object literal pattern
            for m in _RE_DESC_FIELD.finditer(source):
                if len(tools) >= _MAX_TOOLS:
                    return tools
                desc = m.group("desc")
                if desc not in seen_descs:
                    seen_descs.add(desc)
                    tools.append({
                        "name": f"{stem}.description",
                        "description": desc[:_MAX_DESC_CHARS],
                        "inputSchema": {"type": "object", "properties": {}},
                    })

    return tools


def run_cisco_scanner(extract_dir: Path, manifest: dict) -> CiscoResult:
    # 確認 cisco mcp-scanner 是否可用
    try:
        check = subprocess.run(
            [_PYTHON, "-c", "import mcpscanner"],
            capture_output=True, timeout=10,
        )
        if check.returncode != 0:
            return CiscoResult(available=False, error="cisco mcp-scanner 未安裝（請用 python3.11 安裝）")
    except Exception as e:
        return CiscoResult(available=False, error=f"無法確認 cisco mcp-scanner：{e}")

    # 建立暫時的 tools.json（Python AST + JS/TS regex 兩路提取）
    tools = _extract_tool_descriptions(extract_dir, manifest)
    tools.extend(_extract_tool_descriptions_js(extract_dir))
    if not tools:
        return CiscoResult(available=True, error=None, findings=[])

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump({"tools": tools}, tmp, ensure_ascii=False)
        tools_json_path = tmp.name

    try:
        cmd = [
            _PYTHON, "-m", "mcpscanner.cli",
            "--analyzers", "yara",
            "--format", "raw",
            "static",
            "--tools", tools_json_path,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        Path(tools_json_path).unlink(missing_ok=True)
        return CiscoResult(available=True, error="Cisco scanner 逾時")
    finally:
        Path(tools_json_path).unlink(missing_ok=True)

    # Cisco scanner 有找到問題時 exit code 為 1，這是正常的
    raw_output = proc.stdout.strip()
    if not raw_output:
        if proc.returncode not in (0, 1):
            return CiscoResult(available=True, error=f"執行失敗（exit {proc.returncode}）：{proc.stderr[:300]}")
        return CiscoResult(available=True, error=None, findings=[])

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return CiscoResult(available=True, error=f"無法解析輸出：{raw_output[:200]}")

    findings: list[CiscoFinding] = []
    for item in data if isinstance(data, list) else [data]:
        tool_name = item.get("tool_name") or item.get("name", "unknown")
        for result in item.get("results", []):
            if result.get("is_safe"):
                continue
            for finding in result.get("findings", []):
                findings.append(CiscoFinding(
                    tool_name=tool_name,
                    severity=finding.get("severity", "UNKNOWN").upper(),
                    analyzer=finding.get("analyzer", "yara_analyzer"),
                    description=finding.get("description", ""),
                    matched_text=(finding.get("evidence") or finding.get("matched_text") or "")[:300],
                ))

    return CiscoResult(available=True, error=None, findings=findings)
