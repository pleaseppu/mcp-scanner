"""Run Bandit Python security linter on extracted MCPB directory."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_PYTHON = shutil.which("python3") or sys.executable


@dataclass
class BanditFinding:
    test_id: str
    test_name: str
    severity: str    # HIGH / MEDIUM / LOW
    confidence: str
    file: str
    line: int
    message: str
    code: str


@dataclass
class BanditResult:
    available: bool
    error: str | None
    findings: list[BanditFinding]

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")


def run_bandit(extract_dir: Path) -> BanditResult:
    # 確認 bandit 可用
    bandit_bin = shutil.which("bandit")
    if bandit_bin:
        cmd_prefix = [bandit_bin]
    else:
        check = subprocess.run(
            [_PYTHON, "-m", "bandit", "--version"],
            capture_output=True, timeout=10,
        )
        if check.returncode != 0:
            return BanditResult(available=False, error="bandit 未安裝（pip install bandit）", findings=[])
        cmd_prefix = [_PYTHON, "-m", "bandit"]

    # 只掃 Python 檔案；-r 遞迴；-f json；-q 靜音
    cmd = cmd_prefix + [
        "-r", str(extract_dir),
        "-f", "json",
        "-q",
        "--severity-level", "medium",   # 只回報 MEDIUM 以上
        "--confidence-level", "medium",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return BanditResult(available=True, error="bandit 逾時", findings=[])

    # bandit exit code: 0 = 無問題, 1 = 找到問題, 2 = 錯誤
    if proc.returncode == 2:
        return BanditResult(available=True, error=proc.stderr[:300], findings=[])

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return BanditResult(available=True, error="無法解析 bandit 輸出", findings=[])

    findings: list[BanditFinding] = []
    for r in data.get("results", []):
        file_rel = _safe_relative(r.get("filename", ""), extract_dir)
        findings.append(BanditFinding(
            test_id=r.get("test_id", ""),
            test_name=r.get("test_name", ""),
            severity=r.get("issue_severity", "LOW").upper(),
            confidence=r.get("issue_confidence", "").upper(),
            file=file_rel,
            line=r.get("line_number", 0),
            message=r.get("issue_text", ""),
            code=(r.get("code") or "").strip()[:200],
        ))

    return BanditResult(available=True, error=None, findings=findings)


def _safe_relative(path_str: str, base: Path) -> str:
    try:
        return str(Path(path_str).relative_to(base))
    except ValueError:
        return Path(path_str).name
