"""Run Semgrep with multiple passes: custom MCPB rules, obfuscation rules,
p/secrets (registry), and p/typescript (for JS/TS files)."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SemgrepFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    code: str
    pass_name: str = ""


@dataclass
class SemgrepResult:
    available: bool
    error: str | None
    findings: list[SemgrepFinding]

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "ERROR")

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "WARNING")


def _safe_relative(path_str: str, base: Path) -> str:
    try:
        return str(Path(path_str).relative_to(base))
    except ValueError:
        return Path(path_str).name


def _run_one_pass(
    cmd: list[str], extract_dir: Path, pass_name: str
) -> tuple[list[SemgrepFinding], str | None]:
    """Run one semgrep invocation, return (findings, optional_error_msg)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return [], f"{pass_name} 逾時"

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        if proc.returncode not in (0, 1):
            return [], f"{pass_name} 執行失敗（exit {proc.returncode}）: {proc.stderr[:200]}"
        return [], None  # empty output with exit 0/1 → no findings, no error

    findings: list[SemgrepFinding] = []
    for r in data.get("results", []):
        meta = r.get("extra", {})
        findings.append(SemgrepFinding(
            rule_id=r.get("check_id", ""),
            severity=meta.get("severity", "WARNING").upper(),
            message=meta.get("message", ""),
            file=_safe_relative(r.get("path", ""), extract_dir),
            line=r.get("start", {}).get("line", 0),
            code=(meta.get("lines") or "").strip()[:200],
            pass_name=pass_name,
        ))

    return findings, None


def run_semgrep(
    extract_dir: Path,
    rules_path: Path,
    obfuscation_rules_path: Path | None = None,
) -> SemgrepResult:
    """
    Run four Semgrep passes and merge findings:
      1. Custom MCPB rules (rules_path)
      2. Obfuscation / packed-payload rules (obfuscation_rules_path)
      3. p/secrets — Semgrep registry secret detection (38+ patterns)
      4. p/typescript — only when .ts / .js files exist in extract_dir
    """
    if not shutil.which("semgrep"):
        return SemgrepResult(available=False, error="semgrep not found in PATH", findings=[])

    all_findings: list[SemgrepFinding] = []
    errors: list[str] = []

    # ── Pass 1: custom MCPB rules ────────────────────────────────────────────
    if rules_path.exists():
        cmd = ["semgrep", "--config", str(rules_path), "--json", "--quiet", str(extract_dir)]
        findings, err = _run_one_pass(cmd, extract_dir, "mcpb-rules")
        all_findings.extend(findings)
        if err:
            errors.append(err)
    else:
        errors.append(f"規則檔不存在：{rules_path}")

    # ── Pass 2: obfuscation rules ────────────────────────────────────────────
    if obfuscation_rules_path and obfuscation_rules_path.exists():
        cmd = ["semgrep", "--config", str(obfuscation_rules_path), "--json", "--quiet", str(extract_dir)]
        findings, err = _run_one_pass(cmd, extract_dir, "obfuscation")
        all_findings.extend(findings)
        if err:
            errors.append(err)

    # ── Pass 3: p/secrets (requires network, may be slow) ───────────────────
    cmd = ["semgrep", "--config", "p/secrets", "--json", "--quiet", str(extract_dir)]
    findings, err = _run_one_pass(cmd, extract_dir, "p/secrets")
    all_findings.extend(findings)
    if err:
        errors.append(f"p/secrets: {err}")

    # ── Pass 4: p/typescript — only when JS/TS files exist ──────────────────
    has_ts = (
        next(extract_dir.rglob("*.ts"), None) is not None
        or next(extract_dir.rglob("*.js"), None) is not None
    )
    if has_ts:
        cmd = ["semgrep", "--config", "p/typescript", "--json", "--quiet", str(extract_dir)]
        findings, err = _run_one_pass(cmd, extract_dir, "p/typescript")
        all_findings.extend(findings)
        if err:
            errors.append(f"p/typescript: {err}")

    # ── Deduplicate by (file, line, rule_id) ────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[SemgrepFinding] = []
    for f in all_findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    error_msg = "; ".join(errors) if errors else None
    return SemgrepResult(available=True, error=error_msg, findings=deduped)
