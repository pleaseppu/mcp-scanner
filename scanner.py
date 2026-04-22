#!/usr/bin/env python3
"""MCP Security Scanner — CLI entry point.

用法：
    python scanner.py scan ./target.mcpb
    python scanner.py scan ./remote-mcp-server.zip
    python scanner.py scan ./remote-mcp-server/
    python scanner.py scan ./target.mcpb --output report.pdf
    python scanner.py scan ./target.mcpb --skip virustotal semgrep
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path

# 確保 Homebrew 工具在 PATH 中
os.environ["PATH"] = "/opt/homebrew/bin:" + os.environ.get("PATH", "")

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

from modules.extractor import extract_mcpb, scan_directory, cleanup
from modules.trivy import run_trivy
from modules.virustotal import scan_virustotal
from modules.semgrep import run_semgrep
from modules.bandit import run_bandit
from modules.ai_review import ai_review
from modules.cisco_scanner import run_cisco_scanner

load_dotenv()
console = Console()

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "WARNING": "yellow",
    "ERROR": "red",
    "UNKNOWN": "dim",
}

RULES_PATH = Path(__file__).parent / "rules" / "mcpb.yaml"
OBFUSCATION_RULES_PATH = Path(__file__).parent / "rules" / "obfuscation.yaml"


# ─── 風險評分 ──────────────────────────────────────────────────────────────────

def compute_risk(trivy, vt, semgrep, bandit, ai, cisco) -> tuple[str, str]:
    """
    評分邏輯：
      拒絕     — 確認高風險：CRITICAL CVE、VT 惡意>=3、AI 判定拒絕
      需要審查 — 中等風險：HIGH CVE、VT 惡意>=1、Semgrep ERROR、Bandit HIGH、AI 判定需審查
      通過     — 其餘情況
    """
    reject_score = 0
    review_score = 0

    if trivy.available:
        reject_score += trivy.critical_count * 10   # 任何 CRITICAL CVE 即拒絕
        review_score += trivy.high_count * 3
        review_score += trivy.medium_count * 1

    if vt.available and vt.found:
        if vt.malicious >= 3:
            reject_score += 30                       # 多個引擎偵測到惡意 → 拒絕
        elif vt.malicious >= 1:
            review_score += 15
        if vt.suspicious >= 3:
            review_score += 8

    if semgrep.available:
        review_score += semgrep.error_count * 5
        review_score += semgrep.warning_count * 1

    if bandit.available:
        review_score += bandit.high_count * 4        # Bandit HIGH 累積觸發審查
        review_score += bandit.medium_count * 1

    if cisco.available:
        reject_score += cisco.high_count * 8         # Cisco YARA HIGH → 拒絕
        review_score += cisco.medium_count * 5

    if ai.available and ai.content:
        for line in reversed(ai.content.splitlines()):
            if line.strip().startswith("結論："):
                if "拒絕" in line:
                    reject_score += 20
                elif "需要審查" in line:
                    review_score += 10
                break

    if reject_score >= 10:
        return "拒絕", "bold red"
    elif review_score >= 10:
        return "需要審查", "yellow"
    else:
        return "通過", "bold green"


# ─── 終端輸出 ──────────────────────────────────────────────────────────────────

def print_section(title: str):
    console.print()
    console.print(Rule(f"[bold]{title}[/bold]", style="blue"))


def print_trivy(result):
    print_section("第一層 — Trivy 相依套件掃描")
    if not result.available:
        console.print(f"  [dim]略過：{result.error}[/dim]")
        return
    if result.error:
        console.print(f"  [red]錯誤：{result.error}[/red]")
        return
    if not result.vulns:
        console.print("  [green]未發現漏洞[/green]")
        return

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("嚴重程度", style="bold", width=10)
    table.add_column("套件", width=25)
    table.add_column("目前版本", width=15)
    table.add_column("修復版本", width=15)
    table.add_column("CVE ID", width=20)
    table.add_column("說明")

    for v in sorted(result.vulns, key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 99):
        color = SEVERITY_COLOR.get(v.severity, "")
        table.add_row(
            f"[{color}]{v.severity}[/{color}]",
            v.pkg_name, v.installed_version, v.fixed_version or "—",
            v.vuln_id, v.title or "—",
        )

    console.print(table)
    console.print(
        f"  共計：{len(result.vulns)} 筆 ｜ "
        f"CRITICAL：{result.critical_count} ｜ "
        f"HIGH：{result.high_count} ｜ "
        f"MEDIUM：{result.medium_count}"
    )


def print_virustotal(result):
    print_section("第一層 — VirusTotal 檔案掃描")
    if not result.available:
        console.print(f"  [dim]略過：{result.error}[/dim]")
        return
    if result.error:
        console.print(f"  [yellow]警告：{result.error}[/yellow]")
    if not result.found:
        console.print("  [dim]VirusTotal 尚無此檔案紀錄[/dim]")
        return

    mal_color = "red" if result.malicious > 0 else "green"
    sus_color = "yellow" if result.suspicious > 0 else "green"
    console.print(f"  惡意偵測 : [{mal_color}]{result.malicious}[/{mal_color}] / {result.engine_count} 個引擎")
    console.print(f"  可疑偵測 : [{sus_color}]{result.suspicious}[/{sus_color}] / {result.engine_count} 個引擎")
    console.print(f"  無害     : {result.harmless}")
    if result.link:
        console.print(f"  完整報告 : [link={result.link}]{result.link}[/link]")


def print_semgrep(result):
    print_section("第二層 — Semgrep 靜態分析")
    if not result.available:
        console.print(f"  [dim]略過：{result.error}[/dim]")
        return
    if not result.findings:
        console.print("  [green]未發現問題[/green]")
        if result.error:
            console.print(f"  [dim]警告：{result.error}[/dim]")
        return

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("嚴重程度", width=10)
    table.add_column("來源", width=12)
    table.add_column("檔案", width=32)
    table.add_column("行號", width=5)
    table.add_column("規則", width=30)
    table.add_column("說明")

    for f in sorted(result.findings, key=lambda x: 0 if x.severity == "ERROR" else 1):
        color = SEVERITY_COLOR.get(f.severity, "")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.pass_name, f.file, str(f.line), f.rule_id, f.message,
        )

    console.print(table)
    console.print(
        f"  共計：{len(result.findings)} 筆 ｜ "
        f"ERROR：{result.error_count} ｜ "
        f"WARNING：{result.warning_count}"
    )
    if result.error:
        console.print(f"  [dim]部分掃描警告：{result.error}[/dim]")


def print_bandit(result):
    print_section("第二層 — Bandit Python 安全分析")
    if not result.available:
        console.print(f"  [dim]略過：{result.error}[/dim]")
        return
    if result.error:
        console.print(f"  [red]錯誤：{result.error}[/red]")
        return
    if not result.findings:
        console.print("  [green]未發現問題[/green]")
        return

    sev_order = ["HIGH", "MEDIUM", "LOW"]
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("嚴重程度", width=10)
    table.add_column("信心", width=10)
    table.add_column("檔案", width=35)
    table.add_column("行號", width=5)
    table.add_column("規則", width=12)
    table.add_column("說明")

    for f in sorted(result.findings, key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 99):
        color = SEVERITY_COLOR.get(f.severity, "")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.confidence, f.file, str(f.line), f.test_id, f.message,
        )

    console.print(table)
    console.print(
        f"  共計：{len(result.findings)} 筆 ｜ "
        f"HIGH：{result.high_count} ｜ "
        f"MEDIUM：{result.medium_count}"
    )


def print_cisco(result):
    print_section("第二層 — Cisco MCP Scanner（YARA）")
    if not result.available:
        console.print(f"  [dim]略過：{result.error}[/dim]")
        return
    if result.error:
        console.print(f"  [red]錯誤：{result.error}[/red]")
        return
    if not result.findings:
        console.print("  [green]未發現問題[/green]")
        return

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("嚴重程度", width=10)
    table.add_column("工具 / 函式", width=30)
    table.add_column("說明")
    table.add_column("命中內容", width=40)

    for f in sorted(result.findings, key=lambda x: 0 if x.severity in ("HIGH", "CRITICAL") else 1):
        color = SEVERITY_COLOR.get(f.severity, "")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.tool_name, f.description, f.matched_text,
        )

    console.print(table)
    console.print(
        f"  共計：{len(result.findings)} 筆 ｜ "
        f"HIGH+：{result.high_count} ｜ "
        f"MEDIUM：{result.medium_count}"
    )


def print_ai(result):
    print_section("第二層 — AI 安全審查（Maisy）")
    if not result.available:
        console.print(f"  [dim]略過：{result.error}[/dim]")
        return
    if result.error:
        console.print(f"  [red]錯誤：{result.error}[/red]")
        return
    console.print(Panel(
        result.content,
        title=f"[dim]模型：{result.model} ｜ 輸入 {result.input_tokens} / 輸出 {result.output_tokens} tokens ｜ {result.duration_ms}ms[/dim]",
        border_style="blue",
    ))


def print_verdict(verdict: str, color: str, info):
    print_section("最終結論")
    console.print(f"  檔案   : {info.file_path.name}")
    console.print(f"  SHA256 : {info.sha256}")
    console.print()
    console.print(Panel(
        f"[{color}]  {verdict}  [/{color}]",
        border_style=color.replace("bold ", ""),
        expand=False,
    ))


# ─── Markdown / PDF 報告 ────────────────────────────────────────────────────────

def _md_escape(text: str) -> str:
    """Escape characters that would break a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", "")


def build_markdown_report(
    info, trivy, vt, semgrep_res, bandit_res, cisco_res, ai_res,
    verdict: str, now: str,
) -> str:
    verdict_icon = {"通過": "✅", "需要審查": "⚠️", "拒絕": "❌"}.get(verdict, "")
    is_remote = info.scan_mode == "remote"
    report_title = "MCP Server 安全掃描報告" if is_remote else "MCPB 安全掃描報告"
    target_label = "目錄" if not info._is_temp and info.extract_dir == info.file_path else "檔案"
    lines: list[str] = []

    lines += [
        f"# {report_title}",
        "",
        f"**{target_label}**：`{_md_escape(info.file_path.name)}`  ",
        f"**SHA256**：`{info.sha256}`  ",
        f"**掃描時間**：{now}  ",
        "",
        "---",
        "",
        "## 最終結論",
        "",
        f"### {verdict_icon} {verdict}",
        "",
        "---",
        "",
    ]

    # ── Trivy ──────────────────────────────────────────────────────────────────
    lines += ["## 第一層 — Trivy 相依套件漏洞掃描", ""]
    if not trivy.available:
        lines.append(f"> 略過：{_md_escape(trivy.error or '')}")
    elif trivy.error:
        lines.append(f"> 錯誤：{_md_escape(trivy.error)}")
    elif not trivy.vulns:
        lines.append("> 未發現漏洞")
    else:
        lines += [
            "| 嚴重程度 | 套件 | 目前版本 | 修復版本 | CVE | 說明 |",
            "|---------|------|---------|---------|-----|------|",
        ]
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        for v in sorted(trivy.vulns, key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 99):
            lines.append(
                f"| {_md_escape(v.severity)} | {_md_escape(v.pkg_name)} | "
                f"{_md_escape(v.installed_version)} | {_md_escape(v.fixed_version or '—')} | "
                f"{_md_escape(v.vuln_id)} | {_md_escape(v.title or '—')} |"
            )
        lines += [
            "",
            f"**共計**：{len(trivy.vulns)} 筆 ｜ CRITICAL：{trivy.critical_count} ｜ "
            f"HIGH：{trivy.high_count} ｜ MEDIUM：{trivy.medium_count}",
        ]
    lines += ["", "---", ""]

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    lines += ["## 第一層 — VirusTotal 檔案掃描", ""]
    if not vt.available:
        lines.append(f"> 略過：{_md_escape(vt.error or '')}")
    elif not vt.found:
        lines.append("> VirusTotal 尚無此檔案紀錄")
        if vt.error:
            lines.append(f"> 警告：{_md_escape(vt.error)}")
    else:
        mal_badge = f"**{vt.malicious}**（⚠️）" if vt.malicious > 0 else str(vt.malicious)
        sus_badge = f"**{vt.suspicious}**（⚠️）" if vt.suspicious > 0 else str(vt.suspicious)
        lines += [
            f"- **惡意偵測**：{mal_badge} / {vt.engine_count} 個引擎",
            f"- **可疑偵測**：{sus_badge} / {vt.engine_count} 個引擎",
            f"- **無害**：{vt.harmless}",
        ]
        if vt.link:
            lines.append(f"- **完整報告**：{vt.link}")
    lines += ["", "---", ""]

    # ── Semgrep ────────────────────────────────────────────────────────────────
    lines += ["## 第二層 — Semgrep 靜態分析", ""]
    if not semgrep_res.available:
        lines.append(f"> 略過：{_md_escape(semgrep_res.error or '')}")
    elif not semgrep_res.findings:
        lines.append("> 未發現問題")
        if semgrep_res.error:
            lines.append(f"> 警告：{_md_escape(semgrep_res.error)}")
    else:
        lines += [
            "| 嚴重程度 | 來源 | 檔案 | 行號 | 規則 | 說明 |",
            "|---------|------|------|-----|------|------|",
        ]
        for f in sorted(semgrep_res.findings, key=lambda x: 0 if x.severity == "ERROR" else 1):
            lines.append(
                f"| {_md_escape(f.severity)} | {_md_escape(f.pass_name)} | "
                f"{_md_escape(f.file)} | {f.line} | "
                f"`{_md_escape(f.rule_id)}` | {_md_escape(f.message)} |"
            )
        lines += [
            "",
            f"**共計**：{len(semgrep_res.findings)} 筆 ｜ ERROR：{semgrep_res.error_count} ｜ WARNING：{semgrep_res.warning_count}",
        ]
        if semgrep_res.error:
            lines.append(f"\n> 部分掃描警告：{_md_escape(semgrep_res.error)}")
    lines += ["", "---", ""]

    # ── Bandit ─────────────────────────────────────────────────────────────────
    lines += ["## 第二層 — Bandit Python 安全分析", ""]
    if not bandit_res.available:
        lines.append(f"> 略過：{_md_escape(bandit_res.error or '')}")
    elif bandit_res.error:
        lines.append(f"> 錯誤：{_md_escape(bandit_res.error)}")
    elif not bandit_res.findings:
        lines.append("> 未發現問題")
    else:
        lines += [
            "| 嚴重程度 | 信心 | 檔案 | 行號 | 規則 | 說明 |",
            "|---------|-----|------|-----|------|------|",
        ]
        sev_order = ["HIGH", "MEDIUM", "LOW"]
        for f in sorted(bandit_res.findings, key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 99):
            lines.append(
                f"| {_md_escape(f.severity)} | {_md_escape(f.confidence)} | "
                f"{_md_escape(f.file)} | {f.line} | "
                f"`{_md_escape(f.test_id)}` | {_md_escape(f.message)} |"
            )
        lines += [
            "",
            f"**共計**：{len(bandit_res.findings)} 筆 ｜ HIGH：{bandit_res.high_count} ｜ MEDIUM：{bandit_res.medium_count}",
        ]
    lines += ["", "---", ""]

    # ── Cisco ──────────────────────────────────────────────────────────────────
    lines += ["## 第二層 — Cisco MCP Scanner（YARA）", ""]
    if not cisco_res.available:
        lines.append(f"> 略過：{_md_escape(cisco_res.error or '')}")
    elif cisco_res.error:
        lines.append(f"> 錯誤：{_md_escape(cisco_res.error)}")
    elif not cisco_res.findings:
        lines.append("> 未發現問題")
    else:
        lines += [
            "| 嚴重程度 | 工具 / 函式 | 說明 | 命中內容 |",
            "|---------|-----------|------|---------|",
        ]
        for f in sorted(cisco_res.findings, key=lambda x: 0 if x.severity in ("HIGH", "CRITICAL") else 1):
            lines.append(
                f"| {_md_escape(f.severity)} | {_md_escape(f.tool_name)} | "
                f"{_md_escape(f.description)} | `{_md_escape(f.matched_text[:80])}` |"
            )
        lines += [
            "",
            f"**共計**：{len(cisco_res.findings)} 筆 ｜ HIGH+：{cisco_res.high_count} ｜ MEDIUM：{cisco_res.medium_count}",
        ]
    lines += ["", "---", ""]

    # ── AI Review ──────────────────────────────────────────────────────────────
    lines += ["## 第二層 — AI 安全審查（Maisy）", ""]
    if not ai_res.available:
        lines.append(f"> 略過：{_md_escape(ai_res.error or '')}")
    elif ai_res.error:
        lines.append(f"> 錯誤：{_md_escape(ai_res.error)}")
    else:
        lines += [
            ai_res.content,
            "",
            f"*模型：{ai_res.model} ｜ 輸入 {ai_res.input_tokens} / 輸出 {ai_res.output_tokens} tokens ｜ {ai_res.duration_ms}ms*",
        ]
    lines.append("")

    return "\n".join(lines)


def save_report(md_content: str, output_path: str) -> None:
    """Save report as Markdown (.md) or PDF (.pdf)."""
    path = Path(output_path)

    if path.suffix.lower() == ".pdf":
        import markdown as md_lib
        import weasyprint

        html_body = md_lib.markdown(
            md_content,
            extensions=["tables", "fenced_code"],
        )
        html_full = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<style>
  @page {{ margin: 2cm; }}
  body {{
    font-family: -apple-system, "Helvetica Neue", "PingFang TC", Arial, sans-serif;
    max-width: 900px; margin: 0 auto; padding: 1rem; color: #1a1a1a; font-size: 14px;
  }}
  h1 {{ border-bottom: 2px solid #334155; padding-bottom: .5rem; font-size: 1.6rem; }}
  h2 {{ color: #1e3a5f; border-bottom: 1px solid #e2e8f0; padding-bottom: .3rem; margin-top: 2rem; font-size: 1.1rem; }}
  h3 {{ color: #374151; font-size: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .8rem; margin: 1rem 0; }}
  th {{ background: #f1f5f9; text-align: left; padding: .4rem .6rem; border: 1px solid #cbd5e1; }}
  td {{ padding: .35rem .6rem; border: 1px solid #e2e8f0; word-break: break-word; }}
  tr:nth-child(even) td {{ background: #f8fafc; }}
  code {{ background: #f1f5f9; padding: .1rem .3rem; border-radius: .2rem; font-size: .8em; font-family: "SFMono-Regular", Menlo, monospace; }}
  pre {{ background: #f1f5f9; padding: .75rem; border-radius: .3rem; overflow-x: auto; font-size: .8em; }}
  blockquote {{ border-left: 3px solid #94a3b8; margin: .5rem 0; padding: .4rem 1rem; color: #475569; background: #f8fafc; }}
  hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 1.5rem 0; }}
  em {{ color: #64748b; font-size: .85em; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""
        weasyprint.HTML(string=html_full).write_pdf(str(path))
    else:
        path.write_text(md_content, encoding="utf-8")


# ─── 主掃描流程 ────────────────────────────────────────────────────────────────

def cmd_scan(args):
    target_path = args.file
    skip = set(args.skip)
    output = args.output
    is_directory = Path(target_path).is_dir()

    title = "MCP 安全掃描工具" if is_directory else "MCPB 安全掃描工具"
    console.print()
    console.print(Panel(
        f"[bold]{title}[/bold]\n[dim]{target_path}[/dim]",
        border_style="blue",
    ))

    if is_directory:
        console.print("\n[bold]讀取原始碼目錄...[/bold]", end=" ")
        try:
            info = scan_directory(target_path)
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]失敗[/red]\n{e}")
            sys.exit(1)
    else:
        console.print("\n[bold]解壓縮檔案...[/bold]", end=" ")
        try:
            info = extract_mcpb(target_path)
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]失敗[/red]\n{e}")
            sys.exit(1)
    console.print("[green]完成[/green]")

    # Remote 模式下自動略過 VirusTotal（無單檔可查）
    if info.scan_mode == "remote" and "virustotal" not in skip:
        skip.add("virustotal")

    m = info.manifest
    console.print(f"  名稱     : {m.get('display_name', m.get('name', '?'))}")
    console.print(f"  版本     : {m.get('version', '?')}")
    console.print(f"  作者     : {m.get('author', {}).get('name', '?')}")
    console.print(f"  SHA256   : {info.sha256}")
    py_count = sum(1 for f in info.source_files if f.suffix == ".py")
    js_count = len(info.source_files) - py_count
    src_summary = f"{py_count} 個 .py ｜ {js_count} 個 .js/.ts" if js_count else f"{py_count} 個 .py"
    console.print(f"  原始碼   : {src_summary}")

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    maisy_url = os.getenv("MAISY_API_URL", "")
    maisy_key = os.getenv("MAISY_API_KEY", "")
    maisy_model = os.getenv("MAISY_MODEL", "claude-sonnet-4-20250514")

    # ── Trivy ──────────────────────────────────────────────────────────────────
    if "trivy" not in skip:
        console.print("\n[bold]執行 Trivy...[/bold]", end=" ")
        _t0 = time.perf_counter()
        trivy_res = run_trivy(info.extract_dir)
        trivy_ms = int((time.perf_counter() - _t0) * 1000)
        status = "[green]完成[/green]" if trivy_res.available and not trivy_res.error else f"[yellow]{trivy_res.error or '無法使用'}[/yellow]"
        console.print(status)
    else:
        trivy_ms = -1
        from modules.trivy import TrivyResult
        trivy_res = TrivyResult(available=False, error="已略過", vulns=[])

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    if "virustotal" not in skip:
        console.print("[bold]執行 VirusTotal...[/bold]", end=" ")
        _t0 = time.perf_counter()
        vt_res = scan_virustotal(info.file_path, info.sha256, vt_key)
        vt_ms = int((time.perf_counter() - _t0) * 1000)
        status = "[green]完成[/green]" if vt_res.available else f"[yellow]{vt_res.error}[/yellow]"
        console.print(status)
    else:
        vt_ms = -1
        from modules.virustotal import VTResult
        vt_res = VTResult(available=False, error="已略過", sha256=info.sha256, found=False)

    # ── Semgrep (multi-pass) ───────────────────────────────────────────────────
    if "semgrep" not in skip:
        console.print("[bold]執行 Semgrep（多輪掃描）...[/bold]", end=" ")
        _t0 = time.perf_counter()
        semgrep_res = run_semgrep(info.extract_dir, RULES_PATH, OBFUSCATION_RULES_PATH)
        semgrep_ms = int((time.perf_counter() - _t0) * 1000)
        status = "[green]完成[/green]" if semgrep_res.available else f"[yellow]{semgrep_res.error or '無法使用'}[/yellow]"
        console.print(status)
    else:
        semgrep_ms = -1
        from modules.semgrep import SemgrepResult
        semgrep_res = SemgrepResult(available=False, error="已略過", findings=[])

    # ── Bandit ─────────────────────────────────────────────────────────────────
    if "bandit" not in skip:
        console.print("[bold]執行 Bandit...[/bold]", end=" ")
        _t0 = time.perf_counter()
        bandit_res = run_bandit(info.extract_dir)
        bandit_ms = int((time.perf_counter() - _t0) * 1000)
        status = "[green]完成[/green]" if bandit_res.available and not bandit_res.error else f"[yellow]{bandit_res.error or '無法使用'}[/yellow]"
        console.print(status)
    else:
        bandit_ms = -1
        from modules.bandit import BanditResult
        bandit_res = BanditResult(available=False, error="已略過", findings=[])

    # ── Cisco MCP Scanner ──────────────────────────────────────────────────────
    if "cisco" not in skip:
        console.print("[bold]執行 Cisco MCP Scanner...[/bold]", end=" ")
        _t0 = time.perf_counter()
        cisco_res = run_cisco_scanner(info.extract_dir, info.manifest)
        cisco_ms = int((time.perf_counter() - _t0) * 1000)
        status = "[green]完成[/green]" if cisco_res.available and not cisco_res.error else f"[yellow]{cisco_res.error or '無法使用'}[/yellow]"
        console.print(status)
    else:
        cisco_ms = -1
        from modules.cisco_scanner import CiscoResult
        cisco_res = CiscoResult(available=False, error="已略過")

    # ── AI 審查 ────────────────────────────────────────────────────────────────
    if "ai" not in skip:
        console.print("[bold]執行 AI 審查...[/bold]", end=" ")
        _t0 = time.perf_counter()
        ai_res = ai_review(info.manifest, info.source_files, info.extract_dir, maisy_url, maisy_key, maisy_model)
        ai_ms = int((time.perf_counter() - _t0) * 1000)
        status = "[green]完成[/green]" if ai_res.available and not ai_res.error else f"[yellow]{ai_res.error or '無法使用'}[/yellow]"
        console.print(status)
    else:
        ai_ms = -1
        from modules.ai_review import AIReviewResult
        ai_res = AIReviewResult(available=False, error="已略過", content="", model=maisy_model, input_tokens=0, output_tokens=0, duration_ms=0)

    # ── 輸出結果 ───────────────────────────────────────────────────────────────
    print_trivy(trivy_res)
    print_virustotal(vt_res)
    print_semgrep(semgrep_res)
    print_bandit(bandit_res)
    print_cisco(cisco_res)
    print_ai(ai_res)

    verdict, vcolor = compute_risk(trivy_res, vt_res, semgrep_res, bandit_res, ai_res, cisco_res)
    print_verdict(verdict, vcolor, info)

    # ── 掃描耗時統計 ────────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[dim]掃描耗時[/dim]", style="dim"))
    timing_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    timing_table.add_column(style="dim", width=20)
    timing_table.add_column(style="dim", justify="right")
    for _label, _ms in [
        ("Trivy", trivy_ms), ("VirusTotal", vt_ms), ("Semgrep", semgrep_ms),
        ("Bandit", bandit_ms), ("Cisco", cisco_ms), ("AI Review", ai_ms),
    ]:
        timing_table.add_row(_label, f"{_ms:,} ms" if _ms >= 0 else "略過")
    console.print(timing_table)

    if output:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md = build_markdown_report(
            info, trivy_res, vt_res, semgrep_res, bandit_res, cisco_res, ai_res,
            verdict, now,
        )
        try:
            save_report(md, output)
            console.print(f"\n  報告已儲存：[bold]{output}[/bold]")
        except Exception as e:
            console.print(f"\n  [red]報告儲存失敗：{e}[/red]")

    cleanup(info)
    console.print()

    sys.exit(0 if verdict == "通過" else 1)


# ─── 更新子命令 ────────────────────────────────────────────────────────────────

def cmd_update(args):
    import subprocess as sp

    targets = set(args.tools) if args.tools else {"trivy", "semgrep", "cisco", "bandit"}

    def run(label: str, cmd: list[str]):
        console.print(f"\n[bold]更新 {label}...[/bold]")
        result = sp.run(cmd, text=True)
        if result.returncode == 0:
            console.print(f"  [green]{label} 更新完成[/green]")
        else:
            console.print(f"  [red]{label} 更新失敗（exit {result.returncode}）[/red]")

    console.print()
    console.print(Panel("[bold]MCPB 工具更新[/bold]", border_style="blue"))

    if "trivy" in targets:
        run("Trivy", ["brew", "upgrade", "trivy"])

    if "semgrep" in targets:
        run("Semgrep", ["brew", "upgrade", "semgrep"])

    if "bandit" in targets:
        run("Bandit", [sys.executable, "-m", "pip", "install", "--upgrade", "bandit"])

    if "cisco" in targets:
        run(
            "Cisco MCP Scanner",
            [
                "python3.11", "-m", "pip", "install", "--upgrade",
                "git+https://github.com/cisco-ai-defense/mcp-scanner.git",
            ],
        )

    console.print()


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="MCPB 安全掃描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            範例：
              python scanner.py scan ./target.mcpb
              python scanner.py scan ./remote-server.zip
              python scanner.py scan ./remote-mcp-server/
              python scanner.py scan ./target.mcpb --output report.pdf
              python scanner.py scan ./target.mcpb --skip virustotal
              python scanner.py scan ./target.mcpb --skip ai trivy bandit
        """),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="掃描 MCPB / ZIP 檔案或原始碼目錄")
    scan_p.add_argument("file", help=".mcpb / .zip 檔案路徑，或原始碼目錄路徑")
    scan_p.add_argument(
        "--output", "-o", metavar="FILE",
        help="將報告儲存至指定路徑（.md 或 .pdf）",
    )
    scan_p.add_argument(
        "--skip", nargs="+",
        choices=["trivy", "virustotal", "semgrep", "bandit", "cisco", "ai"],
        default=[],
        metavar="MODULE",
        help="略過指定模組：trivy virustotal semgrep bandit cisco ai",
    )

    update_p = subparsers.add_parser("update", help="更新所有掃描工具")
    update_p.add_argument(
        "tools", nargs="*",
        choices=["trivy", "semgrep", "bandit", "cisco"],
        metavar="TOOL",
        help="指定要更新的工具（不填則全部更新）：trivy semgrep bandit cisco",
    )

    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "update":
        cmd_update(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
