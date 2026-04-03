"""Run Trivy filesystem scan on extracted MCPB directory."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TrivyVuln:
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    vuln_id: str
    title: str
    description: str


@dataclass
class TrivyResult:
    available: bool
    error: str | None
    vulns: list[TrivyVuln]

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulns if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulns if v.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulns if v.severity == "MEDIUM")


def run_trivy(extract_dir: Path) -> TrivyResult:
    if not shutil.which("trivy"):
        return TrivyResult(available=False, error="trivy not found in PATH", vulns=[])

    cmd = [
        "trivy", "fs",
        "--format", "json",
        "--scanners", "vuln",
        "--quiet",
        str(extract_dir),
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return TrivyResult(available=True, error="trivy timed out", vulns=[])

    if proc.returncode not in (0, 1):  # trivy exits 1 when vulns found
        return TrivyResult(available=True, error=proc.stderr[:500], vulns=[])

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return TrivyResult(available=True, error="failed to parse trivy output", vulns=[])

    vulns: list[TrivyVuln] = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            vulns.append(TrivyVuln(
                pkg_name=v.get("PkgName", ""),
                installed_version=v.get("InstalledVersion", ""),
                fixed_version=v.get("FixedVersion", ""),
                severity=v.get("Severity", "UNKNOWN"),
                vuln_id=v.get("VulnerabilityID", ""),
                title=v.get("Title", ""),
                description=(v.get("Description") or "")[:300],
            ))

    return TrivyResult(available=True, error=None, vulns=vulns)
