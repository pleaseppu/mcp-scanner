"""Query VirusTotal by file hash only — file content is NEVER uploaded.

Safety policy: VirusTotal is a public platform. Uploaded files are visible
to all premium subscribers. MCPB files may contain proprietary source code
and must not be sent to any external service.

This module performs hash-only lookups: if the hash is not already in the
VirusTotal database the result is reported as "not found" and nothing is sent.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

VT_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 30.0


@dataclass
class VTResult:
    available: bool
    error: str | None
    sha256: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    engine_count: int = 0
    link: str = ""


def _headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _parse_attributes(attrs: dict, sha256: str) -> VTResult:
    stats = attrs.get("last_analysis_stats", {})
    return VTResult(
        available=True,
        error=None,
        sha256=sha256,
        found=True,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        engine_count=sum(stats.values()),
        link=f"https://www.virustotal.com/gui/file/{sha256}",
    )


def scan_virustotal(file_path: Path, sha256: str, api_key: str) -> VTResult:
    """Hash-only lookup against VirusTotal. File content is never transmitted."""
    if not api_key:
        return VTResult(available=False, error="VIRUSTOTAL_API_KEY 未設定", sha256=sha256, found=False)

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.get(f"{VT_BASE}/files/{sha256}", headers=_headers(api_key))

        if resp.status_code == 200:
            return _parse_attributes(resp.json()["data"]["attributes"], sha256)

        if resp.status_code == 404:
            # Hash not in VT database — do NOT upload, just report as not found
            return VTResult(
                available=True,
                error=None,
                sha256=sha256,
                found=False,
            )

        return VTResult(
            available=True,
            error=f"VT API 回傳錯誤 {resp.status_code}",
            sha256=sha256,
            found=False,
        )

    except httpx.RequestError as e:
        return VTResult(available=False, error=str(e)[:200], sha256=sha256, found=False)
