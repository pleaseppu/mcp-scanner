"""Extract and inspect MCPB files (zip-based)."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# 解壓安全限制
_MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024   # 500 MB
_MAX_FILE_COUNT = 10_000


@dataclass
class McpbInfo:
    file_path: Path
    sha256: str
    extract_dir: Path
    manifest: dict
    source_files: list[Path] = field(default_factory=list)
    dependency_files: list[Path] = field(default_factory=list)


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_mcpb(mcpb_path: str) -> McpbInfo:
    """Extract MCPB zip to a temp directory and parse its contents."""
    path = Path(mcpb_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not zipfile.is_zipfile(path):
        raise ValueError(f"Not a valid zip file: {path}")

    sha256 = compute_sha256(path)
    extract_dir = Path(tempfile.mkdtemp(prefix="mcpb_scan_"))

    with zipfile.ZipFile(path) as zf:
        members = zf.infolist()

        # ── Zip Bomb 防護：檔案數量與解壓大小上限 ──
        if len(members) > _MAX_FILE_COUNT:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise ValueError(f"MCPB 包含過多檔案（{len(members)} 筆，上限 {_MAX_FILE_COUNT}）")

        total_size = sum(m.file_size for m in members)
        if total_size > _MAX_UNCOMPRESSED_BYTES:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise ValueError(
                f"解壓後大小超過上限（{total_size // 1024 // 1024} MB，上限 500 MB）"
            )

        # ── Zip Slip 防護：逐一驗證解壓路徑 ──
        extract_dir_resolved = extract_dir.resolve()
        for member in members:
            member_dest = (extract_dir / member.filename).resolve()
            if not str(member_dest).startswith(str(extract_dir_resolved) + "/") \
               and member_dest != extract_dir_resolved:
                shutil.rmtree(extract_dir, ignore_errors=True)
                raise ValueError(f"Zip Slip 攻擊偵測：{member.filename}")
            zf.extract(member, extract_dir)

    # Parse manifest
    manifest_path = extract_dir / "manifest.json"
    if not manifest_path.exists():
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise ValueError("manifest.json not found in MCPB")

    manifest_size = manifest_path.stat().st_size
    if manifest_size > 64 * 1024:  # 64 KB 上限
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise ValueError(f"manifest.json 過大（{manifest_size} bytes，上限 64 KB）")

    manifest = json.loads(manifest_path.read_text())

    # Collect Python source files
    source_files = sorted(extract_dir.rglob("*.py"))

    # Collect dependency definition files
    dep_files = []
    for name in ("pyproject.toml", "requirements.txt", "uv.lock", "package.json", "package-lock.json"):
        p = extract_dir / name
        if p.exists():
            dep_files.append(p)

    return McpbInfo(
        file_path=path,
        sha256=sha256,
        extract_dir=extract_dir,
        manifest=manifest,
        source_files=source_files,
        dependency_files=dep_files,
    )


def cleanup(info: McpbInfo) -> None:
    shutil.rmtree(info.extract_dir, ignore_errors=True)
