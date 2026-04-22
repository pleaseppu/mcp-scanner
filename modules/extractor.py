"""Extract and inspect MCPB / ZIP files or source directories."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# 解壓安全限制
_MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024   # 500 MB
_MAX_FILE_COUNT = 10_000

# 收集原始碼時略過的目錄
_SKIP_DIRS = frozenset({"node_modules", "dist", "build", ".next", "__pycache__", ".venv", "venv", ".git"})

# 原始碼副檔名
_SOURCE_PATTERNS = ("*.py", "*.js", "*.ts", "*.mjs", "*.cjs", "*.jsx", "*.tsx")

# 相依定義檔名
_DEP_FILENAMES = ("pyproject.toml", "requirements.txt", "uv.lock", "package.json", "package-lock.json")


@dataclass
class McpbInfo:
    file_path: Path
    sha256: str
    extract_dir: Path
    manifest: dict
    source_files: list[Path] = field(default_factory=list)
    dependency_files: list[Path] = field(default_factory=list)
    scan_mode: str = "mcpb"        # "mcpb" | "remote"
    _is_temp: bool = True          # cleanup 時是否刪除 extract_dir


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_source_files(root: Path) -> list[Path]:
    return sorted(
        f
        for pattern in _SOURCE_PATTERNS
        for f in root.rglob(pattern)
        if not any(part in _SKIP_DIRS for part in f.relative_to(root).parts)
    )


def _collect_dep_files(root: Path) -> list[Path]:
    return [root / name for name in _DEP_FILENAMES if (root / name).exists()]


def _resolve_root(extract_dir: Path) -> Path:
    """If the zip contains a single top-level directory, use that as root."""
    entries = [e for e in extract_dir.iterdir() if not e.name.startswith(".")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extract_dir


def _parse_metadata(root: Path) -> tuple[dict, str]:
    """Try manifest.json → pyproject.toml → package.json. Return (metadata, mode)."""
    # manifest.json → mcpb mode
    manifest_path = root / "manifest.json"
    if manifest_path.exists():
        size = manifest_path.stat().st_size
        if size > 64 * 1024:
            raise ValueError(f"manifest.json 過大（{size} bytes，上限 64 KB）")
        return json.loads(manifest_path.read_text()), "mcpb"

    # pyproject.toml → remote mode
    pyproject_path = root / "pyproject.toml"
    if pyproject_path.exists():
        data = tomllib.loads(pyproject_path.read_text())
        project = data.get("project", {})
        authors = project.get("authors", [])
        return {
            "name": project.get("name", "unknown"),
            "display_name": project.get("name", "unknown"),
            "version": project.get("version", "unknown"),
            "description": project.get("description", ""),
            "author": {"name": authors[0].get("name", "") if authors else ""},
        }, "remote"

    # package.json → remote mode
    pkg_path = root / "package.json"
    if pkg_path.exists():
        pkg = json.loads(pkg_path.read_text())
        return {
            "name": pkg.get("name", "unknown"),
            "display_name": pkg.get("name", "unknown"),
            "version": pkg.get("version", "unknown"),
            "description": pkg.get("description", ""),
            "author": {"name": pkg.get("author", "")},
        }, "remote"

    return {"name": "unknown", "version": "unknown"}, "remote"


def extract_mcpb(mcpb_path: str) -> McpbInfo:
    """Extract MCPB or ZIP file to a temp directory and parse its contents."""
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
            raise ValueError(f"包含過多檔案（{len(members)} 筆，上限 {_MAX_FILE_COUNT}）")

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

    # Resolve root (handle single top-level folder inside zip)
    root = _resolve_root(extract_dir)
    manifest, scan_mode = _parse_metadata(root)

    return McpbInfo(
        file_path=path,
        sha256=sha256,
        extract_dir=root,
        manifest=manifest,
        source_files=_collect_source_files(root),
        dependency_files=_collect_dep_files(root),
        scan_mode=scan_mode,
        _is_temp=True,
    )


def scan_directory(dir_path: str) -> McpbInfo:
    """Scan a source directory directly (no extraction needed)."""
    path = Path(dir_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Directory not found: {path}")
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")

    manifest, scan_mode = _parse_metadata(path)

    return McpbInfo(
        file_path=path,
        sha256="N/A (directory)",
        extract_dir=path,
        manifest=manifest,
        source_files=_collect_source_files(path),
        dependency_files=_collect_dep_files(path),
        scan_mode="remote",
        _is_temp=False,
    )


def cleanup(info: McpbInfo) -> None:
    if info._is_temp:
        shutil.rmtree(info.extract_dir, ignore_errors=True)
