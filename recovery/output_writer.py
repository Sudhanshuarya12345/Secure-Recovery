"""
pyrecovery.recovery.output_writer — Organize and write recovered files safely.

Handles file output with: dedup naming, category folders, manifest tracking,
and safe writes (never overwrites without explicit request).
"""
from __future__ import annotations
import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class OutputEntry:
    original_name: str
    output_path: str
    category: str
    size: int
    sha256: str
    source: str  # "filesystem", "carved", "fragment"
    is_deleted: bool = False

    def to_dict(self) -> dict:
        return {"original_name": self.original_name, "output_path": self.output_path,
                "category": self.category, "size": self.size, "sha256": self.sha256,
                "source": self.source, "is_deleted": self.is_deleted}


class OutputWriter:
    """Safely write recovered files to organized output directory.

    Structure:
        output_dir/
        ├── images/
        ├── documents/
        ├── archives/
        ├── media/
        ├── system/
        ├── deleted/
        ├── partial/
        └── manifest.json
    """
    CATEGORIES = ["images", "documents", "archives", "media", "system",
                  "deleted", "partial", "unknown"]

    EXTENSION_MAP: dict[str, str] = {
        "jpg": "images", "jpeg": "images", "png": "images", "gif": "images",
        "bmp": "images", "heic": "images", "tiff": "images", "webp": "images",
        "pdf": "documents", "doc": "documents", "docx": "documents",
        "xls": "documents", "xlsx": "documents", "ppt": "documents",
        "txt": "documents", "rtf": "documents", "odt": "documents",
        "zip": "archives", "rar": "archives", "7z": "archives",
        "gz": "archives", "tar": "archives", "bz2": "archives",
        "mp3": "media", "mp4": "media", "avi": "media", "mkv": "media",
        "wav": "media", "flac": "media", "ogg": "media", "mov": "media",
        "exe": "system", "dll": "system", "sys": "system", "db": "system",
        "sqlite": "system", "log": "system",
    }

    def __init__(self, output_dir: str, mode: str = "by_type") -> None:
        self._output_dir = Path(output_dir)
        self.mode = mode
        self._entries: list[OutputEntry] = []
        self._name_counter: dict[str, int] = {}
        if self.mode in ("by_type", "both"):
            self._setup_dirs()
        if self.mode in ("tree", "both"):
            (self._output_dir / "tree").mkdir(parents=True, exist_ok=True)

    def write_with_tree(self, entry, data: bytes) -> OutputEntry | None:
        """Preserves original path for filesystem recovery."""
        if self.mode == "by_type":
            return None

        # Sanitize path components
        safe_path = self._sanitize_path(entry.full_path)
        dest = self._output_dir / "tree" / safe_path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)

        if entry.is_deleted:
            stem = dest.stem
            suffix = dest.suffix
            dest = dest.with_name(f"{stem}_[DELETED]{suffix}")

        dest.write_bytes(data)

        meta = {
            "original_path": entry.full_path,
            "is_deleted": entry.is_deleted,
            "size": entry.size,
            "created_at": entry.created_at.isoformat() if entry.created_at else None,
            "modified_at": entry.modified_at.isoformat() if entry.modified_at else None,
        }
        with open(str(dest) + ".meta.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        sha256 = hashlib.sha256(data).hexdigest()
        out_entry = OutputEntry(
            original_name=entry.name,
            output_path=str(dest),
            category="tree",
            size=len(data),
            sha256=sha256,
            source="filesystem",
            is_deleted=entry.is_deleted
        )
        self._entries.append(out_entry)
        logger.debug("Wrote tree file %s -> %s", entry.full_path, dest)
        return out_entry

    def _sanitize_path(self, path: str) -> str:
        """Ensure no traversal or invalid characters in path."""
        parts = [p for p in path.split("/") if p and p not in (".", "..")]
        safe_parts = []
        for p in parts:
            safe = "".join(c if c.isalnum() or c in ".-_ " else "_" for c in p)
            safe_parts.append(safe)
        return "/".join(safe_parts)

    def write_file(self, name: str, data: bytes, category: str = "",
                   source: str = "filesystem", is_deleted: bool = False) -> OutputEntry:
        if not category:
            ext = Path(name).suffix.lstrip(".").lower()
            category = self.EXTENSION_MAP.get(ext, "unknown")
        if is_deleted:
            category = "deleted"
        target_dir = self._output_dir / category
        target_dir.mkdir(parents=True, exist_ok=True)
        safe_name = self._safe_filename(name, target_dir)
        target_path = target_dir / safe_name

        target_path.write_bytes(data)

        sha256 = hashlib.sha256(data).hexdigest()
        entry = OutputEntry(original_name=name, output_path=str(target_path),
                            category=category, size=len(data), sha256=sha256,
                            source=source, is_deleted=is_deleted)
        self._entries.append(entry)
        logger.debug("Wrote %s -> %s (%d bytes)", name, target_path, len(data))
        return entry

    def copy_file(self, src_path: str, name: str = "", category: str = "",
                  source: str = "filesystem", is_deleted: bool = False) -> OutputEntry:
        src = Path(src_path)
        if not name:
            name = src.name
        data = src.read_bytes()
        return self.write_file(name, data, category, source, is_deleted)

    def write_manifest(self) -> str:
        manifest_path = str(self._output_dir / "manifest.json")
        data = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "total_files": len(self._entries),
            "total_size": sum(e.size for e in self._entries),
            "files": [e.to_dict() for e in self._entries],
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return manifest_path

    def write_file_tree_json(self, root_node, filesystem_type: str = "Unknown") -> str:
        """Write the hierarchical directory structure to file_tree.json."""
        def node_to_dict(node):
            d = {
                "name": node.name,
                "type": "directory" if node.is_directory else "file",
                "deleted": node.deleted
            }
            if not node.is_directory and getattr(node, 'entry', None):
                d["size"] = node.entry.size
                if getattr(node.entry, 'created_at', None):
                    d["created_at"] = node.entry.created_at.isoformat()
                if getattr(node.entry, 'modified_at', None):
                    d["modified_at"] = node.entry.modified_at.isoformat()
            
            if node.is_directory and node.children:
                d["children"] = [node_to_dict(child) for child in node.children]
            return d

        data = {
            "filesystem": filesystem_type,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "tree": node_to_dict(root_node)
        }
        
        tree_path = str(self._output_dir / "file_tree.json")
        with open(tree_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return tree_path

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def total_bytes_written(self) -> int:
        return sum(e.size for e in self._entries)

    def get_stats(self) -> dict:
        by_cat: dict[str, int] = {}
        for e in self._entries:
            by_cat[e.category] = by_cat.get(e.category, 0) + 1
        return {"total_files": len(self._entries),
                "total_bytes": self.total_bytes_written,
                "by_category": by_cat}

    def _setup_dirs(self) -> None:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        for cat in self.CATEGORIES:
            (self._output_dir / cat).mkdir(exist_ok=True)

    def _safe_filename(self, name: str, target_dir: Path) -> str:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
        if not safe:
            safe = "unnamed"
        target = target_dir / safe
        if not target.exists():
            return safe
        stem = Path(safe).stem
        suffix = Path(safe).suffix
        counter = self._name_counter.get(safe, 1)
        while (target_dir / f"{stem}_{counter}{suffix}").exists():
            counter += 1
        self._name_counter[safe] = counter + 1
        return f"{stem}_{counter}{suffix}"
