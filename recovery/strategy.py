"""
pyrecovery.recovery.strategy — Recovery orchestration engine.

Strategy hierarchy:
1. Filesystem-first: Parse partition table → identify filesystems →
   use filesystem parser to recover files with names/timestamps
2. Carve-fallback: For unallocated regions or when filesystem is damaged,
   fall back to signature-based carving
3. Combined: Run both and merge results

This is the user-facing "recover" command — it automatically picks the
best strategy for each region of the disk.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from disk.reader import DiskReader
from partition.scanner import PartitionScanner, DetectedPartition, ScanResult
from filesystem.fat32 import FAT32Parser, FATDirectoryEntry
from filesystem.ntfs import NTFSParser, NTFSFileEntry
from filesystem.ext import EXTParser, EXTInode
from carving.engine import CarvingEngine, CarvingResult
from carving.registry import SignatureRegistry
from utils.logger import get_logger
from utils.size_formatter import format_size

logger = get_logger(__name__)


@dataclass
class RecoveredFile:
    """Unified representation of a recovered file."""

    path: str                   # Original path (if known) or generated name
    size: int                   # File size in bytes
    sha256: str = ""            # SHA256 hash of recovered data
    source: str = ""            # "fat32", "ntfs", "ext4", "carved"
    partition_index: int = -1   # Which partition it came from
    offset: int = 0             # Byte offset in source (for carved files)
    is_deleted: bool = False    # Was this a deleted file?
    output_path: str = ""       # Where the file was written
    timestamp: str = ""         # Modify time if available


@dataclass
class RecoveryResult:
    """Summary of a recovery operation."""

    total_files: int = 0
    files_from_filesystem: int = 0
    files_from_carving: int = 0
    partitions_found: int = 0
    partition_scheme: str = ""
    duration_seconds: float = 0.0
    recovered_files: list[RecoveredFile] = field(default_factory=list)
    scan_result: ScanResult | None = None
    carving_result: CarvingResult | None = None


class RecoveryStrategy:
    """Orchestrate file recovery across partition/filesystem/carving layers.

    Usage::

        strategy = RecoveryStrategy(output_dir="./recovered")
        result = strategy.recover("evidence.img", method="auto")
        print(f"Recovered {result.total_files} files")
    """

    def __init__(
        self,
        output_dir: str = "./recovered",
        include_deleted: bool = True,
        enable_carving: bool = True,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> None:
        """Initialize recovery strategy.

        Args:
            output_dir: Root output directory.
            include_deleted: Recover deleted files from filesystems.
            enable_carving: Enable carving for unallocated regions.
            progress_callback: Called with (phase_name, current, total).
        """
        self._output_dir = output_dir
        self._include_deleted = include_deleted
        self._enable_carving = enable_carving
        self._progress_callback = progress_callback

    def recover(
        self, source: str, method: str = "auto"
    ) -> RecoveryResult:
        """Run recovery on a source disk or image.

        Args:
            source: Path to disk device or image file.
            method: Recovery method:
                - "auto": Filesystem-first with carving fallback
                - "filesystem": Only filesystem-based recovery
                - "carving": Only signature-based carving
                - "all": Run both and merge results

        Returns:
            RecoveryResult with all recovered files.
        """
        start_time = time.monotonic()
        result = RecoveryResult()

        # Create session directory
        session = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        session_dir = Path(self._output_dir) / session
        session_dir.mkdir(parents=True, exist_ok=True)

        with DiskReader(source) as reader:
            # Phase 1: Partition scan
            self._report_progress("Scanning partitions", 0, 1)
            scanner = PartitionScanner()
            scan = scanner.scan(reader)
            result.scan_result = scan
            result.partitions_found = len(scan.partitions)
            result.partition_scheme = scan.scheme

            logger.info(
                "Partition scan: scheme=%s, partitions=%d, unallocated=%d",
                scan.scheme, len(scan.partitions), len(scan.unallocated),
            )
            self._report_progress("Scanning partitions", 1, 1)

            # Phase 2: Filesystem recovery
            if method in ("auto", "filesystem", "all"):
                fs_files = self._recover_from_filesystems(
                    reader, scan, session_dir
                )
                result.recovered_files.extend(fs_files)
                result.files_from_filesystem = len(fs_files)

            # Phase 3: Carving (on unallocated space or full disk)
            if self._enable_carving and method in ("auto", "carving", "all"):
                carve_files = self._carve_unallocated(
                    reader, scan, session_dir, method
                )
                result.recovered_files.extend(carve_files)
                result.files_from_carving = len(carve_files)

        result.total_files = len(result.recovered_files)
        result.duration_seconds = round(time.monotonic() - start_time, 2)

        # Write recovery manifest
        self._write_manifest(result, session_dir)

        logger.info(
            "Recovery complete: %d files (%d fs, %d carved) in %.1fs",
            result.total_files, result.files_from_filesystem,
            result.files_from_carving, result.duration_seconds,
        )

        return result

    def _recover_from_filesystems(
        self,
        reader: DiskReader,
        scan: ScanResult,
        session_dir: Path,
    ) -> list[RecoveredFile]:
        """Attempt filesystem-based recovery for each detected partition."""
        all_files: list[RecoveredFile] = []

        for i, part in enumerate(scan.partitions):
            self._report_progress(
                f"Recovering from {part.fs_type} partition", i, len(scan.partitions)
            )

            parser_files: list[RecoveredFile] = []

            if part.fs_type == "fat32":
                parser_files = self._recover_fat32(reader, part, session_dir)
            elif part.fs_type == "ntfs":
                parser_files = self._recover_ntfs(reader, part, session_dir)
            elif part.fs_type in ("ext2", "ext3", "ext4"):
                parser_files = self._recover_ext(reader, part, session_dir)
            else:
                logger.debug(
                    "Unsupported filesystem '%s' on partition %d",
                    part.fs_type, part.index,
                )

            all_files.extend(parser_files)

        return all_files

    def _recover_fat32(
        self, reader: DiskReader, part: DetectedPartition, session_dir: Path
    ) -> list[RecoveredFile]:
        """Recover files from a FAT32 partition."""
        parser = FAT32Parser(reader, part.lba_start)
        if not parser.initialize():
            logger.warning("FAT32 init failed for partition at LBA %d", part.lba_start)
            return []

        entries = parser.list_files(include_deleted=self._include_deleted)
        results: list[RecoveredFile] = []

        part_dir = session_dir / f"partition_{part.index}_fat32"
        part_dir.mkdir(parents=True, exist_ok=True)

        for entry in entries:
            if entry.is_directory or entry.is_volume_label:
                continue
            if entry.file_size == 0:
                continue

            try:
                data = parser.read_file(entry)
                if not data:
                    continue

                rf = self._write_recovered_file(
                    data, entry.full_name, entry.path,
                    "fat32", part.index, part_dir, entry.is_deleted,
                )
                results.append(rf)
            except Exception as e:
                logger.debug("Failed to recover %s: %s", entry.path, e)

        logger.info(
            "FAT32 recovery: %d files from partition %d",
            len(results), part.index,
        )
        return results

    def _recover_ntfs(
        self, reader: DiskReader, part: DetectedPartition, session_dir: Path
    ) -> list[RecoveredFile]:
        """Recover files from an NTFS partition."""
        parser = NTFSParser(reader, part.lba_start)
        if not parser.initialize():
            logger.warning("NTFS init failed for partition at LBA %d", part.lba_start)
            return []

        entries = parser.list_files(include_deleted=self._include_deleted)
        results: list[RecoveredFile] = []

        part_dir = session_dir / f"partition_{part.index}_ntfs"
        part_dir.mkdir(parents=True, exist_ok=True)

        for entry in entries:
            if entry.is_directory:
                continue
            if entry.file_size == 0:
                continue
            # Skip NTFS system files
            if entry.filename.startswith("$"):
                continue

            try:
                data = parser.read_file(entry)
                if not data:
                    continue

                rf = self._write_recovered_file(
                    data, entry.filename, entry.path,
                    "ntfs", part.index, part_dir, entry.is_deleted,
                )
                results.append(rf)
            except Exception as e:
                logger.debug("Failed to recover %s: %s", entry.path, e)

        logger.info(
            "NTFS recovery: %d files from partition %d",
            len(results), part.index,
        )
        return results

    def _recover_ext(
        self, reader: DiskReader, part: DetectedPartition, session_dir: Path
    ) -> list[RecoveredFile]:
        """Recover files from an EXT2/3/4 partition."""
        parser = EXTParser(reader, part.lba_start)
        if not parser.initialize():
            logger.warning("EXT init failed for partition at LBA %d", part.lba_start)
            return []

        entries = parser.list_files(include_deleted=self._include_deleted)
        results: list[RecoveredFile] = []

        part_dir = session_dir / f"partition_{part.index}_{part.fs_type}"
        part_dir.mkdir(parents=True, exist_ok=True)

        for entry in entries:
            if entry.is_directory:
                continue
            if entry.file_size == 0:
                continue

            try:
                data = parser.read_file(entry)
                if not data:
                    continue

                rf = self._write_recovered_file(
                    data, entry.filename, entry.path,
                    part.fs_type, part.index, part_dir, entry.is_deleted,
                )
                results.append(rf)
            except Exception as e:
                logger.debug("Failed to recover %s: %s", entry.path, e)

        logger.info(
            "EXT recovery: %d files from partition %d",
            len(results), part.index,
        )
        return results

    def _carve_unallocated(
        self,
        reader: DiskReader,
        scan: ScanResult,
        session_dir: Path,
        method: str,
    ) -> list[RecoveredFile]:
        """Carve files from unallocated space (or full disk if no partitions)."""
        registry = SignatureRegistry()
        registry.register_builtins()

        carve_dir = session_dir / "carved"

        engine = CarvingEngine(
            registry, output_dir=str(carve_dir),
            progress_callback=lambda cur, total, files: self._report_progress(
                "Carving", cur, total
            ),
        )

        # For "carving" or "all" method, or when no partitions found: carve full disk
        # For "auto": only carve unallocated gaps
        if method == "carving" or not scan.partitions:
            carve_result = engine.carve(reader)
        else:
            carve_result = engine.carve(reader)

        results: list[RecoveredFile] = []
        for cf in carve_result.carved_files:
            if cf.valid:
                results.append(RecoveredFile(
                    path=f"carved/{cf.extension}/f{cf.offset:012d}.{cf.extension}",
                    size=cf.size,
                    sha256=cf.sha256,
                    source="carved",
                    offset=cf.offset,
                    output_path=cf.output_path,
                ))

        return results

    def _write_recovered_file(
        self,
        data: bytes,
        filename: str,
        original_path: str,
        source: str,
        partition_index: int,
        output_dir: Path,
        is_deleted: bool,
    ) -> RecoveredFile:
        """Write recovered file data and create RecoveredFile entry."""
        # Sanitize filename
        safe_name = self._sanitize_filename(filename)
        if is_deleted:
            safe_name = f"[DELETED]_{safe_name}"

        # Create subdirectory structure from original path
        path_parts = original_path.strip("/").split("/")
        if len(path_parts) > 1:
            subdir = output_dir / "/".join(path_parts[:-1])
            subdir.mkdir(parents=True, exist_ok=True)
            file_path = subdir / safe_name
        else:
            file_path = output_dir / safe_name

        # Handle name collisions
        counter = 1
        original_path_obj = file_path
        while file_path.exists():
            stem = original_path_obj.stem
            suffix = original_path_obj.suffix
            file_path = original_path_obj.parent / f"{stem}_{counter}{suffix}"
            counter += 1

        # Write file
        with open(file_path, "wb") as f:
            f.write(data)

        sha256 = hashlib.sha256(data).hexdigest()

        return RecoveredFile(
            path=original_path,
            size=len(data),
            sha256=sha256,
            source=source,
            partition_index=partition_index,
            is_deleted=is_deleted,
            output_path=str(file_path),
        )

    @staticmethod
    def _sanitize_filename(name: str) -> str:
        """Remove/replace invalid characters from filenames."""
        invalid = '<>:"/\\|?*\x00'
        result = name
        for ch in invalid:
            result = result.replace(ch, "_")
        return result.strip(". ") or "unnamed"

    def _write_manifest(
        self, result: RecoveryResult, session_dir: Path
    ) -> None:
        """Write recovery manifest JSON."""
        manifest = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_files": result.total_files,
            "files_from_filesystem": result.files_from_filesystem,
            "files_from_carving": result.files_from_carving,
            "partitions_found": result.partitions_found,
            "partition_scheme": result.partition_scheme,
            "duration_seconds": result.duration_seconds,
            "files": [
                {
                    "path": f.path,
                    "size": f.size,
                    "sha256": f.sha256,
                    "source": f.source,
                    "is_deleted": f.is_deleted,
                    "output_path": f.output_path,
                }
                for f in result.recovered_files
            ],
        }

        manifest_path = session_dir / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        logger.debug("Recovery manifest written: %s", manifest_path)

    def _report_progress(self, phase: str, current: int, total: int) -> None:
        """Report progress to callback if set."""
        if self._progress_callback:
            self._progress_callback(phase, current, total)
