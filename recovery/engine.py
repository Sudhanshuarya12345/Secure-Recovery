"""
pyrecovery.recovery.engine — Unified callback-based recovery engine.

This is the **shared backend** used by both the CLI wizard and the Tkinter UI.
Neither consumer contains any recovery logic — they only provide callbacks.

Architecture:
    CLI wizard  ─┐
                 ├──▶  RecoveryEngine  ──▶  disk/ + carving/ + filesystem/
    Tkinter UI ──┘

Thread safety:
    - start() runs in the *calling* thread — wrap in threading.Thread externally
    - stop() / pause() / resume() are thread-safe (use threading.Event)
    - Callbacks are called from the engine thread — UI consumers must
      marshal to the main thread via root.after()
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

class RecoveryAborted(Exception):
    """Raised when the user completely aborts the recovery operation."""
    pass


# ── Configuration ───────────────────────────────────────────────────────


@dataclass
class RecoveryConfig:
    """All settings needed to run a recovery — produced by wizard or UI."""

    source: str                         # Device path or image file
    output_dir: str = "./recovered"     # Output root directory
    strategy: str = "both"              # "filesystem", "carving", "both"
    file_types: list[str] = field(default_factory=lambda: ["all"])
    partition_index: int | None = None  # None = entire disk
    chunk_size: int = 1_048_576         # 1 MB default
    skip_duplicates: bool = True
    save_partials: bool = False
    max_file_size: int = 500 * 1024 * 1024  # 500 MB default
    folder_structure: str = "by_type"   # "by_type", "by_batch", "flat"
    file_naming: str = "offset"         # "offset" or "counter"
    generate_hashes: bool = True
    generate_timeline: bool = True
    forensic_log: bool = True


# ── Callback data ──────────────────────────────────────────────────────


@dataclass
class ProgressData:
    """Snapshot of engine progress — passed to on_progress callback."""

    bytes_scanned: int = 0
    total_bytes: int = 0
    speed_bps: float = 0.0
    eta_seconds: float = 0.0
    current_action: str = ""
    files_by_type: dict[str, int] = field(default_factory=dict)

    @property
    def percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return min(100.0, (self.bytes_scanned / self.total_bytes) * 100)


@dataclass
class RecoveredFileInfo:
    """Info about a single recovered file — passed to on_file_found callback."""

    filename: str
    extension: str
    size: int
    offset: int
    sha256: str = ""
    source: str = ""          # "fat32", "ntfs", "ext4", "carved"
    output_path: str = ""
    is_deleted: bool = False


@dataclass
class RecoveryStats:
    """Final recovery statistics — passed to on_complete callback."""

    total_files: int = 0
    files_from_filesystem: int = 0
    files_from_carving: int = 0
    files_by_type: dict[str, int] = field(default_factory=dict)
    total_bytes_recovered: int = 0
    bytes_scanned: int = 0
    duration_seconds: float = 0.0
    output_dir: str = ""
    partitions_found: int = 0
    partition_scheme: str = ""
    report_path: str = ""
    log_path: str = ""


# ── Callbacks ──────────────────────────────────────────────────────────


@dataclass
class EngineCallbacks:
    """Callback functions consumed by CLI or UI.

    CLI uses these to update Rich progress bars.
    UI uses these (wrapped in root.after()) to update Tkinter widgets.
    """

    on_progress: Callable[[ProgressData], None] = lambda _: None
    on_file_found: Callable[[RecoveredFileInfo], None] = lambda _: None
    on_log: Callable[[str, str], None] = lambda lvl, msg: None   # (level, message)
    on_complete: Callable[[RecoveryStats], None] = lambda _: None
    on_error: Callable[[str], None] = lambda _: None


# ── Engine ─────────────────────────────────────────────────────────────


class RecoveryEngine:
    """Unified recovery engine with stop/pause/resume support.

    Usage::

        config = RecoveryConfig(source=r"\\\\.\\E:", output_dir="./out")
        callbacks = EngineCallbacks(on_progress=my_progress_fn)
        engine = RecoveryEngine(config, callbacks)

        # Run in background thread:
        t = threading.Thread(target=engine.start)
        t.start()

        # Later:
        engine.pause()
        engine.resume()
        engine.stop()
    """

    def __init__(self, config: RecoveryConfig, callbacks: EngineCallbacks) -> None:
        self._config = config
        self._cb = callbacks

        self._stop_event = threading.Event()
        self._abort_event = threading.Event()
        self._pause_event = threading.Event()

        # Speed tracking
        self._last_bytes = 0
        self._last_time = 0.0
        self._speed_bps = 0.0

    # ── Thread-safe control ─────────────────────────────────────────

    def stop(self) -> None:
        """Signal the engine to stop gracefully (thread-safe)."""
        self._stop_event.set()
        self._pause_event.set()  # Unpause if paused so it can exit

    def abort(self) -> None:
        """Signal the engine to abort completely (thread-safe)."""
        self._abort_event.set()
        self._stop_event.set()
        self._pause_event.set()

    def pause(self) -> None:
        """Pause the engine (thread-safe)."""
        self._pause_event.set()

    def resume(self) -> None:
        """Resume after pause (thread-safe)."""
        self._pause_event.clear()

    @property
    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    # ── Main entry ──────────────────────────────────────────────────

    def start(self) -> None:
        """Run the full recovery pipeline.  Blocks until complete or stopped."""
        start_time = time.monotonic()
        stats = RecoveryStats()

        try:
            self._cb.on_log("INFO", f"Recovery starting: {self._config.source}")

            # Create output session directory
            session_name = datetime.now().strftime("recovery_%Y%m%d_%H%M%S")
            session_dir = Path(self._config.output_dir) / session_name
            session_dir.mkdir(parents=True, exist_ok=True)
            stats.output_dir = str(session_dir)

            # Import here to avoid circular imports at module level
            from disk.reader import DiskReader
            from partition.scanner import PartitionScanner
            from carving.engine import CarvingEngine
            from carving.registry import SignatureRegistry

            with DiskReader(self._config.source) as reader:
                total_size = reader.get_disk_size()
                stats.bytes_scanned = total_size
                self._last_time = time.monotonic()

                # Phase 1: Partition scan
                self._cb.on_log("INFO", "Scanning partitions...")
                self._update_progress(0, total_size, "Scanning partition table...")

                scanner = PartitionScanner()
                scan_result = scanner.scan(reader)
                stats.partitions_found = len(scan_result.partitions)
                stats.partition_scheme = scan_result.scheme

                self._cb.on_log("INFO",
                    f"Found {len(scan_result.partitions)} partition(s) "
                    f"[{scan_result.scheme.upper()}]"
                )

                # Phase 2: Filesystem recovery
                if not self._stop_event.is_set() and self._config.strategy in ("filesystem", "both"):
                    self._cb.on_log("INFO", "Starting filesystem-aware recovery...")
                    fs_files = self._recover_from_filesystems(
                        reader, scan_result, session_dir, stats
                    )
                    stats.files_from_filesystem = len(fs_files)
                    for f in fs_files:
                        ext = f.extension
                        stats.files_by_type[ext] = stats.files_by_type.get(ext, 0) + 1
                        stats.total_bytes_recovered += f.size

                # Phase 3: Carving
                if not self._stop_event.is_set() and self._config.strategy in ("carving", "both"):
                    self._cb.on_log("INFO", "Starting signature-based carving...")
                    self._run_carving(reader, session_dir, stats)

                # Phase 4: Hash manifest
                if not self._abort_event.is_set() and self._config.generate_hashes:
                    self._cb.on_log("INFO", "Generating hash manifest...")
                    self._generate_hash_manifest(session_dir)

                # Phase 5: Forensic report
                if not self._abort_event.is_set() and self._config.forensic_log:
                    report_path = session_dir / "recovery_report.json"
                    self._write_report(stats, report_path)
                    stats.report_path = str(report_path)
                    self._cb.on_log("INFO", f"Report saved: {report_path}")

                if self._abort_event.is_set():
                    raise RecoveryAborted("Recovery completely aborted by user.")

                if self._stop_event.is_set():
                    self._cb.on_log("WARN", "Recovery stopped by user.")

            stats.total_files = stats.files_from_filesystem + stats.files_from_carving
            stats.duration_seconds = round(time.monotonic() - start_time, 2)

            self._cb.on_log("INFO",
                f"Recovery complete: {stats.total_files} files in "
                f"{stats.duration_seconds:.1f}s"
            )
            self._cb.on_complete(stats)

        except RecoveryAborted as e:
            self._cb.on_log("WARN", str(e))
            self._cb.on_error(str(e))
        except Exception as e:
            self._cb.on_error(str(e))
            self._cb.on_log("ERROR", f"Recovery failed: {e}")

    # ── Filesystem recovery ─────────────────────────────────────────

    def _recover_from_filesystems(
        self, reader, scan_result, session_dir: Path, stats: RecoveryStats
    ) -> list[RecoveredFileInfo]:
        """Delegate to existing RecoveryStrategy for FS-based recovery."""
        from recovery.strategy import RecoveryStrategy

        strategy = RecoveryStrategy(
            output_dir=str(session_dir),
            include_deleted=True,
            enable_carving=False,  # We handle carving separately
            progress_callback=lambda phase, cur, total: self._update_progress(
                cur, total, f"FS recovery: {phase}"
            ),
            stop_check=lambda: self._stop_event.is_set(),
        )

        result = strategy.recover(self._config.source, method="filesystem")

        files: list[RecoveredFileInfo] = []
        for rf in result.recovered_files:
            ext = Path(rf.path).suffix.lstrip(".").lower() or "unknown"
            info = RecoveredFileInfo(
                filename=Path(rf.path).name,
                extension=ext,
                size=rf.size,
                offset=rf.offset,
                sha256=rf.sha256,
                source=rf.source,
                output_path=rf.output_path,
                is_deleted=rf.is_deleted,
            )
            files.append(info)
            self._cb.on_file_found(info)

        return files

    # ── Carving ─────────────────────────────────────────────────────

    def _run_carving(self, reader, session_dir: Path, stats: RecoveryStats) -> None:
        """Run the carving engine with progress callbacks."""
        from carving.engine import CarvingEngine
        from carving.registry import SignatureRegistry

        registry = SignatureRegistry()
        registry.register_builtins()

        carve_dir = session_dir / "carved"

        def carve_progress(scanned: int, total: int, files_found: int) -> bool:
            self._wait_if_paused()
            if self._stop_event.is_set():
                return False
            self._update_progress(scanned, total, f"Carving... ({files_found} files found)")
            return True

        engine = CarvingEngine(
            registry,
            output_dir=str(carve_dir),
            chunk_size=self._config.chunk_size,
            enable_dedup=self._config.skip_duplicates,
            progress_callback=carve_progress,
        )

        result = engine.carve(reader)

        stats.files_from_carving = result.files_valid

        for cf in result.carved_files:
            if cf.valid:
                ext = cf.extension
                stats.files_by_type[ext] = stats.files_by_type.get(ext, 0) + 1
                stats.total_bytes_recovered += cf.size

                info = RecoveredFileInfo(
                    filename=f"f{cf.offset:012d}.{cf.extension}",
                    extension=ext,
                    size=cf.size,
                    offset=cf.offset,
                    sha256=cf.sha256,
                    source="carved",
                    output_path=cf.output_path,
                )
                self._cb.on_file_found(info)

    # ── Progress helpers ────────────────────────────────────────────

    def _update_progress(self, current: int, total: int, action: str) -> None:
        """Calculate speed/ETA and fire on_progress callback."""
        now = time.monotonic()
        elapsed = now - self._last_time

        if elapsed >= 0.5:  # Update speed every 500ms
            bytes_delta = current - self._last_bytes
            self._speed_bps = bytes_delta / elapsed if elapsed > 0 else 0
            self._last_bytes = current
            self._last_time = now

        remaining = total - current
        eta = remaining / self._speed_bps if self._speed_bps > 0 else 0

        data = ProgressData(
            bytes_scanned=current,
            total_bytes=total,
            speed_bps=self._speed_bps,
            eta_seconds=eta,
            current_action=action,
        )
        self._cb.on_progress(data)

    def _wait_if_paused(self) -> None:
        """Block while pause is active (checked in carving loop)."""
        while self._pause_event.is_set() and not self._stop_event.is_set():
            time.sleep(0.1)

    # ── Post-recovery helpers ───────────────────────────────────────

    def _generate_hash_manifest(self, session_dir: Path) -> None:
        """Generate hash manifest for all recovered files."""
        try:
            from forensics.hasher import ForensicHasher
            hasher = ForensicHasher()
            results = hasher.hash_directory(str(session_dir))
            if results:
                hasher.write_manifest_csv(results, str(session_dir / "hash_manifest.csv"))
                hasher.write_manifest_json(results, str(session_dir / "hash_manifest.json"))
                self._cb.on_log("INFO", f"Hash manifest: {len(results)} files hashed")
        except Exception as e:
            self._cb.on_log("WARN", f"Hash manifest generation failed: {e}")

    def _write_report(self, stats: RecoveryStats, path: Path) -> None:
        """Write JSON recovery report."""
        report = {
            "tool": "PyRecovery v1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": self._config.source,
            "strategy": self._config.strategy,
            "output_dir": stats.output_dir,
            "duration_seconds": stats.duration_seconds,
            "total_files": stats.total_files,
            "files_from_filesystem": stats.files_from_filesystem,
            "files_from_carving": stats.files_from_carving,
            "files_by_type": stats.files_by_type,
            "total_bytes_recovered": stats.total_bytes_recovered,
            "bytes_scanned": stats.bytes_scanned,
            "partitions_found": stats.partitions_found,
            "partition_scheme": stats.partition_scheme,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
