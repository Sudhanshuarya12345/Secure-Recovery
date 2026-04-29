"""
pyrecovery.carving.engine — Core file carving engine.

Scanning algorithm:
1. Read source in 1MB chunks via ChunkReader (1024-byte overlap)
2. For each byte position in chunk:
   a. O(1) lookup first byte in SignatureRegistry
   b. For each candidate signature: check full header match
   c. If match → attempt extraction
3. Extraction strategy:
   a. sig.get_size() → use exact size if returned
   b. elif sig.footer → scan forward up to max_size for footer
   c. else → extract max_size bytes
4. Track extracted intervals as sorted list → skip overlaps
5. Call validator → reject invalid files
6. Deduplicator check → skip duplicates
7. Write to: output/{category}/{extension}/f{offset:012d}.{ext}
8. Write sidecar .meta.json with offset, size, signature, timestamp

Performance: ~50 MB/s on typical hardware. The first-byte dict lookup avoids
checking all 30+ signatures at every byte position (would be ~30x slower).
"""

from __future__ import annotations

import json
import time
from bisect import insort, bisect_left
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from carving.base_signature import BaseSignature
from carving.chunk_reader import ChunkReader
from carving.deduplicator import Deduplicator
from carving.registry import SignatureRegistry
from carving.validator import CarvedFileValidator
from disk.reader import DiskReader
from utils.logger import get_logger
from utils.size_formatter import format_size

logger = get_logger(__name__)


@dataclass
class CarvedFile:
    """Metadata for a single carved file."""

    offset: int
    size: int
    signature_name: str
    extension: str
    category: str
    sha256: str = ""
    output_path: str = ""
    valid: bool = True
    method: str = ""  # "size_field", "footer_scan", "max_size"


@dataclass
class CarvingResult:
    """Summary of a carving operation."""

    total_bytes_scanned: int = 0
    duration_seconds: float = 0.0
    files_found: int = 0
    files_valid: int = 0
    files_duplicate: int = 0
    files_rejected: int = 0
    files_by_type: dict[str, int] = field(default_factory=dict)
    carved_files: list[CarvedFile] = field(default_factory=list)


class CarvingEngine:
    """Core file carving engine for signature-based file recovery.

    Usage::

        registry = SignatureRegistry()
        registry.register_builtins()

        engine = CarvingEngine(registry, output_dir="./recovered")
        result = engine.carve("evidence.img")
        print(f"Recovered {result.files_valid} files")
    """

    def __init__(
        self,
        registry: SignatureRegistry,
        output_dir: str = "./output",
        chunk_size: int = 1_048_576,
        enable_dedup: bool = True,
        progress_callback: Callable[[int, int, int], bool] | None = None,
    ) -> None:
        """Initialize the carving engine.

        Args:
            registry: Populated SignatureRegistry with loaded signatures.
            output_dir: Root directory for recovered files.
            chunk_size: Size of each read chunk (default 1 MB).
            enable_dedup: Enable SHA256-based duplicate suppression.
            progress_callback: Called with (bytes_scanned, total_bytes, files_found).
        """
        self._registry = registry
        self._output_dir = output_dir
        self._chunk_size = chunk_size
        self._enable_dedup = enable_dedup
        self._progress_callback = progress_callback

        self._validator = CarvedFileValidator()
        self._dedup = Deduplicator() if enable_dedup else None

        # Sorted list of (start, end) intervals for extracted files
        # Used to prevent overlapping extractions
        self._extracted: list[tuple[int, int]] = []

    def carve(self, source: str | DiskReader) -> CarvingResult:
        """Run file carving on a source disk/image.

        Args:
            source: Path to source image file, or an existing DiskReader.

        Returns:
            CarvingResult with stats and list of carved files.
        """
        start_time = time.monotonic()
        result = CarvingResult()

        # Create session output directory
        session_name = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        session_dir = Path(self._output_dir) / session_name
        session_dir.mkdir(parents=True, exist_ok=True)

        # Open source
        own_reader = False
        if isinstance(source, str):
            reader = DiskReader(source)
            own_reader = True
        else:
            reader = source

        try:
            total_size = reader.get_disk_size()
            chunk_reader = ChunkReader(reader, self._chunk_size)

            logger.info(
                "Starting carving: source=%s, size=%s, signatures=%d",
                reader.source_path,
                format_size(total_size),
                self._registry.count,
            )

            for chunk_offset, chunk in chunk_reader:
                carved = self._scan_chunk(chunk, chunk_offset, reader, session_dir)
                result.carved_files.extend(carved)

                if self._progress_callback:
                    should_continue = self._progress_callback(
                        chunk_reader.bytes_read,
                        total_size,
                        len(result.carved_files),
                    )
                    if should_continue is False:
                        logger.warning("Carving aborted by progress callback")
                        break

        finally:
            if own_reader:
                reader.close()

        # Compute stats
        result.total_bytes_scanned = total_size
        result.duration_seconds = round(time.monotonic() - start_time, 2)
        result.files_found = len(result.carved_files)
        result.files_valid = sum(1 for f in result.carved_files if f.valid)
        result.files_duplicate = self._dedup.duplicate_count if self._dedup else 0
        result.files_rejected = result.files_found - result.files_valid

        for cf in result.carved_files:
            ext = cf.extension
            result.files_by_type[ext] = result.files_by_type.get(ext, 0) + 1

        logger.info(
            "Carving complete: %d files found (%d valid, %d rejected, %d dupes) in %.1fs",
            result.files_found,
            result.files_valid,
            result.files_rejected,
            result.files_duplicate,
            result.duration_seconds,
        )

        return result

    def _scan_chunk(
        self,
        chunk: bytes,
        base_offset: int,
        reader: DiskReader,
        session_dir: Path,
    ) -> list[CarvedFile]:
        """Scan a single chunk for signature matches.

        Args:
            chunk: Raw bytes of the current chunk.
            base_offset: Absolute byte offset of chunk[0] in the source.
            reader: DiskReader for extracting files beyond chunk boundary.
            session_dir: Output directory for this session.

        Returns:
            List of CarvedFile entries found in this chunk.
        """
        results: list[CarvedFile] = []
        chunk_len = len(chunk)
        candidates: list[tuple[int, int, int, BaseSignature]] = []

        # Assign priority: lower number = processed first
        # Signatures with footers or parseable size fields are more precise
        # and should claim disk ranges before greedy max_size fallbacks
        def _sig_priority(sig: BaseSignature) -> int:
            if sig.footer is not None:
                return 0  # Footer-based (JPEG, PDF, etc.) — most reliable
            # Heuristic: if get_size usually returns a value, it's better
            if sig.category in ("images", "documents", "media"):
                return 1  # Typically have structured sizes
            return 2  # System/archive sigs that often fall back to max_size

        # Find all signature candidates at C-speed using bytes.find()
        for sig in self._registry.get_all():
            priority = _sig_priority(sig)
            for header in sig.headers:
                if not header:
                    continue
                pos = 0
                while True:
                    pos = chunk.find(header, pos)
                    if pos == -1:
                        break
                    
                    # Calculate the actual start of the file based on header_offset
                    check_pos = pos - sig.header_offset
                    # Only keep candidates that start inside this chunk's boundaries
                    if 0 <= check_pos < chunk_len:
                        abs_offset = base_offset + check_pos
                        candidates.append((priority, abs_offset, check_pos, sig))
                    
                    # Move past this match to find the next one
                    pos += 1

        # Sort: first by priority (footer sigs first), then by disk offset
        candidates.sort(key=lambda x: (x[0], x[1]))

        for _prio, abs_offset, check_pos, sig in candidates:
            # Skip if this offset is inside an already-extracted file
            if self._overlaps_existing(abs_offset, abs_offset + 1):
                continue

            # Validate the full header logic (e.g. dynamic sizing, constraints)
            if not sig.match_header(chunk, check_pos):
                continue

            # Extract, deduplicate, and write
            carved = self._handle_match(sig, abs_offset, reader, session_dir)
            if carved:
                results.append(carved)

        return results

    def _handle_match(
        self,
        sig: BaseSignature,
        abs_offset: int,
        reader: DiskReader,
        session_dir: Path,
    ) -> CarvedFile | None:
        """Handle a signature match: extract, validate, dedup, write.

        Args:
            sig: The matched signature.
            abs_offset: Absolute byte offset in source where file starts.
            reader: DiskReader for reading file data.
            session_dir: Output directory.

        Returns:
            CarvedFile if successfully processed, None if rejected/duplicate.
        """
        # Check overlap
        if self._overlaps_existing(abs_offset, abs_offset + sig.min_size):
            return None

        # Extract file data
        data, method = self._extract_file(reader, abs_offset, sig)
        if data is None or len(data) < sig.min_size:
            return None

        # Deduplication check (use first 64KB for fast prefix hash)
        if self._dedup:
            is_dup, sha256 = self._dedup.check_and_mark(data)
            if is_dup:
                logger.debug("Duplicate at offset %d (%s)", abs_offset, sig.name)
                return None
        else:
            import hashlib
            sha256 = hashlib.sha256(data[:65536]).hexdigest()

        # Validate
        is_valid, reason = self._validator.validate(data, sig)
        if not is_valid:
            logger.debug(
                "Rejected %s at offset %d: %s", sig.name, abs_offset, reason
            )
            # For invalid files: only block the header area (min_size),
            # NOT the full 50MB extraction. This prevents false positive
            # EXE/BMP from swallowing real JPEG/PNG files behind them.
            block_size = min(sig.min_size, len(data))
            insort(self._extracted, (abs_offset, abs_offset + block_size))
        else:
            # Record extracted interval for valid files (full range)
            end_offset = abs_offset + len(data)
            insort(self._extracted, (abs_offset, end_offset))

        # Write output (valid goes to category, invalid goes to partial/)
        output_path = self._write_output(data, sig, abs_offset, session_dir, is_valid)

        return CarvedFile(
            offset=abs_offset,
            size=len(data),
            signature_name=sig.name,
            extension=sig.extension,
            category=sig.category,
            sha256=sha256,
            output_path=output_path,
            valid=is_valid,
            method=method,
        )

    def _extract_file(
        self, reader: DiskReader, offset: int, sig: BaseSignature
    ) -> tuple[bytes | None, str]:
        """Extract file data using the best available strategy.

        Strategy priority:
        1. sig.get_size() — exact size from header (most accurate)
        2. sig.footer — scan forward for end-of-file marker
        3. sig.max_size — extract maximum allowed bytes (last resort)

        Returns:
            Tuple of (data, method_name). data is None if extraction fails.
        """
        # Read initial data for header parsing
        initial_read = min(sig.max_size, reader.get_disk_size() - offset)
        if initial_read <= 0:
            return None, ""

        # Strategy 1: Parse header for exact size
        # Read a smaller chunk first for header parsing
        header_data = reader.read_at(offset, min(65536, initial_read))
        if not header_data:
            return None, ""

        try:
            exact_size = sig.get_size(header_data, 0)
        except Exception:
            exact_size = None

        if exact_size is not None and exact_size > 0:
            actual_size = min(exact_size, sig.max_size, initial_read)
            data = reader.read_at(offset, actual_size)
            return data, "size_field"

        # Strategy 2: Scan for footer
        if sig.footer is not None:
            footer_pos = self._scan_for_footer(
                reader, offset, sig.footer, sig.max_size
            )
            if footer_pos is not None:
                file_size = footer_pos + len(sig.footer)
                data = reader.read_at(offset, file_size)
                return data, "footer_scan"

        # Strategy 3: Extract max_size bytes (last resort)
        # Early validation: check the header chunk first before reading 50MB
        # This avoids massive I/O for false positive BMP/EXE matches
        try:
            if not sig.validate(header_data):
                return None, ""
        except Exception:
            pass

        # Also check null-byte ratio on the header chunk
        if header_data.count(0) / len(header_data) > 0.95:
            return None, ""

        actual_size = min(sig.max_size, initial_read)
        data = reader.read_at(offset, actual_size)
        return data, "max_size"

    def _scan_for_footer(
        self,
        reader: DiskReader,
        start_offset: int,
        footer: bytes,
        max_size: int,
    ) -> int | None:
        """Scan forward from start_offset looking for footer bytes.

        Args:
            reader: DiskReader instance.
            start_offset: Absolute byte offset where the file starts.
            footer: Footer byte sequence to search for.
            max_size: Maximum distance to scan.

        Returns:
            Offset relative to start_offset where footer was found, or None.
        """
        # Read in chunks for efficiency
        scan_chunk_size = 65536
        search_from = max(len(footer), 1)  # Don't find footer at position 0

        pos = search_from
        while pos < max_size:
            read_size = min(scan_chunk_size, max_size - pos + len(footer))
            data = reader.read_at(start_offset + pos, read_size)
            if not data:
                break

            idx = data.find(footer)
            if idx >= 0:
                return pos + idx

            # If we didn't read enough data to advance, we hit EOF
            if len(data) <= len(footer):
                break

            # Advance, but overlap by footer length to catch split footers
            pos += len(data) - len(footer)

        return None

    def _overlaps_existing(self, start: int, end: int) -> bool:
        """Check if a range overlaps any already-extracted file.

        Uses binary search on the sorted interval list for efficiency.

        Args:
            start: Start offset (inclusive).
            end: End offset (exclusive).

        Returns:
            True if any overlap exists.
        """
        if not self._extracted:
            return False

        # Find insertion point
        idx = bisect_left(self._extracted, (start,))

        # Check the interval at idx and idx-1
        for i in (idx - 1, idx):
            if 0 <= i < len(self._extracted):
                ex_start, ex_end = self._extracted[i]
                if start < ex_end and end > ex_start:
                    return True

        return False

    def _write_output(
        self,
        data: bytes,
        sig: BaseSignature,
        offset: int,
        session_dir: Path,
        is_valid: bool,
    ) -> str:
        """Write carved file and sidecar metadata to organized output dir.

        Output structure:
            session_dir/
              {category}/
                {extension}/
                  f{offset:012d}.{ext}
                  f{offset:012d}.meta.json
              partial/     ← files that failed validation

        Args:
            data: File bytes to write.
            sig: Signature that matched.
            offset: Absolute byte offset in source.
            session_dir: Session output directory.
            is_valid: Whether file passed validation.

        Returns:
            Path to the written file.
        """
        if is_valid:
            category_dir = session_dir / sig.category / sig.extension
        else:
            category_dir = session_dir / "partial" / sig.extension

        category_dir.mkdir(parents=True, exist_ok=True)

        filename = f"f{offset:012d}.{sig.extension}"
        file_path = category_dir / filename
        meta_path = category_dir / f"f{offset:012d}.meta.json"

        # Write file data
        with open(file_path, "wb") as f:
            f.write(data)

        # Write sidecar metadata
        meta = {
            "offset": offset,
            "size": len(data),
            "signature": sig.name,
            "extension": sig.extension,
            "category": sig.category,
            "valid": is_valid,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return str(file_path)
