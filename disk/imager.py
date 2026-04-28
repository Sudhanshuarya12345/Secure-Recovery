"""
pyrecovery.disk.imager — Forensic disk imaging with integrity verification.

Creates byte-exact copies of source media with cryptographic verification.
This is the standard first step in any forensic investigation: image the
source, then work exclusively from the image.

Forensic imaging requirements:
1. Byte-exact copy (including free space, slack space, unallocated areas)
2. SHA256 hash of the entire image for tamper detection
3. Block-level hashes (every 64 MB) for partial verification and corruption locating
4. Bad sector handling: zero-fill and log, never crash
5. The ONLY module in PyRecovery that writes to disk (the output image file)

Design: Uses DiskReader for source access (inherits write-blocking guarantee).
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
from utils.logger import get_logger
from utils.size_formatter import format_size

logger = get_logger(__name__)


@dataclass
class ImageResult:
    """Result of a forensic imaging operation."""

    dest_path: str
    total_bytes: int
    sha256: str
    duration_seconds: float
    bad_sector_count: int
    block_hashes: list[dict] = field(default_factory=list)
    throughput_mbps: float = 0.0

    def __post_init__(self) -> None:
        if self.duration_seconds > 0:
            self.throughput_mbps = round(
                (self.total_bytes / (1024 * 1024)) / self.duration_seconds, 1
            )


@dataclass
class VerifyResult:
    """Result of image integrity verification."""

    valid: bool
    total_blocks: int
    failed_blocks: list[int] = field(default_factory=list)
    computed_sha256: str = ""
    expected_sha256: str = ""
    message: str = ""


class DiskImager:
    """Create and verify forensic disk images.

    A forensic image is a bit-for-bit copy of the source with cryptographic
    integrity guarantees. The sidecar ``.hashlog`` file records block-level
    SHA256 hashes for post-hoc verification and corruption locating.

    Example::

        result = DiskImager.create_image(
            source="/dev/sdb",
            dest_path="evidence.img",
            progress_callback=lambda cur, total: print(f"{cur}/{total}")
        )
        print(f"Image SHA256: {result.sha256}")

        verify = DiskImager.verify_image("evidence.img")
        assert verify.valid, f"Verification failed: {verify.message}"
    """

    @staticmethod
    def create_image(
        source: str,
        dest_path: str,
        chunk_size: int = 1_048_576,
        hash_block_size: int = 67_108_864,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> ImageResult:
        """Create a forensic disk image with integrity hashes.

        Args:
            source: Path to the source device or image file.
            dest_path: Path for the output image file.
            chunk_size: Read/write chunk size in bytes (default: 1 MB).
            hash_block_size: Interval for block-level hashes (default: 64 MB).
            progress_callback: Called with (bytes_read, total_bytes) for progress.

        Returns:
            ImageResult with path, size, hash, timing, and block hashes.

        Process:
            1. Open source via DiskReader (read-only + write-blocked)
            2. Create output file (the ONLY write operation in PyRecovery)
            3. Read in chunk_size blocks, write to output
            4. Compute running SHA256 of entire source stream
            5. Every hash_block_size bytes: record block SHA256 in sidecar
            6. Write sidecar {dest_path}.hashlog with all block hashes
        """
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        hashlog_path = str(dest) + ".hashlog"

        start_time = time.monotonic()
        overall_hasher = hashlib.sha256()
        block_hasher = hashlib.sha256()
        block_hashes: list[dict] = []

        bytes_read = 0
        block_index = 0
        block_bytes = 0

        logger.info(
            "Starting forensic imaging: %s → %s (chunk=%s, hash_block=%s)",
            source, dest_path, format_size(chunk_size), format_size(hash_block_size),
        )

        with DiskReader(source) as reader:
            total_size = reader.get_disk_size()

            with open(dest_path, "wb") as out:
                while bytes_read < total_size:
                    remaining = total_size - bytes_read
                    read_size = min(chunk_size, remaining)

                    data = reader.read_at(bytes_read, read_size)

                    out.write(data)
                    overall_hasher.update(data)
                    block_hasher.update(data)

                    bytes_read += len(data)
                    block_bytes += len(data)

                    # Block-level hash checkpoint
                    if block_bytes >= hash_block_size:
                        block_hashes.append({
                            "block": block_index,
                            "offset": block_index * hash_block_size,
                            "size": block_bytes,
                            "sha256": block_hasher.hexdigest(),
                        })
                        block_index += 1
                        block_bytes = 0
                        block_hasher = hashlib.sha256()

                    if progress_callback:
                        progress_callback(bytes_read, total_size)

                # Final partial block
                if block_bytes > 0:
                    block_hashes.append({
                        "block": block_index,
                        "offset": block_index * hash_block_size,
                        "size": block_bytes,
                        "sha256": block_hasher.hexdigest(),
                    })

            bad_count = reader.bad_sectors.count

        duration = time.monotonic() - start_time
        overall_sha256 = overall_hasher.hexdigest()

        # Write sidecar hashlog
        hashlog = {
            "source": source,
            "image": dest_path,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "total_bytes": bytes_read,
            "overall_sha256": overall_sha256,
            "hash_block_size": hash_block_size,
            "block_hashes": block_hashes,
        }
        with open(hashlog_path, "w", encoding="utf-8") as f:
            json.dump(hashlog, f, indent=2)

        result = ImageResult(
            dest_path=dest_path,
            total_bytes=bytes_read,
            sha256=overall_sha256,
            duration_seconds=round(duration, 2),
            bad_sector_count=bad_count,
            block_hashes=block_hashes,
        )

        logger.info(
            "Imaging complete: %s, SHA256=%s, %.1f MB/s, bad_sectors=%d",
            format_size(bytes_read),
            overall_sha256[:16] + "...",
            result.throughput_mbps,
            bad_count,
        )

        return result

    @staticmethod
    def verify_image(
        image_path: str, hashlog_path: str | None = None
    ) -> VerifyResult:
        """Verify a disk image's integrity against its hashlog.

        Args:
            image_path: Path to the image file.
            hashlog_path: Path to the ``.hashlog`` sidecar. If None, tries
                          ``{image_path}.hashlog``.

        Returns:
            VerifyResult indicating pass/fail with details.
        """
        if hashlog_path is None:
            hashlog_path = image_path + ".hashlog"

        if not Path(hashlog_path).exists():
            return VerifyResult(
                valid=False,
                total_blocks=0,
                message=f"Hashlog not found: {hashlog_path}",
            )

        with open(hashlog_path, "r", encoding="utf-8") as f:
            hashlog = json.load(f)

        expected_sha256 = hashlog.get("overall_sha256", "")
        hash_block_size = hashlog.get("hash_block_size", 67_108_864)
        expected_blocks = hashlog.get("block_hashes", [])

        overall_hasher = hashlib.sha256()
        block_hasher = hashlib.sha256()
        failed_blocks: list[int] = []
        block_index = 0
        block_bytes = 0

        chunk_size = 1_048_576  # 1 MB read chunks
        bytes_read = 0

        logger.info("Verifying image: %s", image_path)

        with open(image_path, "rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break

                overall_hasher.update(data)
                block_hasher.update(data)
                bytes_read += len(data)
                block_bytes += len(data)

                if block_bytes >= hash_block_size:
                    computed = block_hasher.hexdigest()
                    if block_index < len(expected_blocks):
                        expected = expected_blocks[block_index].get("sha256", "")
                        if computed != expected:
                            failed_blocks.append(block_index)
                            logger.warning(
                                "Block %d hash mismatch: expected=%s, computed=%s",
                                block_index, expected[:16], computed[:16],
                            )
                    block_index += 1
                    block_bytes = 0
                    block_hasher = hashlib.sha256()

        # Final partial block
        if block_bytes > 0:
            computed = block_hasher.hexdigest()
            if block_index < len(expected_blocks):
                expected = expected_blocks[block_index].get("sha256", "")
                if computed != expected:
                    failed_blocks.append(block_index)
            block_index += 1

        computed_sha256 = overall_hasher.hexdigest()
        is_valid = computed_sha256 == expected_sha256 and len(failed_blocks) == 0

        result = VerifyResult(
            valid=is_valid,
            total_blocks=block_index,
            failed_blocks=failed_blocks,
            computed_sha256=computed_sha256,
            expected_sha256=expected_sha256,
            message="Verification passed" if is_valid else (
                f"FAILED: {len(failed_blocks)} block(s) corrupted, "
                f"overall hash {'matches' if computed_sha256 == expected_sha256 else 'MISMATCH'}"
            ),
        )

        logger.info("Verification result: %s", result.message)
        return result
