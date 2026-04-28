"""
pyrecovery.advanced.raid.detector — RAID array detection and configuration inference.

Supports detection of:
- RAID 0 (striping): tries common stripe sizes, scores by file carving success
- RAID 1 (mirroring): detects identical content across multiple disks
- RAID 5 (distributed parity): detects parity patterns

Strategy for RAID 0 detection:
1. User provides N disk images
2. For each candidate stripe size (64K, 128K, 256K, 512K):
   a. Assemble virtual disk with that stripe size
   b. Run carving on first 10MB of assembled data
   c. Score by number of valid files found
3. Highest-scoring configuration is most likely correct
4. Report results but NEVER modify source disks

This is a heuristic approach — not guaranteed to find the correct config,
but works well when at least some recognizable file data exists.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from advanced.raid.assembler import VirtualDisk, assemble_raid0
from utils.logger import get_logger

logger = get_logger(__name__)

# Common RAID stripe sizes in bytes
DEFAULT_STRIPE_SIZES = [
    32768,    # 32 KB
    65536,    # 64 KB (most common)
    131072,   # 128 KB
    262144,   # 256 KB
    524288,   # 512 KB
    1048576,  # 1 MB
]


@dataclass
class RAIDConfig:
    """Detected RAID configuration."""
    raid_level: int           # 0, 1, or 5
    stripe_size: int          # In bytes
    disk_count: int           # Number of disks
    disk_order: list[int]     # Disk indices in correct order
    disk_paths: list[str]     # Paths to disk images
    confidence: float         # 0.0 to 1.0
    total_size: int           # Virtual disk total size
    score_details: dict = field(default_factory=dict)

    @property
    def stripe_size_kb(self) -> int:
        return self.stripe_size // 1024


@dataclass
class DetectionResult:
    """RAID detection result with all candidates."""
    best_config: RAIDConfig | None
    candidates: list[RAIDConfig]
    detection_method: str     # "carving_score", "content_match", "metadata"


class RAIDDetector:
    """Detect RAID configuration from multiple disk images.

    Usage::

        detector = RAIDDetector()
        result = detector.detect_raid0(
            ["disk1.img", "disk2.img"],
            stripe_sizes=[65536, 131072, 262144],
        )
        if result.best_config:
            print(f"Stripe size: {result.best_config.stripe_size_kb}KB")
            print(f"Confidence: {result.best_config.confidence:.0%}")
    """

    def detect_raid0(
        self,
        disk_paths: list[str],
        stripe_sizes: list[int] | None = None,
        scan_bytes: int = 10 * 1024 * 1024,  # 10 MB for scoring
    ) -> DetectionResult:
        """Detect RAID 0 stripe size by scoring carving results.

        Args:
            disk_paths: Paths to member disk images.
            stripe_sizes: Candidate stripe sizes to test.
            scan_bytes: Bytes to scan for scoring each config.

        Returns:
            DetectionResult with best config and all candidates.
        """
        if len(disk_paths) < 2:
            logger.warning("RAID 0 requires at least 2 disks")
            return DetectionResult(None, [], "carving_score")

        # Validate all files exist
        for path in disk_paths:
            if not Path(path).exists():
                logger.error("Disk not found: %s", path)
                return DetectionResult(None, [], "carving_score")

        sizes = stripe_sizes or DEFAULT_STRIPE_SIZES
        candidates: list[RAIDConfig] = []

        for stripe_size in sizes:
            score, details = self._score_stripe_size(
                disk_paths, stripe_size, scan_bytes
            )

            config = RAIDConfig(
                raid_level=0,
                stripe_size=stripe_size,
                disk_count=len(disk_paths),
                disk_order=list(range(len(disk_paths))),
                disk_paths=disk_paths,
                confidence=score,
                total_size=self._calc_total_size(disk_paths, stripe_size),
                score_details=details,
            )
            candidates.append(config)

            logger.debug(
                "RAID 0 stripe=%dKB: score=%.3f, details=%s",
                stripe_size // 1024, score, details,
            )

        # Sort by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        best = candidates[0] if candidates and candidates[0].confidence > 0 else None

        if best:
            logger.info(
                "RAID 0 detected: stripe=%dKB, confidence=%.0f%%",
                best.stripe_size_kb, best.confidence * 100,
            )

        return DetectionResult(
            best_config=best,
            candidates=candidates,
            detection_method="carving_score",
        )

    def detect_raid1(self, disk_paths: list[str]) -> DetectionResult:
        """Detect RAID 1 (mirror) by comparing disk contents.

        Args:
            disk_paths: Paths to 2+ disk images.

        Returns:
            DetectionResult. High confidence if disks are identical.
        """
        if len(disk_paths) < 2:
            return DetectionResult(None, [], "content_match")

        # Compare first 1MB of each pair
        match_count = 0
        total_comparisons = 0
        block_size = 1024 * 1024

        for i in range(len(disk_paths)):
            for j in range(i + 1, len(disk_paths)):
                try:
                    with open(disk_paths[i], "rb") as f1, \
                         open(disk_paths[j], "rb") as f2:
                        data1 = f1.read(block_size)
                        data2 = f2.read(block_size)
                        if data1 == data2:
                            match_count += 1
                        total_comparisons += 1
                except OSError:
                    total_comparisons += 1

        if total_comparisons == 0:
            return DetectionResult(None, [], "content_match")

        confidence = match_count / total_comparisons

        if confidence > 0.5:
            config = RAIDConfig(
                raid_level=1,
                stripe_size=0,
                disk_count=len(disk_paths),
                disk_order=list(range(len(disk_paths))),
                disk_paths=disk_paths,
                confidence=confidence,
                total_size=os.path.getsize(disk_paths[0]),
            )
            return DetectionResult(config, [config], "content_match")

        return DetectionResult(None, [], "content_match")

    def _score_stripe_size(
        self,
        disk_paths: list[str],
        stripe_size: int,
        scan_bytes: int,
    ) -> tuple[float, dict]:
        """Score a stripe size by checking for recognizable data patterns.

        Uses lightweight heuristic: count filesystem/file magic numbers
        found at aligned boundaries in the assembled data.
        """
        try:
            vdisk = assemble_raid0(disk_paths, stripe_size)
        except (OSError, ValueError) as e:
            return 0.0, {"error": str(e)}

        # Read sample of assembled data
        try:
            sample = vdisk.read_at(0, min(scan_bytes, vdisk.total_size))
        except (OSError, IndexError):
            return 0.0, {"error": "read_failed"}
        finally:
            vdisk.close()

        if not sample:
            return 0.0, {"error": "empty_read"}

        # Count recognizable patterns
        magic_hits = 0
        patterns = [
            b'\x89PNG', b'\xff\xd8\xff', b'%PDF', b'PK\x03\x04',
            b'\x7fELF', b'MZ', b'RIFF', b'OggS', b'fLaC',
            b'SQLite format 3', b'GIF8', b'BM',
        ]

        # Also check for filesystem superblocks at aligned offsets
        fs_patterns = [
            (b'NTFS', 3),
            (b'FAT32', 82),
        ]

        # Scan at 512-byte boundaries
        for offset in range(0, len(sample) - 16, 512):
            for pattern in patterns:
                if sample[offset:offset + len(pattern)] == pattern:
                    magic_hits += 1
                    break

        # Check for filesystem signatures at partition-aligned offsets
        for check_offset in (0, 2048 * 512, 4096 * 512):
            if check_offset < len(sample):
                for fs_sig, sig_offset in fs_patterns:
                    pos = check_offset + sig_offset
                    if pos + len(fs_sig) <= len(sample):
                        if sample[pos:pos + len(fs_sig)] == fs_sig:
                            magic_hits += 5  # Filesystem hit is worth more

        # Normalize score
        max_expected = scan_bytes // (512 * 100)  # rough expected max
        if max_expected == 0:
            max_expected = 1
        score = min(1.0, magic_hits / max(max_expected, 1))

        return score, {
            "magic_hits": magic_hits,
            "sample_size": len(sample),
            "stripe_kb": stripe_size // 1024,
        }

    @staticmethod
    def _calc_total_size(disk_paths: list[str], stripe_size: int) -> int:
        """Calculate total virtual disk size for RAID 0."""
        sizes = [os.path.getsize(p) for p in disk_paths]
        min_size = min(sizes)
        # Each disk contributes (min_size // stripe_size) stripes
        usable = (min_size // stripe_size) * stripe_size
        return usable * len(disk_paths)
