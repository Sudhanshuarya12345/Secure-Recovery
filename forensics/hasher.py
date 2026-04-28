"""
pyrecovery.forensics.hasher — Forensic-grade file hashing.

Produces both MD5 (for legacy compatibility / NSRL database lookups)
and SHA256 (for integrity verification) simultaneously in a single pass.

Design:
- Never loads entire file into memory (streaming with 64KB blocks)
- Dual-hash in single pass (reads data once, feeds to both hashers)
- Can hash individual files, entire directories, or raw byte buffers
- Outputs CSV manifests compatible with forensic tools (FTK, EnCase, Autopsy)
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from utils.logger import get_logger

logger = get_logger(__name__)

BLOCK_SIZE = 65536  # 64 KB — optimal for disk I/O


@dataclass
class HashResult:
    """Hash result for a single file."""
    path: str
    md5: str
    sha256: str
    size: int

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "md5": self.md5,
            "sha256": self.sha256,
            "size": self.size,
        }


class ForensicHasher:
    """Stream-based dual MD5+SHA256 file hasher.

    Usage::

        hasher = ForensicHasher()

        # Single file
        result = hasher.hash_file("evidence.img")
        print(result.sha256)

        # Entire directory
        results = hasher.hash_directory("./recovered/")
        hasher.write_manifest(results, "manifest.csv")
    """

    @staticmethod
    def hash_bytes(data: bytes) -> HashResult:
        """Hash raw bytes, returning dual MD5+SHA256.

        Args:
            data: Bytes to hash.

        Returns:
            HashResult with both hash digests.
        """
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return HashResult(path="<bytes>", md5=md5, sha256=sha256, size=len(data))

    @staticmethod
    def hash_file(path: str, block_size: int = BLOCK_SIZE) -> HashResult:
        """Hash a file using streaming dual-hash (never loads full file).

        Args:
            path: Path to file.
            block_size: Read buffer size in bytes.

        Returns:
            HashResult with MD5, SHA256, and file size.
        """
        md5_h = hashlib.md5()
        sha256_h = hashlib.sha256()
        total_size = 0

        with open(path, "rb") as f:
            while True:
                chunk = f.read(block_size)
                if not chunk:
                    break
                md5_h.update(chunk)
                sha256_h.update(chunk)
                total_size += len(chunk)

        return HashResult(
            path=path,
            md5=md5_h.hexdigest(),
            sha256=sha256_h.hexdigest(),
            size=total_size,
        )

    @staticmethod
    def hash_file_streaming(
        path: str, block_size: int = BLOCK_SIZE
    ) -> Iterator[tuple[int, int]]:
        """Hash a file with progress yielding.

        Yields:
            (bytes_processed, total_bytes) tuples for progress tracking.
        """
        total = Path(path).stat().st_size
        md5_h = hashlib.md5()
        sha256_h = hashlib.sha256()
        processed = 0

        with open(path, "rb") as f:
            while True:
                chunk = f.read(block_size)
                if not chunk:
                    break
                md5_h.update(chunk)
                sha256_h.update(chunk)
                processed += len(chunk)
                yield processed, total

    def hash_directory(
        self,
        dir_path: str,
        recursive: bool = True,
        skip_patterns: list[str] | None = None,
    ) -> list[HashResult]:
        """Hash all files in a directory.

        Args:
            dir_path: Root directory path.
            recursive: Recurse into subdirectories.
            skip_patterns: Glob patterns to skip (e.g., ["*.log", "*.tmp"]).

        Returns:
            List of HashResult for each file.
        """
        root = Path(dir_path)
        if not root.is_dir():
            logger.warning("Not a directory: %s", dir_path)
            return []

        skip = set(skip_patterns or [])
        results: list[HashResult] = []
        pattern = "**/*" if recursive else "*"

        for file_path in sorted(root.glob(pattern)):
            if not file_path.is_file():
                continue
            if any(file_path.match(p) for p in skip):
                continue

            try:
                result = self.hash_file(str(file_path))
                # Use relative path for portability
                result.path = str(file_path.relative_to(root))
                results.append(result)
            except (OSError, IOError) as e:
                logger.warning("Could not hash %s: %s", file_path, e)

        logger.info("Hashed %d files in %s", len(results), dir_path)
        return results

    @staticmethod
    def write_manifest_csv(results: list[HashResult], output_path: str) -> None:
        """Write hash results to CSV manifest file.

        Format compatible with forensic tools (Autopsy, FTK):
        path, md5, sha256, size
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["path", "md5", "sha256", "size_bytes"])
            for r in results:
                writer.writerow([r.path, r.md5, r.sha256, r.size])

        logger.info("Hash manifest written: %s (%d entries)", output_path, len(results))

    @staticmethod
    def write_manifest_json(results: list[HashResult], output_path: str) -> None:
        """Write hash results to JSON manifest."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        data = {
            "file_count": len(results),
            "files": [r.to_dict() for r in results],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def verify_manifest(manifest_path: str) -> tuple[bool, list[str]]:
        """Verify files against a previously generated manifest.

        Args:
            manifest_path: Path to CSV or JSON manifest.

        Returns:
            Tuple of (all_valid, list_of_errors).
        """
        errors: list[str] = []
        manifest_file = Path(manifest_path)

        if manifest_file.suffix == ".json":
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("files", [])
        else:
            entries = []
            with open(manifest_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entries.append(row)

        for entry in entries:
            path = entry.get("path", "")
            if not Path(path).exists():
                errors.append(f"Missing file: {path}")
                continue

            result = ForensicHasher.hash_file(path)
            if result.sha256 != entry.get("sha256", ""):
                errors.append(
                    f"SHA256 mismatch for {path}: "
                    f"expected={entry.get('sha256', '')[:16]}..., "
                    f"computed={result.sha256[:16]}..."
                )

        return len(errors) == 0, errors
