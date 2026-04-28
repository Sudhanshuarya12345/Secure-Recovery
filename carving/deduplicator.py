"""
pyrecovery.carving.deduplicator — Hash-based duplicate file suppression.

During carving, the same file content frequently appears at multiple offsets:
- Filesystem stored a backup copy
- File existed in multiple directories
- Slack space contains old copy of an active file

Without deduplication, output would be cluttered with identical files.

Strategy:
- Phase 1: SHA256 of first 64 KB (fast reject for different files)
- Phase 2: Full SHA256 only when partial hashes match (avoids hashing large files)
"""

from __future__ import annotations

import hashlib

from utils.logger import get_logger

logger = get_logger(__name__)

# Size of the partial hash window (first 64 KB)
_PARTIAL_HASH_SIZE = 65536


class Deduplicator:
    """Hash-based duplicate file suppression using two-phase hashing.

    Phase 1: Hash first 64 KB → fast reject for clearly different files.
    Phase 2: Hash full file only when partial hash matches → confirms duplicate.

    Usage::

        dedup = Deduplicator()
        if dedup.is_duplicate(carved_data):
            continue  # Skip this file
        dedup.mark_seen(carved_data)  # Record for future checks
    """

    def __init__(self) -> None:
        self._seen_partial: dict[str, set[str]] = {}  # partial_hash → {full_hashes}
        self._seen_full: set[str] = set()
        self._duplicate_count = 0
        self._unique_count = 0

    def _partial_hash(self, data: bytes) -> str:
        """Compute SHA256 of the first 64 KB + total size.

        Including size prevents false matches between files that share
        the same 64 KB prefix but differ in length.
        """
        prefix = data[:_PARTIAL_HASH_SIZE]
        h = hashlib.sha256(prefix)
        h.update(len(data).to_bytes(8, "little"))
        return h.hexdigest()

    def _full_hash(self, data: bytes) -> str:
        """Compute SHA256 of the entire file content."""
        return hashlib.sha256(data).hexdigest()

    def is_duplicate(self, data: bytes) -> bool:
        """Check if this content has been seen before.

        Args:
            data: Complete carved file bytes.

        Returns:
            True if a file with identical content was already processed.
        """
        partial = self._partial_hash(data)

        if partial not in self._seen_partial:
            return False

        # Partial hash matches — need full hash to confirm
        full = self._full_hash(data)
        return full in self._seen_full

    def mark_seen(self, data: bytes) -> str:
        """Mark content as seen and return its SHA256 hash.

        Args:
            data: Complete carved file bytes.

        Returns:
            Full SHA256 hex digest of the data.
        """
        partial = self._partial_hash(data)
        full = self._full_hash(data)

        if full in self._seen_full:
            self._duplicate_count += 1
        else:
            self._unique_count += 1
            self._seen_full.add(full)

        if partial not in self._seen_partial:
            self._seen_partial[partial] = set()
        self._seen_partial[partial].add(full)

        return full

    def check_and_mark(self, data: bytes) -> tuple[bool, str]:
        """Combined check + mark in one call. Returns (is_duplicate, sha256).

        Args:
            data: Complete carved file bytes.

        Returns:
            Tuple of (is_duplicate, sha256_hex_digest).
        """
        is_dup = self.is_duplicate(data)
        sha256 = self.mark_seen(data)
        if is_dup:
            self._duplicate_count += 1
            self._unique_count -= 1  # Undo the increment from mark_seen
        return is_dup, sha256

    @property
    def duplicate_count(self) -> int:
        """Number of duplicate files suppressed."""
        return self._duplicate_count

    @property
    def unique_count(self) -> int:
        """Number of unique files processed."""
        return self._unique_count

    def __repr__(self) -> str:
        return (
            f"Deduplicator(unique={self._unique_count}, "
            f"duplicates={self._duplicate_count})"
        )
