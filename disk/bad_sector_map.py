"""
pyrecovery.disk.bad_sector_map — Track unreadable sectors during disk operations.

In real forensic recovery, damaged media commonly has scattered unreadable sectors.
Rather than crashing on the first I/O error, we log the bad sector and continue.
This map is persisted to JSON for the forensic report and can be reloaded to skip
known-bad regions on subsequent passes.

Design decisions:
- Uses dict[int, BadSectorInfo] internally: O(1) lookup by LBA, preserves metadata
- Save/load to JSON for interoperability with reporting tools
- merge() supports combining maps from multiple scan passes
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class BadSectorInfo:
    """Metadata for a single unreadable sector."""

    lba: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error_type: str = "IOError"
    context: str = ""


class BadSectorMap:
    """Track unreadable LBA addresses encountered during disk operations.

    Provides O(1) lookup, sorted export, JSON persistence, and merge capability.
    """

    def __init__(self) -> None:
        self._sectors: dict[int, BadSectorInfo] = {}

    def mark_bad(
        self, lba: int, error_type: str = "IOError", context: str = ""
    ) -> None:
        """Record an unreadable sector.

        Args:
            lba: Logical block address of the bad sector.
            error_type: Exception class name that caused the failure.
            context: Additional error detail (e.g., the error message).

        If the LBA was already marked, the entry is updated with the new timestamp.
        """
        info = BadSectorInfo(
            lba=lba,
            error_type=error_type,
            context=context,
        )
        self._sectors[lba] = info
        logger.warning(
            "Bad sector at LBA %d: %s — %s", lba, error_type, context or "no detail"
        )

    def is_bad(self, lba: int) -> bool:
        """Check if a sector is known-bad. O(1) lookup.

        Args:
            lba: Logical block address to check.

        Returns:
            True if the sector was previously marked as bad.
        """
        return lba in self._sectors

    def get_all(self) -> list[int]:
        """Return sorted list of all bad LBA addresses.

        Returns:
            Sorted list of integers.
        """
        return sorted(self._sectors.keys())

    @property
    def count(self) -> int:
        """Number of bad sectors recorded."""
        return len(self._sectors)

    def get_info(self, lba: int) -> BadSectorInfo | None:
        """Get full metadata for a specific bad sector.

        Args:
            lba: Logical block address.

        Returns:
            BadSectorInfo if sector is known-bad, None otherwise.
        """
        return self._sectors.get(lba)

    def save(self, path: str) -> None:
        """Persist the bad sector map to a JSON file.

        Args:
            path: Output file path. Parent directories are created if needed.

        File format::

            {
                "total_bad_sectors": 3,
                "generated_at": "2026-04-26T04:45:50+00:00",
                "bad_sectors": [
                    {"lba": 500, "timestamp": "...", "error_type": "IOError", "context": "..."},
                    ...
                ]
            }
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = {
            "total_bad_sectors": self.count,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "bad_sectors": [asdict(self._sectors[lba]) for lba in self.get_all()],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info("Bad sector map saved to %s (%d sectors)", path, self.count)

    @classmethod
    def load(cls, path: str) -> "BadSectorMap":
        """Reload a previously saved bad sector map from JSON.

        Args:
            path: Path to the JSON file.

        Returns:
            A new BadSectorMap populated with the saved data.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            json.JSONDecodeError: If the file is malformed.
        """
        bsm = cls()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for entry in data.get("bad_sectors", []):
            info = BadSectorInfo(
                lba=entry["lba"],
                timestamp=entry.get("timestamp", ""),
                error_type=entry.get("error_type", "IOError"),
                context=entry.get("context", ""),
            )
            bsm._sectors[info.lba] = info

        logger.info("Bad sector map loaded from %s (%d sectors)", path, bsm.count)
        return bsm

    def merge(self, other: "BadSectorMap") -> None:
        """Merge another BadSectorMap into this one.

        If both maps contain the same LBA, the entry with the later timestamp wins.

        Args:
            other: Another BadSectorMap to merge in.
        """
        for lba, info in other._sectors.items():
            existing = self._sectors.get(lba)
            if existing is None or info.timestamp > existing.timestamp:
                self._sectors[lba] = info

    def __len__(self) -> int:
        return self.count

    def __contains__(self, lba: int) -> bool:
        return self.is_bad(lba)

    def __repr__(self) -> str:
        return f"BadSectorMap(count={self.count})"
