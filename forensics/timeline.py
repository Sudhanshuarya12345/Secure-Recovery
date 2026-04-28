"""
pyrecovery.forensics.timeline — Forensic timeline analysis.

Collects timestamps from filesystem metadata (create/modify/access/delete),
normalizes to UTC, and provides anomaly detection.

Anomaly types detected:
- Future timestamps (beyond current time)
- Pre-epoch timestamps (before 1970)
- Impossible sequences (modified before created)
- Timestamp clustering (mass operations suggesting automated tools)
- Timezone inconsistencies
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TimelineEvent:
    """Single timestamped event."""
    timestamp: datetime
    event_type: str       # "created", "modified", "accessed", "deleted"
    source: str           # "fat32", "ntfs", "ext4", "carved"
    file_path: str        # File this event relates to
    details: str = ""     # Additional context
    partition: int = -1   # Partition index

    @property
    def timestamp_iso(self) -> str:
        return self.timestamp.isoformat()

    @property
    def unix_epoch(self) -> float:
        return self.timestamp.timestamp()


@dataclass
class TimelineAnomaly:
    """Detected timestamp anomaly."""
    anomaly_type: str       # "future", "pre_epoch", "impossible_sequence", "cluster"
    severity: str           # "low", "medium", "high"
    description: str
    events: list[TimelineEvent] = field(default_factory=list)


class ForensicTimeline:
    """Forensic timeline: collect, normalize, analyze, and export timestamps.

    Usage::

        tl = ForensicTimeline()

        # Add events from filesystem parsing
        tl.add_event(datetime(...), "created", "fat32", "/photos/img001.jpg")
        tl.add_event(datetime(...), "modified", "fat32", "/photos/img001.jpg")
        tl.add_event(datetime(...), "deleted", "fat32", "/photos/img001.jpg")

        # Analyze
        anomalies = tl.detect_anomalies()
        for a in anomalies:
            print(f"[{a.severity}] {a.anomaly_type}: {a.description}")

        # Export
        tl.export_csv("timeline.csv")
        tl.export_json("timeline.json")
    """

    def __init__(self) -> None:
        self._events: list[TimelineEvent] = []

    def add_event(
        self,
        timestamp: datetime,
        event_type: str,
        source: str,
        file_path: str,
        details: str = "",
        partition: int = -1,
    ) -> None:
        """Add a timestamped event to the timeline.

        Timestamps are normalized to UTC if timezone-naive.
        """
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        self._events.append(TimelineEvent(
            timestamp=timestamp,
            event_type=event_type,
            source=source,
            file_path=file_path,
            details=details,
            partition=partition,
        ))

    def add_from_fat32_entry(
        self, entry, partition: int = -1
    ) -> None:
        """Add events from a FAT32 directory entry (DOS timestamps)."""
        path = getattr(entry, "path", "") or getattr(entry, "full_name", "")

        if hasattr(entry, "create_time") and entry.create_time:
            ts = self._dos_timestamp_to_datetime(entry.create_time)
            if ts:
                self.add_event(ts, "created", "fat32", path, partition=partition)

        if hasattr(entry, "modify_time") and entry.modify_time:
            ts = self._dos_timestamp_to_datetime(entry.modify_time)
            if ts:
                self.add_event(ts, "modified", "fat32", path, partition=partition)

        if hasattr(entry, "is_deleted") and entry.is_deleted:
            self.add_event(
                datetime.now(timezone.utc), "deleted", "fat32", path,
                details="Deletion time approximated", partition=partition,
            )

    def add_from_ntfs_entry(
        self, entry, partition: int = -1
    ) -> None:
        """Add events from an NTFS MFT entry (Windows FILETIME)."""
        path = getattr(entry, "path", "") or getattr(entry, "filename", "")

        if hasattr(entry, "create_time") and entry.create_time:
            ts = self._filetime_to_datetime(entry.create_time)
            if ts:
                self.add_event(ts, "created", "ntfs", path, partition=partition)

        if hasattr(entry, "modify_time") and entry.modify_time:
            ts = self._filetime_to_datetime(entry.modify_time)
            if ts:
                self.add_event(ts, "modified", "ntfs", path, partition=partition)

        if hasattr(entry, "is_deleted") and entry.is_deleted:
            self.add_event(
                datetime.now(timezone.utc), "deleted", "ntfs", path,
                details="MFT record not in use", partition=partition,
            )

    def add_from_ext_inode(
        self, inode, partition: int = -1
    ) -> None:
        """Add events from an EXT inode (Unix timestamps)."""
        path = getattr(inode, "path", "") or getattr(inode, "filename", "")

        if hasattr(inode, "create_time") and inode.create_time:
            ts = self._unix_to_datetime(inode.create_time)
            if ts:
                self.add_event(ts, "created", "ext", path, partition=partition)

        if hasattr(inode, "modify_time") and inode.modify_time:
            ts = self._unix_to_datetime(inode.modify_time)
            if ts:
                self.add_event(ts, "modified", "ext", path, partition=partition)

        if hasattr(inode, "access_time") and inode.access_time:
            ts = self._unix_to_datetime(inode.access_time)
            if ts:
                self.add_event(ts, "accessed", "ext", path, partition=partition)

        if hasattr(inode, "delete_time") and inode.delete_time:
            ts = self._unix_to_datetime(inode.delete_time)
            if ts:
                self.add_event(ts, "deleted", "ext", path, partition=partition)

    def get_sorted_events(self) -> list[TimelineEvent]:
        """Return all events sorted chronologically."""
        return sorted(self._events, key=lambda e: e.timestamp)

    def detect_anomalies(self) -> list[TimelineAnomaly]:
        """Analyze timeline for forensic anomalies.

        Detects:
        1. Future timestamps (> current time + 1 day buffer)
        2. Pre-epoch timestamps (before 1970-01-01)
        3. Impossible sequences (modified/accessed before created)
        4. Timestamp clustering (many events in < 1 second)
        """
        anomalies: list[TimelineAnomaly] = []
        now = datetime.now(timezone.utc)
        future_threshold = now + timedelta(days=1)
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        pre_dos_epoch = datetime(1980, 1, 1, tzinfo=timezone.utc)

        # Group events by file for sequence analysis
        by_file: dict[str, list[TimelineEvent]] = {}
        for e in self._events:
            by_file.setdefault(e.file_path, []).append(e)

        # 1. Future timestamps
        future_events = [e for e in self._events if e.timestamp > future_threshold]
        if future_events:
            anomalies.append(TimelineAnomaly(
                anomaly_type="future_timestamp",
                severity="high",
                description=f"{len(future_events)} event(s) have timestamps in the future",
                events=future_events,
            ))

        # 2. Pre-epoch timestamps
        pre_epoch_events = [e for e in self._events if e.timestamp < epoch]
        if pre_epoch_events:
            anomalies.append(TimelineAnomaly(
                anomaly_type="pre_epoch",
                severity="medium",
                description=f"{len(pre_epoch_events)} event(s) have timestamps before 1970",
                events=pre_epoch_events,
            ))

        # Pre-DOS epoch (for FAT timestamps)
        pre_dos = [e for e in self._events
                   if e.source == "fat32" and epoch <= e.timestamp < pre_dos_epoch]
        if pre_dos:
            anomalies.append(TimelineAnomaly(
                anomaly_type="pre_dos_epoch",
                severity="low",
                description=f"{len(pre_dos)} FAT32 event(s) before 1980 (impossible for FAT)",
                events=pre_dos,
            ))

        # 3. Impossible sequences (modified before created)
        for path, events in by_file.items():
            created = [e for e in events if e.event_type == "created"]
            modified = [e for e in events if e.event_type == "modified"]

            if created and modified:
                earliest_create = min(e.timestamp for e in created)
                earliest_modify = min(e.timestamp for e in modified)
                if earliest_modify < earliest_create:
                    anomalies.append(TimelineAnomaly(
                        anomaly_type="impossible_sequence",
                        severity="medium",
                        description=(
                            f"File '{path}' modified before created "
                            f"({earliest_modify.isoformat()} < {earliest_create.isoformat()})"
                        ),
                        events=created + modified,
                    ))

        # 4. Timestamp clustering (> 50 events in same second)
        second_counts: Counter[str] = Counter()
        for e in self._events:
            key = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            second_counts[key] += 1

        for ts_key, count in second_counts.items():
            if count > 50:
                cluster_events = [
                    e for e in self._events
                    if e.timestamp.strftime("%Y-%m-%d %H:%M:%S") == ts_key
                ]
                anomalies.append(TimelineAnomaly(
                    anomaly_type="timestamp_cluster",
                    severity="low",
                    description=(
                        f"{count} events at {ts_key} — possible automated operation"
                    ),
                    events=cluster_events[:10],  # Cap for readability
                ))

        logger.info(
            "Timeline analysis: %d events, %d anomalies detected",
            len(self._events), len(anomalies),
        )
        return anomalies

    @property
    def event_count(self) -> int:
        return len(self._events)

    def export_csv(self, output_path: str) -> None:
        """Export timeline to CSV (Autopsy-compatible format)."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        events = self.get_sorted_events()

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp_utc", "event_type", "source",
                "file_path", "details", "partition",
            ])
            for e in events:
                writer.writerow([
                    e.timestamp_iso, e.event_type, e.source,
                    e.file_path, e.details, e.partition,
                ])

        logger.info("Timeline exported to CSV: %s (%d events)", output_path, len(events))

    def export_json(self, output_path: str) -> None:
        """Export timeline to JSON."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        events = self.get_sorted_events()

        data = {
            "event_count": len(events),
            "events": [
                {
                    "timestamp": e.timestamp_iso,
                    "event_type": e.event_type,
                    "source": e.source,
                    "file_path": e.file_path,
                    "details": e.details,
                    "partition": e.partition,
                }
                for e in events
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # ── Timestamp converters ────────────────────────────────────────

    @staticmethod
    def _dos_timestamp_to_datetime(raw: int) -> datetime | None:
        """Convert packed DOS date+time (4 bytes) to datetime."""
        try:
            time_part = raw & 0xFFFF
            date_part = (raw >> 16) & 0xFFFF

            if date_part == 0:
                return None

            day = date_part & 0x1F
            month = (date_part >> 5) & 0x0F
            year = ((date_part >> 9) & 0x7F) + 1980

            second = (time_part & 0x1F) * 2
            minute = (time_part >> 5) & 0x3F
            hour = (time_part >> 11) & 0x1F

            return datetime(year, month, day, hour, minute, second,
                            tzinfo=timezone.utc)
        except (ValueError, OverflowError):
            return None

    @staticmethod
    def _filetime_to_datetime(ft: int) -> datetime | None:
        """Convert Windows FILETIME (100ns since 1601-01-01) to datetime."""
        if ft == 0:
            return None
        try:
            # FILETIME epoch: 1601-01-01
            epoch_delta = 116444736000000000  # 100ns intervals from 1601 to 1970
            unix_us = (ft - epoch_delta) // 10  # Convert to microseconds
            return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=unix_us)
        except (ValueError, OverflowError, OSError):
            return None

    @staticmethod
    def _unix_to_datetime(ts: int) -> datetime | None:
        """Convert Unix timestamp to datetime."""
        if ts == 0:
            return None
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
