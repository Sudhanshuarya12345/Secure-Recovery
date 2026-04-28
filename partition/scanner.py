"""
pyrecovery.partition.scanner — Automatic partition detection and filesystem identification.

Combines MBR and GPT parsers with filesystem superblock probing to create
a unified view of all partitions on a disk, including:
- Detected partition scheme (MBR, GPT, or none)
- Each partition's filesystem type (from superblock magic)
- Unallocated gaps between partitions (where deleted files may lurk)

The "lost partition scanner" searches unallocated space for filesystem
superblocks that may indicate deleted or corrupted partitions.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from disk.reader import DiskReader
from partition.mbr import MBRParser, MBRPartitionEntry, PARTITION_TYPES
from partition.gpt import GPTParser, GPTPartitionEntry
from utils.logger import get_logger
from utils.size_formatter import format_size

logger = get_logger(__name__)


@dataclass
class DetectedPartition:
    """Unified partition info combining table entry + filesystem probe."""

    index: int
    scheme: str               # "mbr", "gpt", or "found" (for lost partitions)
    lba_start: int
    lba_end: int
    size_bytes: int
    type_name: str            # From partition table
    fs_type: str              # From superblock probe: "fat32", "ntfs", "ext4", etc.
    label: str = ""           # Volume label if found
    bootable: bool = False
    # Source entry for detailed access
    mbr_entry: MBRPartitionEntry | None = None
    gpt_entry: GPTPartitionEntry | None = None


@dataclass
class ScanResult:
    """Full partition scan result."""

    scheme: str               # "mbr", "gpt", "none"
    partitions: list[DetectedPartition]
    unallocated: list[tuple[int, int]]  # (start_lba, end_lba) gaps
    disk_size: int = 0
    disk_guid: str = ""       # GPT disk GUID


class PartitionScanner:
    """Scan a disk for partition tables and identify filesystems.

    Usage::

        scanner = PartitionScanner()
        result = scanner.scan(reader)
        for p in result.partitions:
            print(f"{p.type_name} at LBA {p.lba_start}, fs={p.fs_type}")
    """

    def __init__(self) -> None:
        self._mbr_parser = MBRParser()
        self._gpt_parser = GPTParser()

    def scan(self, reader: DiskReader) -> ScanResult:
        """Scan the disk for partitions and identify filesystems.

        Strategy:
        1. Check if LBA 0 is actually a raw filesystem (e.g. logical drive like E:)
        2. Read LBA 0 and parse as MBR
        3. If MBR contains protective entry (0xEE) → parse GPT at LBA 1
        4. For each partition → probe for filesystem superblock
        5. Find unallocated gaps between partitions

        Args:
            reader: DiskReader for the source.

        Returns:
            ScanResult with all partitions and unallocated regions.
        """
        total_sectors = reader.get_sector_count()
        disk_size = reader.get_disk_size()

        # Step 1: Check if LBA 0 is already a formatted filesystem (logical volume)
        from filesystem.manager import detect_filesystem_from_reader
        fs_info = detect_filesystem_from_reader(reader, 0)

        if fs_info.fs_type != "unknown":
            logger.info("Detected raw filesystem %s at LBA 0. Skipping partition scan.", fs_info.fs_type)
            return ScanResult(
                scheme="volume",
                partitions=[
                    DetectedPartition(
                        index=0,
                        scheme="volume",
                        lba_start=0,
                        lba_end=max(0, total_sectors - 1),
                        size_bytes=disk_size,
                        type_name=fs_info.fs_type.upper(),
                        fs_type=fs_info.fs_type,
                        label=fs_info.label,
                    )
                ],
                unallocated=[],
                disk_size=disk_size,
            )

        # Step 2: Parse MBR at LBA 0
        mbr_data = reader.read_sector(0)
        mbr_result = self._mbr_parser.parse(mbr_data)

        if not mbr_result.is_valid:
            logger.info("No valid MBR found — scanning for lost partitions")
            lost = self._scan_for_lost_partitions(reader, 0, total_sectors)
            return ScanResult(
                scheme="none",
                partitions=lost,
                unallocated=[(0, total_sectors - 1)],
                disk_size=disk_size,
            )

        # Step 2: Check for GPT
        if mbr_result.is_protective_gpt:
            return self._scan_gpt(reader, disk_size, total_sectors)

        # Step 3: Process MBR partitions
        return self._scan_mbr(reader, mbr_result, disk_size, total_sectors)

    def _scan_gpt(
        self, reader: DiskReader, disk_size: int, total_sectors: int
    ) -> ScanResult:
        """Parse GPT and probe each partition."""
        gpt_result = self._gpt_parser.parse(
            lambda lba: reader.read_sector(lba),
            reader.sector_size,
        )

        if not gpt_result.is_valid:
            logger.warning("GPT header invalid — falling back to MBR")
            mbr_data = reader.read_sector(0)
            mbr_result = self._mbr_parser.parse(mbr_data)
            return self._scan_mbr(reader, mbr_result, disk_size, total_sectors)

        partitions: list[DetectedPartition] = []
        for entry in gpt_result.partitions:
            fs_type, label = self._probe_filesystem(reader, entry.lba_start)
            partitions.append(DetectedPartition(
                index=entry.index,
                scheme="gpt",
                lba_start=entry.lba_start,
                lba_end=entry.lba_end,
                size_bytes=entry.size_bytes,
                type_name=entry.type_name,
                fs_type=fs_type,
                label=label or entry.name,
                gpt_entry=entry,
            ))

        unallocated = self._find_gaps(partitions, total_sectors)

        logger.info(
            "GPT scan: %d partition(s), %d gap(s), disk_guid=%s",
            len(partitions), len(unallocated), gpt_result.disk_guid[:8],
        )

        return ScanResult(
            scheme="gpt",
            partitions=partitions,
            unallocated=unallocated,
            disk_size=disk_size,
            disk_guid=gpt_result.disk_guid,
        )

    def _scan_mbr(
        self,
        reader: DiskReader,
        mbr_result: MBRParser.Result,
        disk_size: int,
        total_sectors: int,
    ) -> ScanResult:
        """Process MBR partitions including extended."""
        partitions: list[DetectedPartition] = []

        for entry in mbr_result.partitions:
            if entry.is_extended:
                # Follow EBR chain for logical partitions
                logicals = self._mbr_parser.parse_extended(
                    lambda lba: reader.read_sector(lba),
                    entry.lba_start,
                    entry.lba_start,
                )
                for logical in logicals:
                    fs_type, label = self._probe_filesystem(reader, logical.lba_start)
                    partitions.append(DetectedPartition(
                        index=logical.index,
                        scheme="mbr",
                        lba_start=logical.lba_start,
                        lba_end=logical.lba_end,
                        size_bytes=logical.size_bytes,
                        type_name=logical.type_name,
                        fs_type=fs_type,
                        label=label,
                        bootable=logical.is_bootable,
                        mbr_entry=logical,
                    ))
            else:
                fs_type, label = self._probe_filesystem(reader, entry.lba_start)
                partitions.append(DetectedPartition(
                    index=entry.index,
                    scheme="mbr",
                    lba_start=entry.lba_start,
                    lba_end=entry.lba_end,
                    size_bytes=entry.size_bytes,
                    type_name=entry.type_name,
                    fs_type=fs_type,
                    label=label,
                    bootable=entry.is_bootable,
                    mbr_entry=entry,
                ))

        unallocated = self._find_gaps(partitions, total_sectors)

        logger.info(
            "MBR scan: %d partition(s), %d gap(s)",
            len(partitions), len(unallocated),
        )

        return ScanResult(
            scheme="mbr",
            partitions=partitions,
            unallocated=unallocated,
            disk_size=disk_size,
        )

    def _probe_filesystem(
        self, reader: DiskReader, lba_start: int
    ) -> tuple[str, str]:
        """Probe the first few sectors of a partition to identify filesystem.

        Returns:
            Tuple of (fs_type, volume_label).
            fs_type is one of: "fat32", "fat16", "fat12", "ntfs", "ext2",
            "ext3", "ext4", "exfat", "hfsplus", "unknown"
        """
        # Read first 8 sectors (4 KB) for probing
        data = reader.read_at(lba_start * reader.sector_size, 4096)
        if len(data) < 512:
            return "unknown", ""

        # ── NTFS: "NTFS    " at offset 3 ────────────────────────
        if data[3:7] == b'NTFS':
            label = self._get_ntfs_label(data)
            return "ntfs", label

        # ── FAT: check for FAT signatures ────────────────────────
        if data[0] in (0xEB, 0xE9) or data[0:1] == b'\x00':
            # Read the BPB (BIOS Parameter Block)
            if len(data) >= 90:
                # FAT32: bytes_per_sector at 11, sectors_per_cluster at 13
                # FAT32 has 0 root entries and > 0 fat32_sectors
                root_entries = struct.unpack_from('<H', data, 17)[0]
                fat32_sectors = struct.unpack_from('<I', data, 36)[0]

                if root_entries == 0 and fat32_sectors > 0:
                    label = data[71:82].decode('ascii', errors='replace').strip()
                    return "fat32", label
                elif root_entries > 0:
                    total_sectors_16 = struct.unpack_from('<H', data, 19)[0]
                    if total_sectors_16 > 0:
                        label = data[43:54].decode('ascii', errors='replace').strip()
                        return "fat16", label

        # ── EXT2/3/4: superblock at offset 1024 ─────────────────
        # Need to read more data for superblock at byte 1024
        if len(data) >= 2048:
            sb_offset = 1024
            ext_magic = struct.unpack_from('<H', data, sb_offset + 56)[0]
            if ext_magic == 0xEF53:
                # Feature bits determine ext version
                compat = struct.unpack_from('<I', data, sb_offset + 92)[0]
                incompat = struct.unpack_from('<I', data, sb_offset + 96)[0]
                ro_compat = struct.unpack_from('<I', data, sb_offset + 100)[0]

                label_bytes = data[sb_offset + 120:sb_offset + 136]
                label = label_bytes.decode('utf-8', errors='replace').rstrip('\x00')

                # EXT4: INCOMPAT_EXTENTS (0x40) or INCOMPAT_64BIT (0x80)
                if incompat & 0x0040 or incompat & 0x0080:
                    return "ext4", label
                # EXT3: has_journal (COMPAT 0x04)
                elif compat & 0x0004:
                    return "ext3", label
                else:
                    return "ext2", label

        # ── exFAT: "EXFAT   " at offset 3 ───────────────────────
        if data[3:11] == b'EXFAT   ':
            return "exfat", ""

        # ── HFS+: magic 0x482B at offset 1024 ───────────────────
        if len(data) >= 1026:
            hfs_magic = struct.unpack_from('>H', data, 1024)[0]
            if hfs_magic == 0x482B:
                return "hfsplus", ""

        return "unknown", ""

    @staticmethod
    def _get_ntfs_label(data: bytes) -> str:
        """Extract volume label from NTFS boot sector OEM field."""
        # NTFS OEM ID is at offset 3, but the actual label is in the $Volume MFT entry
        # For probing, we just return the OEM string
        return ""

    def _find_gaps(
        self, partitions: list[DetectedPartition], total_sectors: int
    ) -> list[tuple[int, int]]:
        """Find unallocated LBA ranges between partitions.

        Args:
            partitions: Sorted list of detected partitions.
            total_sectors: Total sectors on disk.

        Returns:
            List of (start_lba, end_lba) tuples for unallocated regions.
            Only includes gaps > 2048 sectors (1 MB) to filter noise.
        """
        if not partitions:
            return [(0, total_sectors - 1)]

        # Sort by start LBA
        sorted_parts = sorted(partitions, key=lambda p: p.lba_start)
        gaps: list[tuple[int, int]] = []

        # Gap before first partition
        first_start = sorted_parts[0].lba_start
        if first_start > 2048:
            gaps.append((0, first_start - 1))

        # Gaps between partitions
        for i in range(len(sorted_parts) - 1):
            current_end = sorted_parts[i].lba_end
            next_start = sorted_parts[i + 1].lba_start
            gap_size = next_start - current_end - 1
            if gap_size > 2048:
                gaps.append((current_end + 1, next_start - 1))

        # Gap after last partition
        last_end = sorted_parts[-1].lba_end
        if total_sectors - last_end > 2048:
            gaps.append((last_end + 1, total_sectors - 1))

        return gaps

    def _scan_for_lost_partitions(
        self, reader: DiskReader, start_lba: int, end_lba: int,
        step: int = 2048,
    ) -> list[DetectedPartition]:
        """Scan unallocated space for filesystem superblocks.

        Checks every ``step`` sectors (default 1MB alignment) for known
        filesystem signatures. This finds partitions that were deleted
        from the partition table but whose data is still intact.

        Args:
            reader: DiskReader for the source.
            start_lba: Starting LBA to scan.
            end_lba: Ending LBA.
            step: Sector interval between probes.

        Returns:
            List of DetectedPartition entries for found filesystems.
        """
        found: list[DetectedPartition] = []
        idx = 100  # Start index above normal partition numbers

        for lba in range(start_lba, end_lba, step):
            fs_type, label = self._probe_filesystem(reader, lba)
            if fs_type != "unknown":
                found.append(DetectedPartition(
                    index=idx,
                    scheme="found",
                    lba_start=lba,
                    lba_end=lba,  # Size unknown without full parse
                    size_bytes=0,
                    type_name=f"Lost {fs_type}",
                    fs_type=fs_type,
                    label=label,
                ))
                idx += 1
                logger.info(
                    "Lost partition found: %s at LBA %d (label=%s)",
                    fs_type, lba, label,
                )

        return found
