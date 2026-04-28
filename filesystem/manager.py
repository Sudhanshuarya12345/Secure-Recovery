"""
pyrecovery.filesystem.manager — Byte-level filesystem detection.

Reads first 4096 bytes of a device/partition and identifies the filesystem
by checking magic numbers at known offsets.  No guessing — every detection
is based on documented on-disk structures.

Supported filesystems:
    FAT12/16, FAT32, NTFS, EXT2, EXT3, EXT4, HFS+, LUKS, BitLocker

Usage::

    from filesystem.manager import detect_filesystem, FilesystemInfo
    info = detect_filesystem("/dev/sdb1")
    # or
    info = detect_filesystem_from_reader(reader, partition_offset=2048*512)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FilesystemInfo:
    """Detected filesystem information."""

    fs_type: str = "unknown"       # "fat32", "ntfs", "ext4", "luks", etc.
    label: str = ""                # Volume label if available
    cluster_size: int = 0          # Bytes per cluster/block
    total_size: int = 0            # Total size in bytes (from FS metadata)
    free_size: int = 0             # Free space in bytes (estimated)
    version: str = ""              # e.g. "EXT4", "LUKS2"
    encrypted: bool = False        # True for LUKS/BitLocker
    uuid: str = ""                 # UUID if available

    @property
    def display_name(self) -> str:
        """Human-readable name for display."""
        names = {
            "fat12": "FAT12", "fat16": "FAT16", "fat32": "FAT32",
            "ntfs": "NTFS", "ext2": "EXT2", "ext3": "EXT3", "ext4": "EXT4",
            "hfsplus": "HFS+", "luks": "LUKS (Encrypted)",
            "bitlocker": "BitLocker (Encrypted)", "unknown": "Unknown",
        }
        return names.get(self.fs_type, self.fs_type.upper())


def detect_filesystem(source: str, offset: int = 0) -> FilesystemInfo:
    """Detect filesystem type by reading raw bytes from a path.

    Args:
        source: Path to device or image file.
        offset: Byte offset to the partition start (0 for whole disk).

    Returns:
        FilesystemInfo with detected type and metadata.
    """
    try:
        with open(source, "rb") as f:
            f.seek(offset)
            data = f.read(4096)
        return _detect_from_bytes(data)
    except (OSError, PermissionError) as e:
        logger.warning("Cannot read %s for FS detection: %s", source, e)
        return FilesystemInfo()


def detect_filesystem_from_reader(reader, partition_offset: int = 0) -> FilesystemInfo:
    """Detect filesystem type using an existing DiskReader.

    Args:
        reader: An open DiskReader instance.
        partition_offset: Byte offset to the partition start.

    Returns:
        FilesystemInfo with detected type and metadata.
    """
    data = reader.read_at(partition_offset, 4096)
    if not data:
        return FilesystemInfo()
    return _detect_from_bytes(data)


def _detect_from_bytes(data: bytes) -> FilesystemInfo:
    """Core detection logic — check magic numbers at known offsets.

    Detection order matters — more specific signatures first.

    Reference offsets:
        LUKS:     offset 0     → "LUKS\\xba\\xbe"
        BitLocker: offset 3    → "-FVE-FS-"
        NTFS:     offset 3     → "NTFS    "
        FAT32:    offset 82    → "FAT32   "
        FAT16:    offset 54    → "FAT16   " or "FAT12   "
        EXT:      offset 1080  → 0xEF53 (little-endian uint16)
        HFS+:     offset 1024  → "H+" (uint16 0x482B) or "HX" (uint16 0x4858)
    """
    if len(data) < 1088:
        return FilesystemInfo()

    info = FilesystemInfo()

    # ── 1. LUKS (encryption) ────────────────────────────────────────
    if data[0:6] == b"LUKS\xba\xbe":
        info.fs_type = "luks"
        info.encrypted = True
        # Version at offset 6 (uint16 BE)
        version = struct.unpack_from(">H", data, 6)[0]
        info.version = f"LUKS{version}"
        logger.debug("Detected LUKS%d", version)
        return info

    # ── 2. BitLocker ────────────────────────────────────────────────
    if data[3:11] == b"-FVE-FS-":
        info.fs_type = "bitlocker"
        info.encrypted = True
        info.version = "BitLocker"
        logger.debug("Detected BitLocker")
        return info

    # ── 3. NTFS ─────────────────────────────────────────────────────
    if data[3:11] == b"NTFS    ":
        info.fs_type = "ntfs"
        # Bytes per sector at offset 11 (uint16 LE)
        bytes_per_sector = struct.unpack_from("<H", data, 11)[0]
        # Sectors per cluster at offset 13 (uint8)
        sectors_per_cluster = data[13]
        info.cluster_size = bytes_per_sector * sectors_per_cluster
        # Total sectors at offset 40 (uint64 LE)
        total_sectors = struct.unpack_from("<Q", data, 40)[0]
        info.total_size = total_sectors * bytes_per_sector
        # Volume serial at offset 72 (uint64 LE) — use as pseudo-UUID
        serial = struct.unpack_from("<Q", data, 72)[0]
        info.uuid = f"{serial:016X}"
        logger.debug("Detected NTFS, cluster=%d, total=%d",
                      info.cluster_size, info.total_size)
        return info

    # ── 4. FAT32 ────────────────────────────────────────────────────
    if data[82:90] == b"FAT32   ":
        info.fs_type = "fat32"
        bytes_per_sector = struct.unpack_from("<H", data, 11)[0]
        sectors_per_cluster = data[13]
        info.cluster_size = bytes_per_sector * sectors_per_cluster
        # Total sectors (32-bit at offset 32 for FAT32)
        total_sectors = struct.unpack_from("<I", data, 32)[0]
        info.total_size = total_sectors * bytes_per_sector
        # Volume label at offset 71 (11 bytes)
        info.label = data[71:82].decode("ascii", errors="replace").strip()
        logger.debug("Detected FAT32, label='%s', cluster=%d",
                      info.label, info.cluster_size)
        return info

    # ── 5. FAT12/FAT16 ─────────────────────────────────────────────
    if data[54:62] in (b"FAT16   ", b"FAT12   "):
        fat_type = data[54:62].decode("ascii").strip()
        info.fs_type = fat_type.lower().replace(" ", "")
        bytes_per_sector = struct.unpack_from("<H", data, 11)[0]
        sectors_per_cluster = data[13]
        info.cluster_size = bytes_per_sector * sectors_per_cluster
        total_sectors = struct.unpack_from("<H", data, 19)[0]
        if total_sectors == 0:
            total_sectors = struct.unpack_from("<I", data, 32)[0]
        info.total_size = total_sectors * bytes_per_sector
        info.label = data[43:54].decode("ascii", errors="replace").strip()
        logger.debug("Detected %s, label='%s'", fat_type, info.label)
        return info

    # ── 6. EXT2/3/4 ─────────────────────────────────────────────────
    # Superblock starts at offset 1024, magic at offset 56 within SB = 1080
    ext_magic = struct.unpack_from("<H", data, 1080)[0]
    if ext_magic == 0xEF53:
        # Determine EXT version from feature flags
        # s_feature_compat at superblock offset 92 = byte 1024+92 = 1116
        # s_feature_incompat at superblock offset 96 = byte 1024+96 = 1120
        s_feature_compat = struct.unpack_from("<I", data, 1116)[0]
        s_feature_incompat = struct.unpack_from("<I", data, 1120)[0]

        HAS_JOURNAL = 0x0004       # compat feature
        EXTENTS = 0x0040           # incompat feature
        FLEX_BG = 0x0200           # incompat feature

        if s_feature_incompat & (EXTENTS | FLEX_BG):
            info.fs_type = "ext4"
        elif s_feature_compat & HAS_JOURNAL:
            info.fs_type = "ext3"
        else:
            info.fs_type = "ext2"

        # Block size: 1024 << s_log_block_size (at SB offset 24 = 1048)
        log_block_size = struct.unpack_from("<I", data, 1048)[0]
        block_size = 1024 << log_block_size
        info.cluster_size = block_size

        # Total blocks (at SB offset 4 = 1028) — 32-bit
        total_blocks = struct.unpack_from("<I", data, 1028)[0]
        info.total_size = total_blocks * block_size

        # Free blocks (at SB offset 12 = 1036) — 32-bit
        free_blocks = struct.unpack_from("<I", data, 1036)[0]
        info.free_size = free_blocks * block_size

        # Volume name (at SB offset 120 = 1144, 16 bytes)
        label_bytes = data[1144:1160]
        info.label = label_bytes.split(b"\x00")[0].decode("ascii", errors="replace")

        # UUID (at SB offset 104 = 1128, 16 bytes)
        uuid_bytes = data[1128:1144]
        info.uuid = (
            f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-"
            f"{uuid_bytes[6:8].hex()}-{uuid_bytes[8:10].hex()}-"
            f"{uuid_bytes[10:16].hex()}"
        )

        logger.debug("Detected %s, block_size=%d, label='%s'",
                      info.fs_type, block_size, info.label)
        return info

    # ── 7. HFS+ ─────────────────────────────────────────────────────
    if len(data) >= 1026:
        hfs_sig = struct.unpack_from(">H", data, 1024)[0]
        if hfs_sig in (0x482B, 0x4858):  # "H+" or "HX"
            info.fs_type = "hfsplus"
            # Block size at offset 1024+40 = 1064 (uint32 BE)
            if len(data) >= 1068:
                info.cluster_size = struct.unpack_from(">I", data, 1064)[0]
            logger.debug("Detected HFS+")
            return info

    # ── 8. Unknown ──────────────────────────────────────────────────
    logger.debug("No filesystem detected")
    return info
