"""
pyrecovery.filesystem.fat32 — FAT32 filesystem parser for file recovery.

FAT32 key structures:
1. Boot Sector (BPB) at sector 0 of partition: contains cluster geometry
2. FAT (File Allocation Table): linked list of cluster chains
3. Root Directory: starting at cluster 2 (typically), 32-byte entries
4. Data Region: actual file content in clusters

Deleted file recovery in FAT32:
- Deleted entries have first byte of filename set to 0xE5
- The FAT chain is zeroed out, BUT the starting cluster is preserved
- For non-fragmented files, reading starting_cluster for file_size bytes recovers the file
- For fragmented files, we lose the chain — only first fragment is recoverable

Design: All reads go through DiskReader → forensic safety guaranteed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional

from disk.reader import DiskReader
from utils.logger import get_logger
from utils.size_formatter import format_size

logger = get_logger(__name__)


@dataclass
class FATBootSector:
    """Parsed FAT32 BPB (BIOS Parameter Block)."""
    bytes_per_sector: int = 512
    sectors_per_cluster: int = 8
    reserved_sectors: int = 32
    num_fats: int = 2
    total_sectors: int = 0
    fat_size_sectors: int = 0
    root_cluster: int = 2
    volume_label: str = ""
    fs_type: str = ""

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def fat_start_sector(self) -> int:
        return self.reserved_sectors

    @property
    def data_start_sector(self) -> int:
        return self.reserved_sectors + (self.num_fats * self.fat_size_sectors)


@dataclass
class FATDirectoryEntry:
    """Parsed FAT32 directory entry (32 bytes each)."""
    short_name: str         # 8.3 filename
    long_name: str          # VFAT long filename (if any)
    extension: str          # File extension
    attributes: int         # File attributes byte
    start_cluster: int      # First cluster of file data
    file_size: int          # File size in bytes
    is_deleted: bool        # First byte was 0xE5
    is_directory: bool      # Attribute bit 0x10
    is_volume_label: bool   # Attribute bit 0x08
    is_long_name: bool      # Attribute 0x0F (LFN entry)
    create_time: int = 0    # DOS timestamp
    modify_time: int = 0    # DOS timestamp
    path: str = ""          # Full reconstructed path

    @property
    def full_name(self) -> str:
        if self.long_name:
            return self.long_name
        name = self.short_name.strip()
        ext = self.extension.strip()
        if ext:
            return f"{name}.{ext}"
        return name


class FAT32Parser:
    """Parse FAT32 filesystem for file recovery.

    Capabilities:
    - Parse BPB and determine cluster geometry
    - Read and cache the entire FAT in memory (typically < 32 MB)
    - Walk directory tree to enumerate all files (active + deleted)
    - Follow cluster chains for file extraction
    - Recover deleted files from single-cluster or contiguous allocation

    Usage::

        parser = FAT32Parser(reader, partition_start_lba=2048)
        files = parser.list_files(include_deleted=True)
        for f in files:
            data = parser.read_file(f)
    """

    def __init__(self, reader: DiskReader, partition_start_lba: int = 0) -> None:
        self._reader = reader
        self._part_start = partition_start_lba
        self._bpb: FATBootSector | None = None
        self._fat: dict[int, int] = {}  # cluster → next_cluster
        self._initialized = False

    def initialize(self) -> bool:
        """Parse BPB and load FAT into memory.

        Returns:
            True if FAT32 filesystem was successfully parsed.
        """
        bpb_data = self._read_partition_sector(0)
        if len(bpb_data) < 90:
            return False

        self._bpb = self._parse_bpb(bpb_data)
        if not self._bpb:
            return False

        self._load_fat()
        self._initialized = True

        logger.info(
            "FAT32 initialized: cluster_size=%d, root_cluster=%d, "
            "total=%s, label=%r",
            self._bpb.cluster_size, self._bpb.root_cluster,
            format_size(self._bpb.total_sectors * self._bpb.bytes_per_sector),
            self._bpb.volume_label,
        )
        return True

    def list_files(
        self, include_deleted: bool = True, path: str = "/"
    ) -> list[FATDirectoryEntry]:
        """List all files, optionally including deleted entries.

        Args:
            include_deleted: If True, include entries with 0xE5 first byte.
            path: Root path prefix for returned entries.

        Returns:
            Flat list of all FATDirectoryEntry items found.
        """
        if not self._initialized:
            if not self.initialize():
                return []

        assert self._bpb is not None
        results: list[FATDirectoryEntry] = []
        self._walk_directory(
            self._bpb.root_cluster, path, results, include_deleted
        )
        return results

    def read_file(self, entry: FATDirectoryEntry) -> bytes:
        """Read file data by following its cluster chain.

        For deleted files, attempts contiguous cluster read from start_cluster
        since the FAT chain has been zeroed.

        Args:
            entry: FATDirectoryEntry to read.

        Returns:
            File content bytes (up to file_size).
        """
        if not self._initialized or self._bpb is None:
            return b""

        if entry.start_cluster < 2:
            return b""

        if entry.is_deleted:
            # Deleted: FAT chain is gone. Read contiguous clusters.
            return self._read_contiguous(entry.start_cluster, entry.file_size)
        else:
            # Active: follow FAT chain
            return self._read_chain(entry.start_cluster, entry.file_size)

    @property
    def boot_sector(self) -> FATBootSector | None:
        return self._bpb

    # ── Private methods ─────────────────────────────────────────────

    def _parse_bpb(self, data: bytes) -> FATBootSector | None:
        """Parse the FAT32 BPB from boot sector data."""
        if data[0] not in (0xEB, 0xE9, 0x00):
            return None

        bps = struct.unpack_from('<H', data, 11)[0]
        spc = data[13]
        reserved = struct.unpack_from('<H', data, 14)[0]
        num_fats = data[16]
        root_entries = struct.unpack_from('<H', data, 17)[0]

        # FAT32 requires root_entries == 0
        if root_entries != 0:
            logger.debug("Not FAT32: root_entries=%d", root_entries)
            return None

        total_16 = struct.unpack_from('<H', data, 19)[0]
        total_32 = struct.unpack_from('<I', data, 32)[0]
        total = total_32 if total_16 == 0 else total_16

        fat_size = struct.unpack_from('<I', data, 36)[0]
        root_cluster = struct.unpack_from('<I', data, 44)[0]

        label = data[71:82].decode('ascii', errors='replace').strip()
        fs_type = data[82:90].decode('ascii', errors='replace').strip()

        # Sanity checks
        if bps not in (512, 1024, 2048, 4096):
            return None
        if spc == 0 or (spc & (spc - 1)) != 0:
            return None

        return FATBootSector(
            bytes_per_sector=bps,
            sectors_per_cluster=spc,
            reserved_sectors=reserved,
            num_fats=num_fats,
            total_sectors=total,
            fat_size_sectors=fat_size,
            root_cluster=root_cluster,
            volume_label=label,
            fs_type=fs_type,
        )

    def _load_fat(self) -> None:
        """Load entire FAT into memory as {cluster: next_cluster} dict."""
        assert self._bpb is not None
        fat_start = self._bpb.fat_start_sector
        fat_size = self._bpb.fat_size_sectors
        bps = self._bpb.bytes_per_sector

        # Read all FAT sectors
        fat_bytes = bytearray()
        for i in range(fat_size):
            sector_data = self._read_partition_sector(fat_start + i)
            fat_bytes.extend(sector_data)

        # Parse as array of uint32 (each entry is 4 bytes in FAT32)
        entry_count = len(fat_bytes) // 4
        for i in range(2, entry_count):  # Clusters start at 2
            offset = i * 4
            if offset + 4 > len(fat_bytes):
                break
            value = struct.unpack_from('<I', fat_bytes, offset)[0] & 0x0FFFFFFF
            if value != 0:
                self._fat[i] = value

        logger.debug("FAT loaded: %d non-zero entries", len(self._fat))

    def _walk_directory(
        self,
        cluster: int,
        path: str,
        results: list[FATDirectoryEntry],
        include_deleted: bool,
        depth: int = 0,
    ) -> None:
        """Recursively walk directory entries starting from a cluster."""
        if depth > 32:
            return  # Prevent infinite recursion

        assert self._bpb is not None
        dir_data = self._read_chain(cluster, max_size=self._bpb.cluster_size * 256)
        if not dir_data:
            return

        entries = self._parse_directory_entries(dir_data)
        lfn_buffer: list[str] = []

        for entry in entries:
            if entry.is_long_name:
                # Accumulate LFN fragments (stored in reverse order)
                lfn_buffer.insert(0, entry.long_name)
                continue

            if entry.is_volume_label:
                continue

            # Assign accumulated LFN
            if lfn_buffer:
                entry.long_name = "".join(lfn_buffer)
                lfn_buffer = []
            else:
                lfn_buffer = []

            if not include_deleted and entry.is_deleted:
                continue

            entry.path = path + entry.full_name

            if entry.is_directory:
                if entry.short_name.strip() in (".", ".."):
                    continue
                entry.path += "/"
                results.append(entry)
                # Recurse into subdirectory
                if entry.start_cluster >= 2:
                    self._walk_directory(
                        entry.start_cluster, entry.path,
                        results, include_deleted, depth + 1,
                    )
            else:
                results.append(entry)

    def _parse_directory_entries(self, data: bytes) -> list[FATDirectoryEntry]:
        """Parse 32-byte directory entries from raw data."""
        entries: list[FATDirectoryEntry] = []
        for i in range(0, len(data), 32):
            if i + 32 > len(data):
                break

            first_byte = data[i]
            if first_byte == 0x00:
                break  # End of directory
            if first_byte == 0x2E:
                continue  # Skip . and .. entries

            attrs = data[i + 11]
            is_deleted = (first_byte == 0xE5)

            # Long filename entry
            if attrs == 0x0F:
                lfn_chars = self._extract_lfn_chars(data[i:i + 32])
                entries.append(FATDirectoryEntry(
                    short_name="", extension="", long_name=lfn_chars,
                    attributes=attrs, start_cluster=0, file_size=0,
                    is_deleted=False, is_directory=False,
                    is_volume_label=False, is_long_name=True,
                ))
                continue

            # Standard 8.3 entry
            name_bytes = data[i:i + 8]
            ext_bytes = data[i + 8:i + 11]

            if is_deleted:
                name_bytes = b'_' + name_bytes[1:]

            short_name = name_bytes.decode('ascii', errors='replace').strip()
            extension = ext_bytes.decode('ascii', errors='replace').strip()

            cluster_hi = struct.unpack_from('<H', data, i + 20)[0]
            cluster_lo = struct.unpack_from('<H', data, i + 26)[0]
            start_cluster = (cluster_hi << 16) | cluster_lo

            file_size = struct.unpack_from('<I', data, i + 28)[0]

            create_time = struct.unpack_from('<I', data, i + 14)[0]
            modify_time = struct.unpack_from('<I', data, i + 22)[0]

            entries.append(FATDirectoryEntry(
                short_name=short_name,
                extension=extension,
                long_name="",
                attributes=attrs,
                start_cluster=start_cluster,
                file_size=file_size,
                is_deleted=is_deleted,
                is_directory=bool(attrs & 0x10),
                is_volume_label=bool(attrs & 0x08),
                is_long_name=False,
                create_time=create_time,
                modify_time=modify_time,
            ))

        return entries

    @staticmethod
    def _extract_lfn_chars(entry: bytes) -> str:
        """Extract Unicode characters from a LFN directory entry."""
        chars = bytearray()
        # Characters are at fixed positions: 1-10, 14-25, 28-31
        for start, end in [(1, 11), (14, 26), (28, 32)]:
            chars.extend(entry[start:end])
        try:
            text = chars.decode('utf-16-le', errors='replace')
            return text.split('\x00')[0].split('\xff')[0]
        except (UnicodeDecodeError, ValueError):
            return ""

    def _read_chain(
        self, start_cluster: int, file_size: int = 0, max_size: int = 0
    ) -> bytes:
        """Read data by following the FAT cluster chain."""
        assert self._bpb is not None
        result = bytearray()
        cluster = start_cluster
        limit = file_size if file_size > 0 else (max_size if max_size > 0 else 10 * 1024 * 1024)
        visited: set[int] = set()

        while cluster >= 2 and cluster < 0x0FFFFFF8 and len(result) < limit:
            if cluster in visited:
                break  # Circular chain
            visited.add(cluster)

            cluster_data = self._read_cluster(cluster)
            result.extend(cluster_data)

            # Follow chain
            next_cluster = self._fat.get(cluster, 0x0FFFFFFF)
            if next_cluster >= 0x0FFFFFF8:
                break  # End of chain
            cluster = next_cluster

        if file_size > 0:
            return bytes(result[:file_size])
        return bytes(result)

    def _read_contiguous(self, start_cluster: int, file_size: int) -> bytes:
        """Read contiguous clusters for deleted file recovery."""
        assert self._bpb is not None
        clusters_needed = (file_size + self._bpb.cluster_size - 1) // self._bpb.cluster_size
        result = bytearray()

        for i in range(clusters_needed):
            cluster_data = self._read_cluster(start_cluster + i)
            result.extend(cluster_data)

        return bytes(result[:file_size])

    def _read_cluster(self, cluster: int) -> bytes:
        """Read a single cluster by number."""
        assert self._bpb is not None
        sector = self._bpb.data_start_sector + (cluster - 2) * self._bpb.sectors_per_cluster
        abs_sector = self._part_start + sector
        offset = abs_sector * self._bpb.bytes_per_sector
        return self._reader.read_at(offset, self._bpb.cluster_size)

    def _read_partition_sector(self, sector: int) -> bytes:
        """Read a sector relative to partition start."""
        abs_sector = self._part_start + sector
        return self._reader.read_sector(abs_sector)
