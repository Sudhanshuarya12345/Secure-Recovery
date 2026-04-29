"""
pyrecovery.filesystem.ntfs — NTFS filesystem parser for file recovery.

NTFS key structures:
1. Boot Sector: cluster geometry, MFT location
2. MFT (Master File Table): one record per file/directory (~1024 bytes each)
3. Attributes within MFT records: $FILE_NAME, $DATA, $STANDARD_INFORMATION
4. $Bitmap: tracks cluster allocation

Deleted file recovery in NTFS:
- MFT records are flagged as "not in use" (flag bit cleared) but data remains
- $FILE_NAME attribute still contains the filename
- $DATA attribute contains data runs (cluster mappings)
- If clusters haven't been reallocated, full recovery is possible

Design: Parse MFT records + data runs. All I/O through DiskReader.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from disk.reader import DiskReader
from utils.logger import get_logger
from utils.size_formatter import format_size

logger = get_logger(__name__)


@dataclass
class NTFSBootSector:
    """Parsed NTFS boot sector."""
    bytes_per_sector: int = 512
    sectors_per_cluster: int = 8
    mft_cluster: int = 0        # Starting cluster of $MFT
    mft_mirror_cluster: int = 0 # Starting cluster of $MFTMirr
    mft_record_size: int = 1024 # Bytes per MFT record
    total_sectors: int = 0
    volume_serial: int = 0

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster


@dataclass
class NTFSFileEntry:
    """Parsed NTFS MFT record for a file or directory."""
    mft_index: int          # MFT record number
    filename: str           # From $FILE_NAME attribute
    parent_mft: int         # Parent directory MFT index
    file_size: int          # Real size from $DATA attribute
    allocated_size: int     # Allocated size on disk
    is_directory: bool
    is_deleted: bool        # MFT record flagged as not in use
    is_resident: bool       # Data stored in MFT record itself
    data_runs: list[tuple[int, int]] = field(default_factory=list)  # (cluster, length)
    resident_data: bytes = b""
    create_time: int = 0    # Windows FILETIME (100ns since 1601)
    modify_time: int = 0
    path: str = ""          # Reconstructed path


class NTFSParser:
    """Parse NTFS filesystem for file recovery.

    Usage::

        parser = NTFSParser(reader, partition_start_lba=2048)
        if parser.initialize():
            files = parser.list_files(include_deleted=True)
            for f in files:
                data = parser.read_file(f)
    """

    def __init__(self, reader: DiskReader, partition_start_lba: int = 0) -> None:
        self._reader = reader
        self._part_start = partition_start_lba
        self._boot: NTFSBootSector | None = None
        self._initialized = False

    def initialize(self) -> bool:
        """Parse NTFS boot sector.

        Returns:
            True if NTFS filesystem was successfully identified.
        """
        data = self._read_partition_bytes(0, 512)
        if len(data) < 512:
            return False

        # Check OEM ID
        if data[3:7] != b'NTFS':
            return False

        bps = struct.unpack_from('<H', data, 11)[0]
        spc = data[13]
        mft_cluster = struct.unpack_from('<Q', data, 48)[0]
        mft_mirror = struct.unpack_from('<Q', data, 56)[0]

        # MFT record size: byte at offset 64
        # If positive: clusters per record. If negative: 2^|value| bytes
        mft_raw = struct.unpack_from('<b', data, 64)[0]
        if mft_raw > 0:
            mft_record_size = mft_raw * bps * spc
        else:
            mft_record_size = 2 ** abs(mft_raw)

        total_sectors = struct.unpack_from('<Q', data, 40)[0]
        serial = struct.unpack_from('<Q', data, 72)[0]

        self._boot = NTFSBootSector(
            bytes_per_sector=bps,
            sectors_per_cluster=spc,
            mft_cluster=mft_cluster,
            mft_mirror_cluster=mft_mirror,
            mft_record_size=mft_record_size,
            total_sectors=total_sectors,
            volume_serial=serial,
        )

        self._initialized = True
        logger.info(
            "NTFS initialized: cluster_size=%d, mft_cluster=%d, "
            "record_size=%d, total=%s",
            self._boot.cluster_size, self._boot.mft_cluster,
            self._boot.mft_record_size,
            format_size(total_sectors * bps),
        )
        return True

    def list_files(
        self, include_deleted: bool = True, max_records: int = 10000
    ) -> list[NTFSFileEntry]:
        """Scan MFT records and extract file entries.

        Args:
            include_deleted: Include records flagged as deleted.
            max_records: Maximum MFT records to scan.

        Returns:
            List of NTFSFileEntry items.
        """
        if not self._initialized or self._boot is None:
            return []

        entries: list[NTFSFileEntry] = []
        record_size = self._boot.mft_record_size
        mft_offset = self._boot.mft_cluster * self._boot.cluster_size

        for i in range(max_records):
            offset = mft_offset + (i * record_size)
            record_data = self._read_partition_bytes(offset, record_size)
            if len(record_data) < record_size:
                break

            entry = self._parse_mft_record(record_data, i)
            if entry is None:
                continue

            if not include_deleted and entry.is_deleted:
                continue

            entries.append(entry)

        # Build paths from parent references
        self._build_paths(entries)

        logger.info(
            "NTFS MFT scan: %d entries (%d deleted)",
            len(entries),
            sum(1 for e in entries if e.is_deleted),
        )
        return entries

    def build_tree(self, include_deleted: bool = True) -> "DirectoryNode | None":
        """Reconstruct the entire directory tree, including deleted entries.
        
        Returns:
            Root DirectoryNode containing the nested tree, or None if failed.
        """
        if not self._initialized:
            if not self.initialize():
                return None
                
        from filesystem.ntfs.tree_builder import NTFSTreeBuilder
        builder = NTFSTreeBuilder(self)
        return builder.build(include_deleted=include_deleted)

    def read_file(self, entry: NTFSFileEntry) -> bytes:
        """Read file data from data runs or resident data.

        Args:
            entry: NTFSFileEntry to read.

        Returns:
            File content bytes.
        """
        if not self._initialized or self._boot is None:
            return b""

        if entry.is_resident:
            return entry.resident_data[:entry.file_size]

        # Non-resident: follow data runs
        result = bytearray()
        cluster_size = self._boot.cluster_size

        for run_cluster, run_length in entry.data_runs:
            for i in range(run_length):
                cluster_offset = (run_cluster + i) * cluster_size
                data = self._read_partition_bytes(cluster_offset, cluster_size)
                result.extend(data)
                if len(result) >= entry.file_size:
                    break
            if len(result) >= entry.file_size:
                break

        return bytes(result[:entry.file_size])

    @property
    def boot_sector(self) -> NTFSBootSector | None:
        return self._boot

    # ── Private methods ─────────────────────────────────────────────

    def _parse_mft_record(
        self, data: bytes, index: int
    ) -> NTFSFileEntry | None:
        """Parse a single MFT record."""
        # Check FILE signature
        if data[0:4] != b'FILE':
            return None

        # Flags at offset 22: 0x01 = in use, 0x02 = directory
        flags = struct.unpack_from('<H', data, 22)[0]
        is_in_use = bool(flags & 0x01)
        is_directory = bool(flags & 0x02)

        # Apply fixup array (critical for multi-sector records)
        data = self._apply_fixup(data)
        if data is None:
            return None

        # First attribute offset at byte 20
        attr_offset = struct.unpack_from('<H', data, 20)[0]

        filename = ""
        parent_mft = 0
        file_size = 0
        allocated_size = 0
        is_resident = False
        data_runs: list[tuple[int, int]] = []
        resident_data = b""
        create_time = 0
        modify_time = 0

        # Walk attributes
        pos = attr_offset
        while pos + 4 < len(data):
            attr_type = struct.unpack_from('<I', data, pos)[0]
            if attr_type == 0xFFFFFFFF or attr_type == 0:
                break

            attr_length = struct.unpack_from('<I', data, pos + 4)[0]
            if attr_length == 0 or attr_length > len(data) - pos:
                break

            if attr_type == 0x30:  # $FILE_NAME
                fn = self._parse_filename_attr(data, pos)
                if fn:
                    filename, parent_mft, create_time, modify_time = fn

            elif attr_type == 0x80:  # $DATA
                is_non_resident = data[pos + 8]
                if is_non_resident:
                    # Non-resident $DATA
                    real_size = struct.unpack_from('<Q', data, pos + 48)[0]
                    alloc_size = struct.unpack_from('<Q', data, pos + 40)[0]
                    runs = self._parse_data_runs(data, pos)
                    file_size = real_size
                    allocated_size = alloc_size
                    data_runs = runs
                else:
                    # Resident $DATA
                    content_size = struct.unpack_from('<I', data, pos + 16)[0]
                    content_offset = struct.unpack_from('<H', data, pos + 20)[0]
                    resident_data = data[pos + content_offset:pos + content_offset + content_size]
                    file_size = content_size
                    allocated_size = content_size
                    is_resident = True

            pos += attr_length

        if not filename:
            return None

        return NTFSFileEntry(
            mft_index=index,
            filename=filename,
            parent_mft=parent_mft,
            file_size=file_size,
            allocated_size=allocated_size,
            is_directory=is_directory,
            is_deleted=not is_in_use,
            is_resident=is_resident,
            data_runs=data_runs,
            resident_data=resident_data,
            create_time=create_time,
            modify_time=modify_time,
        )

    def _parse_filename_attr(
        self, data: bytes, attr_offset: int
    ) -> tuple[str, int, int, int] | None:
        """Parse $FILE_NAME attribute. Returns (name, parent_mft, ctime, mtime)."""
        is_non_resident = data[attr_offset + 8]
        if is_non_resident:
            return None

        content_offset = struct.unpack_from('<H', data, attr_offset + 20)[0]
        abs_offset = attr_offset + content_offset

        if abs_offset + 66 > len(data):
            return None

        parent_ref = struct.unpack_from('<Q', data, abs_offset)[0]
        parent_mft = parent_ref & 0x0000FFFFFFFFFFFF  # Lower 48 bits

        create_time = struct.unpack_from('<Q', data, abs_offset + 8)[0]
        modify_time = struct.unpack_from('<Q', data, abs_offset + 16)[0]

        name_length = data[abs_offset + 64]
        name_namespace = data[abs_offset + 65]

        # Skip DOS (8.3) names — prefer Win32 or POSIX names
        if name_namespace == 2:  # DOS namespace only
            return None

        name_start = abs_offset + 66
        name_end = name_start + name_length * 2
        if name_end > len(data):
            return None

        try:
            filename = data[name_start:name_end].decode('utf-16-le')
        except (UnicodeDecodeError, ValueError):
            return None

        return filename, parent_mft, create_time, modify_time

    def _parse_data_runs(
        self, data: bytes, attr_offset: int
    ) -> list[tuple[int, int]]:
        """Parse data runs from a non-resident $DATA attribute.

        Data runs are a compact encoding of cluster extents:
        Each run: 1 header byte (nibbles: offset_size | length_size)
                  followed by length_size bytes of run length
                  followed by offset_size bytes of run offset (signed, relative)
        """
        run_offset_start = struct.unpack_from('<H', data, attr_offset + 32)[0]
        pos = attr_offset + run_offset_start
        runs: list[tuple[int, int]] = []
        current_cluster = 0

        while pos < len(data):
            header = data[pos]
            if header == 0:
                break

            length_size = header & 0x0F
            offset_size = (header >> 4) & 0x0F
            pos += 1

            if pos + length_size + offset_size > len(data):
                break

            # Parse run length
            run_length = int.from_bytes(data[pos:pos + length_size], 'little', signed=False)
            pos += length_size

            # Parse run offset (signed, relative to previous)
            if offset_size > 0:
                run_offset = int.from_bytes(data[pos:pos + offset_size], 'little', signed=True)
                pos += offset_size
                current_cluster += run_offset
                runs.append((current_cluster, run_length))
            else:
                # Sparse run (no offset = zeroed clusters)
                pos += offset_size

        return runs

    @staticmethod
    def _apply_fixup(data: bytes) -> bytes | None:
        """Apply NTFS fixup array to validate multi-sector record integrity."""
        if len(data) < 48:
            return None

        fixup_offset = struct.unpack_from('<H', data, 4)[0]
        fixup_count = struct.unpack_from('<H', data, 6)[0]

        if fixup_offset + fixup_count * 2 > len(data):
            return data  # Can't apply fixup, return as-is

        result = bytearray(data)
        signature = struct.unpack_from('<H', result, fixup_offset)[0]

        for i in range(1, fixup_count):
            sector_end = i * 512 - 2
            if sector_end + 2 > len(result):
                break
            expected = struct.unpack_from('<H', result, sector_end)[0]
            if expected != signature:
                logger.debug("Fixup mismatch at sector %d", i)
            # Apply fixup value
            fixup_value = struct.unpack_from('<H', result, fixup_offset + i * 2)[0]
            struct.pack_into('<H', result, sector_end, fixup_value)

        return bytes(result)

    def _build_paths(self, entries: list[NTFSFileEntry]) -> None:
        """Build full paths from parent MFT references."""
        # Create index: mft_number → entry
        by_mft: dict[int, NTFSFileEntry] = {}
        for e in entries:
            by_mft[e.mft_index] = e

        for entry in entries:
            parts: list[str] = [entry.filename]
            current = entry
            visited: set[int] = {current.mft_index}
            depth = 0

            while current.parent_mft in by_mft and depth < 32:
                parent = by_mft[current.parent_mft]
                if parent.mft_index in visited:
                    break
                visited.add(parent.mft_index)
                if parent.mft_index == 5:  # Root directory
                    break
                parts.insert(0, parent.filename)
                current = parent
                depth += 1

            entry.path = "/" + "/".join(parts)

    def _read_partition_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes at offset relative to partition start."""
        abs_offset = self._part_start * self._reader.sector_size + offset
        return self._reader.read_at(abs_offset, size)

    def _read_partition_sector(self, sector: int) -> bytes:
        """Read a sector relative to partition start."""
        return self._reader.read_sector(self._part_start + sector)
