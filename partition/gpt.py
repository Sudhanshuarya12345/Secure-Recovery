"""
pyrecovery.partition.gpt — GUID Partition Table parser.

GPT layout (on a disk with 512-byte sectors):
  LBA 0:     Protective MBR (parsed by mbr.py, type 0xEE)
  LBA 1:     GPT Header (92 bytes of structured data)
  LBA 2-33:  Partition Entry Array (128 entries × 128 bytes = 16,384 bytes)
  ...
  LBA -33:   Backup Partition Entry Array
  LBA -1:    Backup GPT Header

GPT Header (at LBA 1):
  +0:   Signature "EFI PART" (8 bytes)
  +8:   Revision (4 bytes, expect 0x00010000)
  +12:  Header size (4 bytes, typically 92)
  +16:  Header CRC32 (4 bytes)
  +20:  Reserved (4 bytes)
  +24:  This header LBA (8 bytes)
  +32:  Backup header LBA (8 bytes)
  +40:  First usable LBA (8 bytes)
  +48:  Last usable LBA (8 bytes)
  +56:  Disk GUID (16 bytes)
  +72:  Partition entry start LBA (8 bytes)
  +80:  Number of partition entries (4 bytes)
  +84:  Size of each entry (4 bytes, typically 128)
  +88:  Partition entry array CRC32 (4 bytes)

Each 128-byte partition entry:
  +0:   Partition type GUID (16 bytes)
  +16:  Unique partition GUID (16 bytes)
  +32:  First LBA (8 bytes)
  +40:  Last LBA (8 bytes, inclusive)
  +48:  Attributes (8 bytes)
  +56:  Name (72 bytes, UTF-16LE)
"""

from __future__ import annotations

import struct
import uuid
import zlib
from dataclasses import dataclass
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Well-known GPT partition type GUIDs
GPT_TYPE_GUIDS: dict[str, str] = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux Swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
    "48465300-0000-11AA-AA11-00306543ECAC": "macOS HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "macOS APFS",
    "53746F72-6167-11AA-AA11-00306543ECAC": "macOS Core Storage",
}


def _bytes_to_guid(b: bytes) -> str:
    """Convert 16 bytes in mixed-endian GPT format to standard UUID string.

    GPT uses a "mixed endian" format: first 3 fields are little-endian,
    last 2 fields are big-endian. Python's uuid module handles this
    when constructed from bytes_le.
    """
    if len(b) != 16:
        return "00000000-0000-0000-0000-000000000000"
    return str(uuid.UUID(bytes_le=bytes(b))).upper()


@dataclass
class GPTPartitionEntry:
    """Parsed GPT partition entry."""

    index: int
    type_guid: str          # Partition type GUID string
    type_name: str          # Human-readable type name
    unique_guid: str        # Unique partition GUID string
    lba_start: int          # First LBA
    lba_end: int            # Last LBA (inclusive)
    attributes: int         # Attribute flags
    name: str               # UTF-16LE partition name

    @property
    def size_sectors(self) -> int:
        return self.lba_end - self.lba_start + 1

    @property
    def size_bytes(self) -> int:
        return self.size_sectors * 512

    @property
    def is_empty(self) -> bool:
        return self.type_guid == "00000000-0000-0000-0000-000000000000"

    def __repr__(self) -> str:
        return (
            f"GPTPartitionEntry(#{self.index}, {self.type_name!r}, "
            f"LBA={self.lba_start}–{self.lba_end}, "
            f"name={self.name!r})"
        )


class GPTParser:
    """Parse GPT headers and partition entries.

    Usage::

        reader = DiskReader("disk.img")
        parser = GPTParser()
        result = parser.parse(reader)
        if result.is_valid:
            for entry in result.partitions:
                print(entry)
    """

    @dataclass
    class Result:
        """GPT parse result."""
        is_valid: bool
        disk_guid: str
        partitions: list[GPTPartitionEntry]
        first_usable_lba: int = 0
        last_usable_lba: int = 0
        header_crc_valid: bool = False
        entries_crc_valid: bool = False

    GPT_SIGNATURE = b"EFI PART"

    def parse(self, read_fn, sector_size: int = 512) -> "GPTParser.Result":
        """Parse GPT from a disk/image using a sector read function.

        Args:
            read_fn: Callable(lba: int) -> bytes that reads a sector.
            sector_size: Sector size in bytes.

        Returns:
            GPTParser.Result with validity and partition list.
        """
        # Read GPT header at LBA 1
        header_data = read_fn(1)
        if len(header_data) < 92:
            return GPTParser.Result(is_valid=False, disk_guid="", partitions=[])

        return self._parse_header_and_entries(header_data, read_fn, sector_size)

    def _parse_header_and_entries(
        self, header_data: bytes, read_fn, sector_size: int
    ) -> "GPTParser.Result":
        """Parse GPT header and partition entries."""

        # Validate signature
        sig = header_data[0:8]
        if sig != self.GPT_SIGNATURE:
            logger.debug("GPT signature invalid: %r", sig)
            return GPTParser.Result(is_valid=False, disk_guid="", partitions=[])

        # Parse header fields
        revision = struct.unpack_from('<I', header_data, 8)[0]
        header_size = struct.unpack_from('<I', header_data, 12)[0]
        header_crc = struct.unpack_from('<I', header_data, 16)[0]

        my_lba = struct.unpack_from('<Q', header_data, 24)[0]
        backup_lba = struct.unpack_from('<Q', header_data, 32)[0]
        first_usable = struct.unpack_from('<Q', header_data, 40)[0]
        last_usable = struct.unpack_from('<Q', header_data, 48)[0]

        disk_guid = _bytes_to_guid(header_data[56:72])

        entry_start_lba = struct.unpack_from('<Q', header_data, 72)[0]
        num_entries = struct.unpack_from('<I', header_data, 80)[0]
        entry_size = struct.unpack_from('<I', header_data, 84)[0]
        entries_crc = struct.unpack_from('<I', header_data, 88)[0]

        # Validate header CRC (zero out the CRC field for calculation)
        header_for_crc = bytearray(header_data[:header_size])
        header_for_crc[16:20] = b'\x00\x00\x00\x00'
        computed_header_crc = zlib.crc32(bytes(header_for_crc)) & 0xFFFFFFFF
        header_crc_valid = (computed_header_crc == header_crc)

        if not header_crc_valid:
            logger.warning(
                "GPT header CRC mismatch: expected=0x%08X, computed=0x%08X",
                header_crc, computed_header_crc,
            )

        # Read partition entries
        total_entry_bytes = num_entries * entry_size
        sectors_needed = (total_entry_bytes + sector_size - 1) // sector_size

        entry_data = bytearray()
        for i in range(sectors_needed):
            sector = read_fn(entry_start_lba + i)
            entry_data.extend(sector)

        # Validate entries CRC
        entries_bytes = bytes(entry_data[:total_entry_bytes])
        computed_entries_crc = zlib.crc32(entries_bytes) & 0xFFFFFFFF
        entries_crc_valid = (computed_entries_crc == entries_crc)

        if not entries_crc_valid:
            logger.warning(
                "GPT entries CRC mismatch: expected=0x%08X, computed=0x%08X",
                entries_crc, computed_entries_crc,
            )

        # Parse individual entries
        partitions: list[GPTPartitionEntry] = []
        for i in range(num_entries):
            offset = i * entry_size
            if offset + 128 > len(entry_data):
                break
            entry = self._parse_entry(entry_data, offset, i)
            if not entry.is_empty:
                partitions.append(entry)

        logger.info(
            "GPT parsed: disk_guid=%s, %d partition(s), "
            "header_crc=%s, entries_crc=%s",
            disk_guid[:8] + "...",
            len(partitions),
            "OK" if header_crc_valid else "FAIL",
            "OK" if entries_crc_valid else "FAIL",
        )

        return GPTParser.Result(
            is_valid=True,
            disk_guid=disk_guid,
            partitions=partitions,
            first_usable_lba=first_usable,
            last_usable_lba=last_usable,
            header_crc_valid=header_crc_valid,
            entries_crc_valid=entries_crc_valid,
        )

    @staticmethod
    def _parse_entry(data: bytes, offset: int, index: int) -> GPTPartitionEntry:
        """Parse a single 128-byte GPT partition entry."""
        type_guid = _bytes_to_guid(data[offset:offset + 16])
        unique_guid = _bytes_to_guid(data[offset + 16:offset + 32])
        lba_start = struct.unpack_from('<Q', data, offset + 32)[0]
        lba_end = struct.unpack_from('<Q', data, offset + 40)[0]
        attributes = struct.unpack_from('<Q', data, offset + 48)[0]

        # Name: 72 bytes of UTF-16LE, null-terminated
        name_bytes = data[offset + 56:offset + 128]
        try:
            name = name_bytes.decode('utf-16-le').rstrip('\x00')
        except (UnicodeDecodeError, ValueError):
            name = ""

        type_name = GPT_TYPE_GUIDS.get(type_guid, f"Unknown ({type_guid[:8]}...)")

        return GPTPartitionEntry(
            index=index,
            type_guid=type_guid,
            type_name=type_name,
            unique_guid=unique_guid,
            lba_start=lba_start,
            lba_end=lba_end,
            attributes=attributes,
            name=name,
        )
