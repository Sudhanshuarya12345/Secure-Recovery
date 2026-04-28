"""
pyrecovery.partition.mbr — Master Boot Record parser.

The MBR sits at LBA 0 (first 512 bytes) of any MBR-partitioned disk.
Layout:
  Offset 0-445:   Bootstrap code (boot loader, ignored for recovery)
  Offset 446-509: 4 partition table entries, 16 bytes each
  Offset 510-511: Boot signature 0x55AA

Each 16-byte partition entry:
  +0:  Status (0x80 = bootable, 0x00 = inactive)
  +1:  CHS of first sector (3 bytes, legacy — we use LBA instead)
  +4:  Partition type code (e.g., 0x07=NTFS, 0x0B=FAT32, 0x83=Linux)
  +5:  CHS of last sector (3 bytes)
  +8:  LBA of first sector (uint32 LE) ← the critical field
  +12: Size in sectors (uint32 LE) ← the other critical field

Extended partitions (type 0x05/0x0F) contain a chain of EBRs
(Extended Boot Records) that hold logical partitions. We parse
these recursively.

Design: Pure parsing — no disk I/O in this module. Caller provides bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Partition type codes — the most forensically relevant ones
PARTITION_TYPES: dict[int, str] = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32MB",
    0x05: "Extended (CHS)",
    0x06: "FAT16 >32MB",
    0x07: "NTFS/exFAT/HPFS",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 <32MB",
    0x16: "Hidden FAT16 >32MB",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32 (CHS)",
    0x1C: "Hidden FAT32 (LBA)",
    0x1E: "Hidden FAT16 (LBA)",
    0x27: "Windows RE",
    0x42: "Windows Dynamic",
    0x82: "Linux swap",
    0x83: "Linux native",
    0x85: "Linux extended",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xAF: "macOS HFS+",
    0xBE: "Solaris boot",
    0xBF: "Solaris",
    0xEE: "GPT Protective",
    0xEF: "EFI System",
    0xFD: "Linux RAID",
}


@dataclass
class MBRPartitionEntry:
    """Parsed MBR partition table entry."""

    index: int              # 0-3 for primary, 4+ for logical
    status: int             # 0x80=bootable, 0x00=inactive
    type_code: int          # Partition type byte
    type_name: str          # Human-readable type name
    lba_start: int          # First sector (absolute LBA)
    size_sectors: int       # Partition size in sectors
    is_bootable: bool       # status == 0x80
    is_extended: bool       # type is 0x05 or 0x0F
    is_empty: bool          # type_code == 0x00

    @property
    def size_bytes(self) -> int:
        """Partition size in bytes (assuming 512-byte sectors)."""
        return self.size_sectors * 512

    @property
    def lba_end(self) -> int:
        """Last sector (inclusive) of this partition."""
        return self.lba_start + self.size_sectors - 1 if self.size_sectors > 0 else self.lba_start

    def __repr__(self) -> str:
        return (
            f"MBRPartitionEntry(#{self.index}, {self.type_name}, "
            f"LBA={self.lba_start}–{self.lba_end}, "
            f"sectors={self.size_sectors})"
        )


class MBRParser:
    """Parse MBR partition table from raw 512-byte sector data.

    Usage::

        mbr_data = reader.read_sector(0)
        parser = MBRParser()
        result = parser.parse(mbr_data)
        if result.is_valid:
            for entry in result.partitions:
                print(entry)
    """

    @dataclass
    class Result:
        """MBR parse result."""
        is_valid: bool
        is_protective_gpt: bool  # If True, this is a GPT disk (parse GPT instead)
        partitions: list[MBRPartitionEntry]
        raw_bootstrap: bytes = b""

    def parse(self, data: bytes, sector_size: int = 512) -> "MBRParser.Result":
        """Parse an MBR from raw sector data.

        Args:
            data: At least 512 bytes of LBA 0.
            sector_size: Sector size (default 512).

        Returns:
            MBRParser.Result with validity flag and partition list.
        """
        if len(data) < 512:
            logger.warning("MBR data too short: %d bytes", len(data))
            return MBRParser.Result(is_valid=False, is_protective_gpt=False, partitions=[])

        # Check boot signature
        sig = struct.unpack_from('<H', data, 510)[0]
        if sig != 0xAA55:
            logger.debug("MBR signature invalid: 0x%04X (expected 0xAA55)", sig)
            return MBRParser.Result(is_valid=False, is_protective_gpt=False, partitions=[])

        partitions: list[MBRPartitionEntry] = []
        is_protective = False

        # Parse 4 primary partition entries at offset 446
        for i in range(4):
            offset = 446 + (i * 16)
            entry = self._parse_entry(data, offset, index=i)
            if not entry.is_empty:
                partitions.append(entry)
                if entry.type_code == 0xEE:
                    is_protective = True

        logger.info(
            "MBR parsed: %d partition(s), protective_gpt=%s",
            len(partitions), is_protective,
        )

        return MBRParser.Result(
            is_valid=True,
            is_protective_gpt=is_protective,
            partitions=partitions,
            raw_bootstrap=data[:446],
        )

    def parse_extended(
        self, read_fn, ebr_lba: int, ext_start_lba: int, logical_index: int = 4
    ) -> list[MBRPartitionEntry]:
        """Follow the EBR chain to parse logical partitions.

        Extended partitions contain a linked list of EBRs. Each EBR
        has the same 16-byte entry format as MBR but only uses slots 0-1:
        - Entry 0: The logical partition (LBA relative to this EBR)
        - Entry 1: Pointer to next EBR (LBA relative to ext_start_lba)

        Args:
            read_fn: Callable(lba) -> bytes that reads a sector.
            ebr_lba: Absolute LBA of the first EBR.
            ext_start_lba: Absolute LBA where the extended partition begins
                           (used for calculating next EBR position).
            logical_index: Starting index number for logical partitions.

        Returns:
            List of logical MBRPartitionEntry items.
        """
        logical: list[MBRPartitionEntry] = []
        current_ebr = ebr_lba
        idx = logical_index
        visited: set[int] = set()  # Prevent infinite loops from corrupt chains

        while current_ebr != 0 and current_ebr not in visited:
            visited.add(current_ebr)
            data = read_fn(current_ebr)
            if len(data) < 512:
                break

            # Check EBR signature
            sig = struct.unpack_from('<H', data, 510)[0]
            if sig != 0xAA55:
                break

            # Entry 0: logical partition (LBA relative to this EBR)
            entry0 = self._parse_entry(data, 446, index=idx)
            if not entry0.is_empty:
                # Convert relative LBA to absolute
                entry0 = MBRPartitionEntry(
                    index=idx,
                    status=entry0.status,
                    type_code=entry0.type_code,
                    type_name=entry0.type_name,
                    lba_start=current_ebr + entry0.lba_start,
                    size_sectors=entry0.size_sectors,
                    is_bootable=entry0.is_bootable,
                    is_extended=entry0.is_extended,
                    is_empty=False,
                )
                logical.append(entry0)
                idx += 1

            # Entry 1: pointer to next EBR (LBA relative to ext_start_lba)
            entry1 = self._parse_entry(data, 462, index=-1)
            if entry1.is_empty or entry1.lba_start == 0:
                break

            current_ebr = ext_start_lba + entry1.lba_start

        logger.debug("Extended partition: found %d logical partition(s)", len(logical))
        return logical

    @staticmethod
    def _parse_entry(data: bytes, offset: int, index: int) -> MBRPartitionEntry:
        """Parse a single 16-byte partition entry."""
        status = data[offset]
        type_code = data[offset + 4]
        lba_start = struct.unpack_from('<I', data, offset + 8)[0]
        size_sectors = struct.unpack_from('<I', data, offset + 12)[0]

        type_name = PARTITION_TYPES.get(type_code, f"Unknown (0x{type_code:02X})")

        return MBRPartitionEntry(
            index=index,
            status=status,
            type_code=type_code,
            type_name=type_name,
            lba_start=lba_start,
            size_sectors=size_sectors,
            is_bootable=(status == 0x80),
            is_extended=(type_code in (0x05, 0x0F, 0x85)),
            is_empty=(type_code == 0x00 and lba_start == 0 and size_sectors == 0),
        )
