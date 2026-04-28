"""
pyrecovery.advanced.encryption.bitlocker_detector — BitLocker volume detection.

BitLocker (Windows full-disk encryption) signatures:

Method 1 — Boot sector signature:
  Offset 3: "-FVE-FS-" (8 bytes) — BitLocker metadata marker
  This replaces the normal OEM ID ("NTFS    " or "MSDOS5.0")

Method 2 — BitLocker metadata block:
  Contains a GUID identifying the encryption type:
  - FVE metadata signature: "\\xeb\\x52\\x90-FVE-FS-"
  - Or at specific offsets within the volume

Method 3 — BitLocker To Go (removable media):
  Boot sector starts with normal FAT32 BPB but contains
  BitLocker metadata in reserved sectors.

BitLocker metadata fields:
  +0:    Boot entry point (3 bytes)
  +3:    "-FVE-FS-" signature (8 bytes)
  +11:   Bytes per sector (2 bytes)
  +160:  Volume GUID (16 bytes)
  +424:  FVE metadata block offsets (3 × 8 bytes)

NOTE: This module DETECTS and REPORTS only. It never attempts decryption.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class BitLockerInfo:
    """Detected BitLocker encrypted volume information."""
    signature_type: str       # "fve_fs", "bitlocker_togo", "metadata"
    volume_guid: str          # Volume GUID if parseable
    offset: int               # Byte offset where signature was found
    bytes_per_sector: int     # From boot sector BPB
    encrypted_size: int       # Estimated encrypted region size (if available)
    metadata_offsets: list[int]  # FVE metadata block offsets
    description: str          # Human-readable summary

    @property
    def is_valid(self) -> bool:
        return self.signature_type != ""


class BitLockerDetector:
    """Detect BitLocker encrypted volumes.

    Usage::

        detector = BitLockerDetector()
        info = detector.detect(boot_sector_data, offset=0)
        if info:
            print(f"BitLocker detected: {info.description}")
            print(f"Volume GUID: {info.volume_guid}")
    """

    FVE_SIGNATURE = b'-FVE-FS-'

    def detect(self, data: bytes, offset: int = 0) -> BitLockerInfo | None:
        """Check data for BitLocker signatures.

        Args:
            data: Raw bytes (at least 512 bytes for boot sector).
            offset: Byte offset for reporting.

        Returns:
            BitLockerInfo if BitLocker detected, None otherwise.
        """
        if len(data) < 512:
            return None

        # Method 1: Check for -FVE-FS- at offset 3
        if data[3:11] == self.FVE_SIGNATURE:
            return self._parse_fve_boot(data, offset)

        # Method 2: Check for BitLocker To Go marker
        # BitLocker To Go still has valid FAT32 BPB but with BitLocker metadata
        if data[0] in (0xEB, 0xE9):
            # Check deeper in the boot sector for BitLocker markers
            for search_offset in range(0, min(len(data) - 8, 512)):
                if data[search_offset:search_offset + 8] == self.FVE_SIGNATURE:
                    return self._parse_fve_boot(data, offset)

        # Method 3: Search for FVE metadata signature in larger data
        if len(data) >= 1024:
            for search_offset in (0x00, 0x200, 0x10000, 0x20000):
                if search_offset + 8 <= len(data):
                    if data[search_offset + 3:search_offset + 11] == self.FVE_SIGNATURE:
                        return self._parse_fve_metadata(
                            data[search_offset:], offset + search_offset
                        )

        return None

    def detect_at_offset(
        self, reader, byte_offset: int
    ) -> BitLockerInfo | None:
        """Detect BitLocker at a specific byte offset using a DiskReader.

        Args:
            reader: DiskReader instance.
            byte_offset: Absolute byte offset to check.

        Returns:
            BitLockerInfo if found, None otherwise.
        """
        data = reader.read_at(byte_offset, 1024)
        return self.detect(data, offset=byte_offset)

    def scan_disk(
        self, reader, step_sectors: int = 2048, max_sectors: int = 0
    ) -> list[BitLockerInfo]:
        """Scan disk for BitLocker signatures.

        Args:
            reader: DiskReader instance.
            step_sectors: Sector interval between probes.
            max_sectors: Max sectors to scan (0 = full disk).

        Returns:
            List of BitLockerInfo for all detected volumes.
        """
        results: list[BitLockerInfo] = []
        sector_size = reader.sector_size
        total = max_sectors or reader.get_sector_count()

        for lba in range(0, total, step_sectors):
            data = reader.read_at(lba * sector_size, 1024)
            info = self.detect(data, offset=lba * sector_size)
            if info:
                results.append(info)
                logger.info(
                    "BitLocker found at offset %d: %s",
                    info.offset, info.description,
                )

        return results

    def _parse_fve_boot(self, data: bytes, offset: int) -> BitLockerInfo:
        """Parse BitLocker FVE boot sector."""
        bps = struct.unpack_from('<H', data, 11)[0] if len(data) >= 13 else 512

        # Volume GUID at offset 160 (16 bytes, mixed-endian like GPT)
        volume_guid = ""
        if len(data) >= 176:
            try:
                guid_bytes = data[160:176]
                volume_guid = str(uuid.UUID(bytes_le=guid_bytes)).upper()
            except (ValueError, AssertionError):
                volume_guid = ""

        # FVE metadata block offsets at offset 424 (3 × 8 bytes)
        metadata_offsets: list[int] = []
        if len(data) >= 448:
            for i in range(3):
                meta_offset = struct.unpack_from('<Q', data, 424 + i * 8)[0]
                if meta_offset > 0:
                    metadata_offsets.append(meta_offset)

        # Total sectors for size estimation
        total_sectors = 0
        if len(data) >= 80:
            total_sectors = struct.unpack_from('<Q', data, 40)[0]

        return BitLockerInfo(
            signature_type="fve_fs",
            volume_guid=volume_guid,
            offset=offset,
            bytes_per_sector=bps,
            encrypted_size=total_sectors * bps,
            metadata_offsets=metadata_offsets,
            description=f"BitLocker FVE-FS volume (GUID={volume_guid[:8]}...)" if volume_guid else "BitLocker FVE-FS volume",
        )

    def _parse_fve_metadata(self, data: bytes, offset: int) -> BitLockerInfo:
        """Parse BitLocker FVE metadata block."""
        bps = struct.unpack_from('<H', data, 11)[0] if len(data) >= 13 else 512

        return BitLockerInfo(
            signature_type="metadata",
            volume_guid="",
            offset=offset,
            bytes_per_sector=bps,
            encrypted_size=0,
            metadata_offsets=[],
            description="BitLocker FVE metadata block",
        )
