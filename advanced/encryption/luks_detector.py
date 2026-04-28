"""
pyrecovery.advanced.encryption.luks_detector — LUKS encrypted volume detection.

LUKS (Linux Unified Key Setup) uses a well-defined header format:

LUKS1 Header (offset 0 from partition start):
  +0:    Magic "LUKS\\xBA\\xBE" (6 bytes)
  +6:    Version (2 bytes, big-endian) — 0x0001 for LUKS1
  +8:    Cipher name (32 bytes, null-terminated ASCII)
  +40:   Cipher mode (32 bytes, null-terminated ASCII)
  +72:   Hash spec (32 bytes, null-terminated ASCII)
  +104:  Payload offset (4 bytes, big-endian) — start of encrypted data
  +108:  Key bytes (4 bytes, big-endian) — master key length
  +112:  MK digest (20 bytes) — PBKDF2 of master key
  +132:  MK digest salt (32 bytes)
  +164:  MK digest iterations (4 bytes, big-endian)
  +168:  UUID (40 bytes, null-terminated)
  +208:  Key slots (8 × 48 bytes = 384 bytes)

LUKS2 Header:
  +0:    Magic "LUKS\\xBA\\xBE" (6 bytes)
  +6:    Version (2 bytes) — 0x0002 for LUKS2
  +8:    Header size (8 bytes)
  +16:   Sequence ID (8 bytes)
  +24:   Label (48 bytes)
  +72:   Checksum algorithm (32 bytes)
  +104:  Salt (64 bytes)
  +168:  UUID (40 bytes)
  ... followed by JSON metadata area

NOTE: This module DETECTS and REPORTS only. It never attempts decryption.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class LUKSInfo:
    """Detected LUKS encrypted volume information."""
    version: int              # 1 or 2
    cipher_name: str          # e.g., "aes"
    cipher_mode: str          # e.g., "xts-plain64"
    hash_spec: str            # e.g., "sha256"
    uuid: str                 # Volume UUID
    key_bytes: int            # Master key length (e.g., 32 = AES-256)
    payload_offset: int       # Sector offset where encrypted data begins
    key_slots_active: int     # Number of active key slots
    key_slots_total: int      # Total key slots (8 for LUKS1)
    offset: int               # Byte offset where LUKS header was found
    header_size: int           # Header size in bytes

    @property
    def encryption_description(self) -> str:
        """Human-readable encryption description."""
        key_bits = self.key_bytes * 8
        return f"{self.cipher_name.upper()}-{key_bits} {self.cipher_mode}"


class LUKSDetector:
    """Detect LUKS encrypted volumes on disk.

    Usage::

        detector = LUKSDetector()
        info = detector.detect(data, offset=0)
        if info:
            print(f"LUKS{info.version} found: {info.encryption_description}")
            print(f"UUID: {info.uuid}")
    """

    MAGIC = b'LUKS\xba\xbe'

    def detect(self, data: bytes, offset: int = 0) -> LUKSInfo | None:
        """Check data for LUKS header.

        Args:
            data: Raw bytes (at least 592 bytes for LUKS1 header).
            offset: Byte offset for reporting purposes.

        Returns:
            LUKSInfo if LUKS header found, None otherwise.
        """
        if len(data) < 208:
            return None

        # Check magic
        if data[0:6] != self.MAGIC:
            return None

        version = struct.unpack_from('>H', data, 6)[0]

        if version == 1:
            return self._parse_luks1(data, offset)
        elif version == 2:
            return self._parse_luks2(data, offset)
        else:
            logger.debug("Unknown LUKS version: %d", version)
            return None

    def detect_at_offset(
        self, reader, byte_offset: int
    ) -> LUKSInfo | None:
        """Detect LUKS at a specific byte offset using a DiskReader.

        Args:
            reader: DiskReader instance.
            byte_offset: Absolute byte offset to check.

        Returns:
            LUKSInfo if found, None otherwise.
        """
        data = reader.read_at(byte_offset, 1024)
        return self.detect(data, offset=byte_offset)

    def scan_disk(
        self, reader, step_sectors: int = 2048, max_sectors: int = 0
    ) -> list[LUKSInfo]:
        """Scan disk for LUKS headers at regular intervals.

        Args:
            reader: DiskReader instance.
            step_sectors: Sector interval between probes.
            max_sectors: Maximum sectors to scan (0 = full disk).

        Returns:
            List of LUKSInfo for all detected volumes.
        """
        results: list[LUKSInfo] = []
        sector_size = reader.sector_size
        total = max_sectors or reader.get_sector_count()

        for lba in range(0, total, step_sectors):
            data = reader.read_at(lba * sector_size, 1024)
            info = self.detect(data, offset=lba * sector_size)
            if info:
                results.append(info)
                logger.info(
                    "LUKS%d found at offset %d: %s",
                    info.version, info.offset, info.encryption_description,
                )

        return results

    def _parse_luks1(self, data: bytes, offset: int) -> LUKSInfo | None:
        """Parse LUKS1 header."""
        if len(data) < 592:
            return None

        cipher_name = data[8:40].split(b'\x00')[0].decode('ascii', errors='replace')
        cipher_mode = data[40:72].split(b'\x00')[0].decode('ascii', errors='replace')
        hash_spec = data[72:104].split(b'\x00')[0].decode('ascii', errors='replace')

        payload_offset = struct.unpack_from('>I', data, 104)[0]
        key_bytes = struct.unpack_from('>I', data, 108)[0]

        uuid_bytes = data[168:208].split(b'\x00')[0]
        uuid_str = uuid_bytes.decode('ascii', errors='replace')

        # Count active key slots (8 slots, each 48 bytes starting at 208)
        active_slots = 0
        for i in range(8):
            slot_offset = 208 + i * 48
            if slot_offset + 4 > len(data):
                break
            slot_active = struct.unpack_from('>I', data, slot_offset)[0]
            if slot_active == 0x00AC71F3:  # LUKS_KEY_ENABLED
                active_slots += 1

        return LUKSInfo(
            version=1,
            cipher_name=cipher_name,
            cipher_mode=cipher_mode,
            hash_spec=hash_spec,
            uuid=uuid_str,
            key_bytes=key_bytes,
            payload_offset=payload_offset,
            key_slots_active=active_slots,
            key_slots_total=8,
            offset=offset,
            header_size=592,
        )

    def _parse_luks2(self, data: bytes, offset: int) -> LUKSInfo | None:
        """Parse LUKS2 header (basic fields)."""
        if len(data) < 208:
            return None

        # LUKS2 has JSON metadata — we parse just the fixed header
        header_size = struct.unpack_from('>Q', data, 8)[0] if len(data) >= 16 else 4096

        label = data[24:72].split(b'\x00')[0].decode('ascii', errors='replace')
        checksum_algo = data[72:104].split(b'\x00')[0].decode('ascii', errors='replace')
        uuid_bytes = data[168:208].split(b'\x00')[0]
        uuid_str = uuid_bytes.decode('ascii', errors='replace')

        return LUKSInfo(
            version=2,
            cipher_name="(see JSON metadata)",
            cipher_mode="(see JSON metadata)",
            hash_spec=checksum_algo,
            uuid=uuid_str,
            key_bytes=0,
            payload_offset=0,
            key_slots_active=0,
            key_slots_total=32,  # LUKS2 supports up to 32 key slots
            offset=offset,
            header_size=int(header_size),
        )
