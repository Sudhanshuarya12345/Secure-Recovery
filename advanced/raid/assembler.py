"""
pyrecovery.advanced.raid.assembler — Virtual RAID disk assembly.

Translates virtual read operations on an assembled RAID array into
physical read operations on individual member disk images.

RAID 0 (Striping):
  Data is interleaved across N disks in fixed-size stripes.
  Virtual offset → (disk_index, physical_offset) mapping:

    stripe_number = virtual_offset // stripe_size
    disk_index    = stripe_number % num_disks
    disk_stripe   = stripe_number // num_disks
    disk_offset   = disk_stripe * stripe_size + (virtual_offset % stripe_size)

All reads are READ-ONLY. No data is written to member disks.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class VirtualDisk:
    """Virtual RAID 0 disk that maps reads to physical member disks.

    Provides a read_at() interface identical to DiskReader,
    allowing it to be used with carving/filesystem parsers.

    Usage::

        vdisk = assemble_raid0(["disk1.img", "disk2.img"], stripe_size=65536)
        data = vdisk.read_at(0, 4096)  # Reads from correct physical disk
        vdisk.close()
    """

    def __init__(
        self,
        disk_handles: list[BinaryIO],
        disk_paths: list[str],
        stripe_size: int,
        disk_sizes: list[int],
    ) -> None:
        self._handles = disk_handles
        self._paths = disk_paths
        self._stripe_size = stripe_size
        self._disk_sizes = disk_sizes
        self._num_disks = len(disk_handles)
        self._closed = False

        # Calculate usable size per disk (rounded down to stripe boundary)
        min_size = min(disk_sizes)
        self._usable_per_disk = (min_size // stripe_size) * stripe_size
        self._total_size = self._usable_per_disk * self._num_disks

    @property
    def total_size(self) -> int:
        """Total virtual disk size in bytes."""
        return self._total_size

    @property
    def stripe_size(self) -> int:
        return self._stripe_size

    @property
    def num_disks(self) -> int:
        return self._num_disks

    @property
    def sector_size(self) -> int:
        """Compatibility with DiskReader interface."""
        return 512

    def read_at(self, offset: int, size: int) -> bytes:
        """Read bytes from the virtual RAID 0 disk.

        Translates virtual offset to physical (disk, offset) and reads.

        Args:
            offset: Virtual byte offset.
            size: Number of bytes to read.

        Returns:
            Read bytes. May be shorter than requested at end of disk.
        """
        if self._closed:
            raise RuntimeError("VirtualDisk is closed")

        if offset >= self._total_size:
            return b""

        # Clamp to available data
        available = self._total_size - offset
        read_size = min(size, available)

        result = bytearray()
        remaining = read_size
        current_offset = offset

        while remaining > 0:
            # Map virtual offset to physical
            disk_idx, disk_offset, bytes_in_stripe = self._map_offset(current_offset)

            # Read up to end of current stripe
            chunk_size = min(remaining, bytes_in_stripe)

            handle = self._handles[disk_idx]
            handle.seek(disk_offset)
            chunk = handle.read(chunk_size)

            if not chunk:
                break

            result.extend(chunk)
            remaining -= len(chunk)
            current_offset += len(chunk)

        return bytes(result)

    def read_sector(self, lba: int) -> bytes:
        """Read a single 512-byte sector. Compatibility with DiskReader."""
        return self.read_at(lba * 512, 512)

    def get_sector_count(self) -> int:
        """Total virtual sectors."""
        return self._total_size // 512

    def get_disk_size(self) -> int:
        """Total virtual disk size."""
        return self._total_size

    def close(self) -> None:
        """Close all member disk handles."""
        if not self._closed:
            for h in self._handles:
                try:
                    h.close()
                except Exception:
                    pass
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _map_offset(self, virtual_offset: int) -> tuple[int, int, int]:
        """Map virtual offset to (disk_index, disk_offset, bytes_remaining_in_stripe).

        RAID 0 striping formula:
          stripe_number = virtual_offset // stripe_size
          disk_index    = stripe_number % num_disks
          disk_stripe   = stripe_number // num_disks
          stripe_offset = virtual_offset % stripe_size
          disk_offset   = disk_stripe * stripe_size + stripe_offset
          remaining     = stripe_size - stripe_offset
        """
        stripe_num = virtual_offset // self._stripe_size
        disk_idx = stripe_num % self._num_disks
        disk_stripe = stripe_num // self._num_disks
        stripe_offset = virtual_offset % self._stripe_size
        disk_offset = disk_stripe * self._stripe_size + stripe_offset
        remaining = self._stripe_size - stripe_offset

        return disk_idx, disk_offset, remaining


def assemble_raid0(
    disk_paths: list[str],
    stripe_size: int,
    disk_order: list[int] | None = None,
) -> VirtualDisk:
    """Assemble a RAID 0 virtual disk from member images.

    Args:
        disk_paths: Paths to member disk images.
        stripe_size: Stripe size in bytes.
        disk_order: Optional custom disk ordering (indices into disk_paths).

    Returns:
        VirtualDisk instance ready for reading.

    Raises:
        ValueError: If fewer than 2 disks or invalid stripe size.
        FileNotFoundError: If any disk image doesn't exist.
    """
    if len(disk_paths) < 2:
        raise ValueError(f"RAID 0 requires at least 2 disks, got {len(disk_paths)}")

    if stripe_size <= 0 or (stripe_size & (stripe_size - 1)) != 0:
        raise ValueError(f"Stripe size must be a power of 2, got {stripe_size}")

    # Apply custom ordering
    if disk_order:
        ordered_paths = [disk_paths[i] for i in disk_order]
    else:
        ordered_paths = list(disk_paths)

    # Open all disk images read-only
    handles: list[BinaryIO] = []
    sizes: list[int] = []

    try:
        for path in ordered_paths:
            if not Path(path).exists():
                raise FileNotFoundError(f"Disk image not found: {path}")
            size = os.path.getsize(path)
            handle = open(path, "rb")
            handles.append(handle)
            sizes.append(size)
    except Exception:
        # Clean up on error
        for h in handles:
            h.close()
        raise

    logger.info(
        "RAID 0 assembled: %d disks, stripe=%dKB, total=%d bytes",
        len(handles), stripe_size // 1024,
        (min(sizes) // stripe_size) * stripe_size * len(handles),
    )

    return VirtualDisk(
        disk_handles=handles,
        disk_paths=ordered_paths,
        stripe_size=stripe_size,
        disk_sizes=sizes,
    )
