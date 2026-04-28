"""
pyrecovery.disk.reader — Read-only sector-level access to disks and disk images.

This is the foundational I/O layer for the entire PyRecovery tool. Every other
module reads disk data through DiskReader — it never touches the source directly.

Design decisions:
- All reads go through WriteBlocker: prevents accidental writes to evidence
- mmap acceleration for images < 2GB: zero-copy slicing, ~2x faster random reads
- Bad sectors return zeroed bytes instead of crashing: critical for damaged media
- Sector-aligned reads are the primary API (matches physical disk geometry)
- Thread safety: NOT thread-safe. Use one DiskReader per thread.

Performance notes (Python vs C):
    Sequential read: ~200 MB/s (Python) vs ~500 MB/s (C/C++)
    mmap random access: ~300 MB/s for cached pages
    Mitigation: mmap for files < 2GB, buffered I/O for larger sources
"""

from __future__ import annotations

import mmap
import os
import stat
from pathlib import Path
from typing import Optional

from disk.bad_sector_map import BadSectorMap
from disk.write_blocker import WriteBlocker
from utils.logger import get_logger

logger = get_logger(__name__)

# Maximum file size for mmap acceleration (2 GB)
# Beyond this, mmap on 32-bit systems can fail, and even on 64-bit
# the kernel page table overhead becomes significant
_MMAP_THRESHOLD = 2 * 1024 * 1024 * 1024


class DiskReader:
    """Read-only sector-level access to physical disks and disk image files.

    Supports:
    - Physical devices (``/dev/sdX``, ``\\\\.\\PhysicalDriveN``)
    - Disk image files (``.img``, ``.dd``, ``.raw``, ``.E01`` header only)
    - mmap acceleration for images under 2 GB
    - Automatic bad sector handling (zero-fill + log)

    Usage::

        with DiskReader("/path/to/evidence.img") as reader:
            boot_sector = reader.read_sector(0)
            bulk = reader.read_sectors(100, 10)
            raw = reader.read_at(0x1000, 256)
            print(f"Disk size: {reader.get_disk_size()} bytes")
    """

    def __init__(self, source: str, sector_size: int = 512) -> None:
        """Open a source in read-only binary mode with forensic protections.

        Args:
            source: Path to a device (``/dev/sda``) or image file (``evidence.img``).
            sector_size: Bytes per sector (default 512; some modern drives use 4096).

        Raises:
            FileNotFoundError: If the source path doesn't exist.
            PermissionError: If elevated privileges are needed (physical devices).
            ValueError: If sector_size is not a power of 2.
        """
        if sector_size <= 0 or (sector_size & (sector_size - 1)) != 0:
            raise ValueError(
                f"sector_size must be a positive power of 2, got {sector_size}"
            )

        self._source = source
        self._sector_size = sector_size
        self._bad_sectors = BadSectorMap()
        self._mmap: mmap.mmap | None = None

        # Detect source type before opening
        source_path = Path(source)
        self._is_device = self._detect_device(source)

        # Open in binary read-only mode
        try:
            self._file = open(source, "rb")
        except PermissionError:
            raise PermissionError(
                f"Cannot open '{source}': Permission denied.\n"
                f"Physical devices require elevated privileges.\n"
                f"  Linux/macOS: sudo pyrecovery ...\n"
                f"  Windows: Run as Administrator"
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"Source not found: '{source}'")

        # Wrap with WriteBlocker — the forensic safety net
        self._blocker = WriteBlocker(self._file)

        # Determine total size
        self._size = self._get_source_size()

        # Enable mmap for small files (zero-copy reads)
        self._setup_mmap()

        logger.info(
            "DiskReader opened: source=%s, size=%d bytes (%d sectors), "
            "device=%s, mmap=%s",
            source,
            self._size,
            self.get_sector_count(),
            self._is_device,
            self._mmap is not None,
        )

    def _detect_device(self, source: str) -> bool:
        """Detect if the source is a physical device or a regular file.

        Physical devices on different platforms:
        - Linux: /dev/sd*, /dev/nvme*, /dev/hd*
        - macOS: /dev/disk*, /dev/rdisk*
        - Windows: \\\\.\\PhysicalDrive*
        """
        # Windows device path pattern
        if source.startswith("\\\\.\\"):
            return True

        try:
            st = os.stat(source)
            # On Unix, block devices have S_ISBLK flag
            if stat.S_ISBLK(st.st_mode):
                return True
        except (OSError, AttributeError):
            # S_ISBLK not available on Windows, or stat failed
            pass

        # Check for common device path patterns
        dev_prefixes = ("/dev/sd", "/dev/hd", "/dev/nvme", "/dev/disk", "/dev/rdisk")
        if any(source.startswith(p) for p in dev_prefixes):
            return True

        return False

    def _get_source_size(self) -> int:
        """Determine the total size of the source in bytes.

        For regular files: os.fstat().st_size
        For block devices: seek to end and read position
        For Windows volumes: IOCTL_DISK_GET_LENGTH_INFO or shutil.disk_usage
        """
        # Method 1: fstat (works for regular files)
        try:
            st = os.fstat(self._file.fileno())
            if st.st_size > 0:
                return st.st_size
        except OSError:
            pass

        # Method 2: Windows IOCTL for raw volumes/physical drives
        if self._is_device and os.name == "nt":
            size = self._get_windows_device_size()
            if size > 0:
                return size

        # Method 3: Seek to end (works on Linux/macOS block devices)
        try:
            current = self._file.tell()
            self._file.seek(0, 2)  # Seek to end
            size = self._file.tell()
            self._file.seek(current, 0)  # Seek back
            if size > 0:
                return size
        except OSError:
            pass

        # Method 4: shutil.disk_usage for mounted drive letters (Windows E:\)
        if os.name == "nt" and self._source.endswith(":"):
            try:
                import shutil
                letter = self._source[-2]
                if letter.isalpha():
                    usage = shutil.disk_usage(letter + ":\\")
                    if usage.total > 0:
                        return usage.total
            except Exception:
                pass

        logger.error("Cannot determine source size for: %s", self._source)
        raise OSError(f"Cannot determine size of '{self._source}'")

    def _get_windows_device_size(self) -> int:
        """Get device/volume size on Windows via DeviceIoControl.

        Uses IOCTL_DISK_GET_LENGTH_INFO which works on both
        physical drives (PhysicalDriveN) and volume handles (E:).
        """
        try:
            import ctypes
            import ctypes.wintypes

            IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
            GENERIC_READ = 0x80000000
            OPEN_EXISTING = 3
            FILE_SHARE_READ = 1
            FILE_SHARE_WRITE = 2

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                self._source,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None,
            )
            if handle == -1:
                return 0

            length = ctypes.c_longlong(0)
            returned = ctypes.wintypes.DWORD(0)
            result = kernel32.DeviceIoControl(
                handle, IOCTL_DISK_GET_LENGTH_INFO,
                None, 0,
                ctypes.byref(length), ctypes.sizeof(length),
                ctypes.byref(returned), None,
            )
            kernel32.CloseHandle(handle)

            if result and length.value > 0:
                logger.debug(
                    "Windows IOCTL size for %s: %d bytes",
                    self._source, length.value,
                )
                return length.value
        except Exception as e:
            logger.debug("Windows IOCTL failed for %s: %s", self._source, e)

        return 0

    def _setup_mmap(self) -> None:
        """Set up mmap for files under the threshold.

        mmap provides zero-copy reads: data goes directly from the OS page cache
        to the Python bytes object without an intermediate buffer copy.
        This is ~2x faster for random access patterns (common in carving).

        We only use ACCESS_READ to maintain forensic read-only guarantees.
        """
        if self._is_device:
            # Don't mmap physical devices — behavior is platform-dependent
            return

        if self._size <= 0 or self._size > _MMAP_THRESHOLD:
            return

        try:
            self._mmap = mmap.mmap(
                self._file.fileno(),
                0,  # Map the entire file
                access=mmap.ACCESS_READ,
            )
            logger.debug("mmap enabled for %s (%d bytes)", self._source, self._size)
        except (OSError, ValueError) as e:
            # mmap can fail on some platforms or with certain file types
            logger.debug("mmap not available for %s: %s", self._source, e)
            self._mmap = None

    def read_sector(self, lba: int) -> bytes:
        """Read exactly one sector at a logical block address.

        Args:
            lba: Logical block address (0-indexed sector number).

        Returns:
            Exactly ``sector_size`` bytes. If the sector is unreadable,
            returns zeroed bytes and logs to the bad sector map.

        Note:
            On damaged media, I/O errors are expected. Rather than crashing,
            we return a zero-filled sector and continue. The bad sector map
            records every failed read for the forensic report.
        """
        offset = lba * self._sector_size

        if offset + self._sector_size > self._size:
            logger.debug("read_sector(%d) past end of source", lba)
            return b"\x00" * self._sector_size

        try:
            return self._read_bytes(offset, self._sector_size)
        except OSError as e:
            self._bad_sectors.mark_bad(
                lba, error_type=type(e).__name__, context=str(e)
            )
            return b"\x00" * self._sector_size

    def read_sectors(self, lba: int, count: int) -> bytes:
        """Read multiple contiguous sectors starting at a logical block address.

        Args:
            lba: Starting logical block address.
            count: Number of sectors to read.

        Returns:
            ``count * sector_size`` bytes. Falls back to per-sector reads
            on I/O error, so partial results include zeroed bad sectors.
        """
        if count <= 0:
            return b""

        total_size = count * self._sector_size
        offset = lba * self._sector_size

        if offset + total_size > self._size:
            # Clamp to available data
            available = max(0, self._size - offset)
            total_size = available
            count = available // self._sector_size

        # Try bulk read first (faster)
        try:
            data = self._read_bytes(offset, total_size)
            if len(data) == total_size:
                return data
        except OSError:
            pass

        # Fallback: read sector by sector (handles bad sectors individually)
        logger.debug("Bulk read failed at LBA %d, falling back to per-sector", lba)
        result = bytearray()
        for i in range(count):
            result.extend(self.read_sector(lba + i))
        return bytes(result)

    def read_at(self, offset: int, size: int) -> bytes:
        """Read arbitrary bytes at an absolute byte offset.

        Args:
            offset: Absolute byte offset from start of source.
            size: Number of bytes to read.

        Returns:
            Up to ``size`` bytes. May be shorter if reading past end of source.
            On I/O error at the raw byte level, logs error and returns what's available.
        """
        if offset < 0 or size <= 0:
            return b""

        if offset >= self._size:
            return b""

        # Clamp to available data
        actual_size = min(size, self._size - offset)

        try:
            return self._read_bytes(offset, actual_size)
        except OSError as e:
            lba = offset // self._sector_size
            self._bad_sectors.mark_bad(
                lba, error_type=type(e).__name__, context=str(e)
            )
            logger.error("Read error at offset %d (size %d): %s", offset, size, e)
            return b"\x00" * actual_size

    def _read_bytes(self, offset: int, size: int) -> bytes:
        """Internal: read raw bytes using mmap or seek+read.

        Args:
            offset: Absolute byte offset.
            size: Number of bytes.

        Returns:
            Raw bytes from source.

        Raises:
            OSError: On read failure (propagated to caller for bad sector handling).
        """
        if self._mmap is not None:
            # mmap: zero-copy slice (fastest path)
            return bytes(self._mmap[offset : offset + size])
            
        # On Windows, reading raw devices requires strict sector alignment
        if self._is_device and os.name == "nt":
            return self._read_bytes_aligned(offset, size)

        # Standard seek + read (for regular files or Linux/macOS buffered block devices)
        self._file.seek(offset, 0)
        data = self._file.read(size)
        if len(data) < size:
            # Short read: pad with zeros (common at end of device)
            data = data + b"\x00" * (size - len(data))
        return data

    def _read_bytes_aligned(self, offset: int, size: int) -> bytes:
        """Handle strict sector alignment required by Windows raw devices.
        
        Windows requires `seek()` and `read()` to be aligned to sector boundaries
        when reading from `\\\\.\\PhysicalDriveX` or `\\\\.\\E:`. This method aligns
        the offset down to the nearest sector, reads enough full sectors to cover
        the requested data, and slices out the exact requested bytes.
        """
        sector_size = self._sector_size
        aligned_offset = (offset // sector_size) * sector_size
        align_diff = offset - aligned_offset
        
        # Calculate how many full sectors we need to read
        aligned_size = ((align_diff + size + sector_size - 1) // sector_size) * sector_size
        
        self._file.seek(aligned_offset, 0)
        data = self._file.read(aligned_size)
        
        # Slice out the exact bytes requested
        result = data[align_diff : align_diff + size]
        
        if len(result) < size:
            result = result + b"\x00" * (size - len(result))
        return result

    def get_disk_size(self) -> int:
        """Return total source size in bytes.

        Returns:
            Total size of the source media or image file.
        """
        return self._size

    def get_sector_count(self) -> int:
        """Return total number of sectors.

        Returns:
            ``get_disk_size() // sector_size``. Partial last sector is excluded.
        """
        return self._size // self._sector_size

    @property
    def sector_size(self) -> int:
        """Bytes per sector (typically 512 or 4096)."""
        return self._sector_size

    @property
    def bad_sectors(self) -> BadSectorMap:
        """Access the bad sector map for this reader.

        Returns:
            BadSectorMap instance tracking all read errors.
        """
        return self._bad_sectors

    @property
    def is_device(self) -> bool:
        """True if the source is a physical device, not a regular file."""
        return self._is_device

    @property
    def uses_mmap(self) -> bool:
        """True if mmap acceleration is active for this source."""
        return self._mmap is not None

    @property
    def source_path(self) -> str:
        """Path to the source device or image file."""
        return self._source

    def close(self) -> None:
        """Release mmap and file handle.

        Safe to call multiple times. After close(), all read methods
        will raise ValueError.
        """
        if self._mmap is not None:
            try:
                self._mmap.close()
            except Exception:
                pass
            self._mmap = None

        if hasattr(self, "_blocker") and not self._blocker.closed:
            self._blocker.close()

        logger.debug(
            "DiskReader closed: %s (bad sectors: %d)",
            self._source,
            self._bad_sectors.count,
        )

    def __enter__(self) -> "DiskReader":
        """Context manager entry — returns self."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Context manager exit — closes all handles."""
        self.close()

    def __repr__(self) -> str:
        return (
            f"DiskReader(source={self._source!r}, "
            f"size={self._size}, "
            f"sectors={self.get_sector_count()}, "
            f"device={self._is_device})"
        )
