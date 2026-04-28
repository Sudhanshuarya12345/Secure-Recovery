"""
pyrecovery.disk.platform_devices — Cross-platform physical storage device enumeration.

Each OS has its own way of discovering and querying storage devices:
- Linux: /proc/partitions, /sys/block/*, /dev/sd* and /dev/nvme*
- macOS: diskutil command, /dev/disk* and /dev/rdisk*
- Windows: \\\\.\\PhysicalDriveN, WMI/DeviceIoControl for metadata

This module normalizes all of that into a uniform DeviceInfo interface.

Security note:
    Enumerating devices is read-only (stat, open+close, subprocess for diskutil/wmic).
    We never mount, modify, or write to any discovered device.
"""

from __future__ import annotations

import glob
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.logger import get_logger
from utils.platform_utils import get_os, UnsupportedPlatformError

logger = get_logger(__name__)


@dataclass
class DeviceInfo:
    """Normalized information about a physical storage device."""

    path: str               # /dev/sda, \\.\PhysicalDrive0, or E:
    size_bytes: int = 0     # Total device size
    model: str = "Unknown"  # Device model name
    removable: bool = False # USB/SD card = True
    partitions: list[str] = field(default_factory=list)  # ["/dev/sda1", ...]
    fs_type: str = ""       # Filesystem type (FAT32, NTFS, etc.)
    label: str = ""         # Volume label

    @property
    def size_display(self) -> str:
        """Human-readable size."""
        from utils.size_formatter import format_size
        return format_size(self.size_bytes)


def list_devices() -> list[DeviceInfo]:
    """Enumerate physical storage devices on the current platform.

    Returns:
        List of DeviceInfo for each discovered device.
        Returns empty list (not error) if no devices are accessible.
        Logs a warning if elevated privileges are needed.

    This function never raises on failure — device enumeration is best-effort.
    Physical disk access still requires elevated privileges even if enumeration succeeds.
    """
    current_os = get_os()

    try:
        if current_os == "linux":
            return _list_linux_devices()
        elif current_os == "darwin":
            return _list_macos_devices()
        elif current_os == "windows":
            return _list_windows_devices()
    except Exception as e:
        logger.warning("Device enumeration failed: %s", e)
        return []

    return []


def get_device_size(path: str) -> int:
    """Get the size of a specific device in bytes.

    Args:
        path: Device path (e.g., ``/dev/sda``, ``\\\\.\\PhysicalDrive0``).

    Returns:
        Size in bytes, or 0 if size cannot be determined.

    Works by opening the device read-only and seeking to the end.
    """
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            return f.tell()
    except (OSError, PermissionError) as e:
        logger.debug("Cannot get size for %s: %s", path, e)
        return 0


# ── Linux implementation ────────────────────────────────────────────────

def _list_linux_devices() -> list[DeviceInfo]:
    """Enumerate devices on Linux via /proc/partitions and /sys/block/.

    Filters out virtual devices (loop, ram, dm-).
    Reads model and removable flag from sysfs.
    """
    devices: list[DeviceInfo] = []
    skip_prefixes = ("loop", "ram", "dm-", "zram")

    proc_partitions = Path("/proc/partitions")
    if not proc_partitions.exists():
        logger.warning("/proc/partitions not found")
        return devices

    try:
        lines = proc_partitions.read_text().strip().split("\n")
    except OSError as e:
        logger.warning("Cannot read /proc/partitions: %s", e)
        return devices

    # Skip header lines (first two lines: header + blank)
    for line in lines[2:]:
        parts = line.split()
        if len(parts) < 4:
            continue

        name = parts[3]

        # Skip virtual devices
        if any(name.startswith(p) for p in skip_prefixes):
            continue

        # Only enumerate whole disks (sda, nvme0n1), not partitions (sda1)
        dev_path = f"/dev/{name}"

        # Check if it's a whole disk (has entries in /sys/block/)
        sys_block = Path(f"/sys/block/{name}")
        if not sys_block.exists():
            continue

        # Size: /sys/block/{name}/size contains sector count (512-byte sectors)
        size_bytes = 0
        size_file = sys_block / "size"
        if size_file.exists():
            try:
                sectors = int(size_file.read_text().strip())
                size_bytes = sectors * 512
            except (ValueError, OSError):
                pass

        # Model
        model = "Unknown"
        model_file = sys_block / "device" / "model"
        if model_file.exists():
            try:
                model = model_file.read_text().strip()
            except OSError:
                pass

        # Removable flag
        removable = False
        removable_file = sys_block / "removable"
        if removable_file.exists():
            try:
                removable = removable_file.read_text().strip() == "1"
            except OSError:
                pass

        # Find partitions
        partitions = sorted(
            f"/dev/{p.name}"
            for p in sys_block.iterdir()
            if p.is_dir() and p.name.startswith(name)
        )

        devices.append(DeviceInfo(
            path=dev_path,
            size_bytes=size_bytes,
            model=model,
            removable=removable,
            partitions=partitions,
        ))

    logger.info("Linux device scan: found %d device(s)", len(devices))
    return devices


# ── macOS implementation ────────────────────────────────────────────────

def _list_macos_devices() -> list[DeviceInfo]:
    """Enumerate devices on macOS using diskutil.

    Runs ``diskutil list`` and parses output for /dev/disk* entries.
    Then queries each disk with ``diskutil info`` for size and model.
    """
    devices: list[DeviceInfo] = []

    try:
        result = subprocess.run(
            ["diskutil", "list"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            logger.warning("diskutil list failed: %s", result.stderr)
            return devices
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("diskutil not available: %s", e)
        return devices

    # Parse output for /dev/disk* lines
    disk_names: list[str] = []
    for line in result.stdout.split("\n"):
        line = line.strip()
        if line.startswith("/dev/disk") and not line.startswith("/dev/disk0s"):
            # Extract disk identifier (e.g., /dev/disk0)
            disk_path = line.split()[0].rstrip(":")
            if disk_path not in disk_names:
                disk_names.append(disk_path)

    for disk_path in disk_names:
        try:
            info_result = subprocess.run(
                ["diskutil", "info", disk_path],
                capture_output=True, text=True, timeout=10,
            )
            if info_result.returncode != 0:
                continue
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        size_bytes = 0
        model = "Unknown"
        removable = False

        for line in info_result.stdout.split("\n"):
            line = line.strip()
            if "Disk Size:" in line:
                # "Disk Size: 500.1 GB (500107862016 Bytes)..."
                try:
                    size_str = line.split("(")[1].split(" ")[0]
                    size_bytes = int(size_str)
                except (IndexError, ValueError):
                    pass
            elif "Device / Media Name:" in line:
                model = line.split(":", 1)[1].strip()
            elif "Removable Media:" in line:
                removable = "removable" in line.lower() or "yes" in line.lower()

        # Find partitions
        partitions = sorted(glob.glob(f"{disk_path}s*"))

        devices.append(DeviceInfo(
            path=disk_path,
            size_bytes=size_bytes,
            model=model,
            removable=removable,
            partitions=partitions,
        ))

    logger.info("macOS device scan: found %d device(s)", len(devices))
    return devices


# ── Windows implementation ──────────────────────────────────────────────

def _list_windows_devices() -> list[DeviceInfo]:
    """Enumerate devices on Windows using logical drives AND physical drives.

    Strategy (no admin required for logical drives):
    1. Use kernel32.GetLogicalDrives() to find all drive letters (C:, D:, E:, ...)
    2. Use GetDriveTypeW() to identify removable/fixed/network/cdrom
    3. Use GetVolumeInformationW() for filesystem type and volume label
    4. Use GetDiskFreeSpaceExW() for size information

    If running as Admin, also probe PhysicalDrive paths for raw disk access.
    """
    devices: list[DeviceInfo] = []

    # ── Phase 1: Logical drives (always works, no admin needed) ─────
    try:
        devices.extend(_list_windows_logical_drives())
    except Exception as e:
        logger.warning("Logical drive enumeration failed: %s", e)

    # ── Phase 2: Physical drives (needs admin, best-effort) ─────────
    try:
        phys = _list_windows_physical_drives()
        devices.extend(phys)
    except Exception as e:
        logger.debug("Physical drive enumeration skipped (no admin): %s", e)

    logger.info("Windows device scan: found %d device(s)", len(devices))
    return devices


def _list_windows_logical_drives() -> list[DeviceInfo]:
    """Enumerate logical drives using kernel32 APIs (no admin required).

    Uses:
    - GetLogicalDrives() → bitmask of available drive letters
    - GetDriveTypeW() → drive type (removable, fixed, network, cdrom)
    - GetVolumeInformationW() → filesystem name, volume label
    - GetDiskFreeSpaceExW() → free/total bytes
    """
    import ctypes
    import ctypes.wintypes
    import shutil

    kernel32 = ctypes.windll.kernel32
    devices: list[DeviceInfo] = []

    # Drive type constants
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_REMOTE = 4
    DRIVE_CDROM = 5

    bitmask = kernel32.GetLogicalDrives()
    if bitmask == 0:
        return devices

    for i in range(26):
        if not (bitmask & (1 << i)):
            continue

        letter = chr(ord("A") + i)
        root = f"{letter}:\\"
        drive_path = f"{letter}:"

        # Get drive type
        drive_type = kernel32.GetDriveTypeW(root)

        # Skip network and unknown drives
        if drive_type not in (DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_CDROM):
            continue

        # Determine type label
        if drive_type == DRIVE_REMOVABLE:
            type_label = "USB/Removable"
            is_removable = True
        elif drive_type == DRIVE_CDROM:
            type_label = "CD/DVD"
            is_removable = True
        else:
            type_label = "Fixed Disk"
            is_removable = False

        # Get volume information (filesystem type, label)
        fs_type = ""
        vol_label = ""
        try:
            vol_name_buf = ctypes.create_unicode_buffer(261)
            fs_name_buf = ctypes.create_unicode_buffer(261)
            serial = ctypes.wintypes.DWORD(0)
            max_len = ctypes.wintypes.DWORD(0)
            flags = ctypes.wintypes.DWORD(0)

            success = kernel32.GetVolumeInformationW(
                root,
                vol_name_buf, 261,
                ctypes.byref(serial),
                ctypes.byref(max_len),
                ctypes.byref(flags),
                fs_name_buf, 261,
            )
            if success:
                fs_type = fs_name_buf.value  # "NTFS", "FAT32", "exFAT", etc.
                vol_label = vol_name_buf.value
        except Exception:
            pass

        # Get size information
        size_bytes = 0
        try:
            usage = shutil.disk_usage(root)
            size_bytes = usage.total
        except Exception:
            pass

        # Build display name
        model = vol_label if vol_label else type_label
        if vol_label:
            model = f"{vol_label} ({type_label})"

        devices.append(DeviceInfo(
            path=f"\\\\.\\{letter}:",
            size_bytes=size_bytes,
            model=model,
            removable=is_removable,
            partitions=[],
            fs_type=fs_type,
            label=vol_label,
        ))

    return devices


def _list_windows_physical_drives() -> list[DeviceInfo]:
    """Enumerate physical drives (requires admin for raw access).

    Tries opening \\\\.\\PhysicalDrive0 through \\\\.\\PhysicalDrive15.
    Uses WMI (via ``wmic``) for model and removable info when available.
    """
    devices: list[DeviceInfo] = []
    wmi_info = _get_wmi_disk_info()

    for i in range(16):
        drive_path = f"\\\\.\\PhysicalDrive{i}"
        size_bytes = 0

        try:
            # Try to open and get size
            with open(drive_path, "rb") as f:
                f.seek(0, 2)
                size_bytes = f.tell()
        except (OSError, PermissionError):
            continue  # Drive doesn't exist or no access

        # Look up WMI info if available
        model = wmi_info.get(i, {}).get("model", "Unknown")
        removable = wmi_info.get(i, {}).get("removable", False)

        devices.append(DeviceInfo(
            path=drive_path,
            size_bytes=size_bytes,
            model=model,
            removable=removable,
            partitions=[],
        ))

    return devices


def _get_wmi_disk_info() -> dict[int, dict]:
    """Query WMI for disk model and media type via ``wmic``.

    Returns:
        Dict mapping drive index to {"model": str, "removable": bool}.
    """
    info: dict[int, dict] = {}

    try:
        result = subprocess.run(
            ["wmic", "diskdrive", "get", "Index,Model,MediaType", "/format:csv"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        if result.returncode != 0:
            return info
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return info

    for line in result.stdout.strip().split("\n"):
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue
        try:
            index = int(parts[1])
            media_type = parts[2]
            model = parts[3] if len(parts) > 3 else "Unknown"
            info[index] = {
                "model": model,
                "removable": "removable" in media_type.lower(),
            }
        except (ValueError, IndexError):
            continue

    return info

