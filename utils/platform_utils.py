"""
pyrecovery.utils.platform_utils — Cross-platform OS detection and privilege checks.

Centralizes all platform-specific logic so the rest of the codebase can use
simple ``if/elif`` on normalized OS names instead of scattered ``platform.system()``
calls with inconsistent casing.
"""

from __future__ import annotations

import os
import platform
from typing import Literal


def get_os() -> Literal["linux", "darwin", "windows"]:
    """Return a normalized OS identifier.

    Returns:
        One of ``"linux"``, ``"darwin"``, or ``"windows"``.

    Raises:
        UnsupportedPlatformError: If the OS is not supported.
    """
    os_name = platform.system().lower()
    if os_name == "linux":
        return "linux"
    elif os_name == "darwin":
        return "darwin"
    elif os_name == "windows":
        return "windows"
    else:
        raise UnsupportedPlatformError(f"Unsupported operating system: {platform.system()}")


def is_admin() -> bool:
    """Check if the current process has elevated (root/Administrator) privileges.

    Returns:
        True if running as root (Unix) or Administrator (Windows).

    Design note:
        Physical disk access requires elevated privileges on all major OSes.
        This check allows PyRecovery to give a helpful error message early
        rather than failing with a cryptic PermissionError deep in I/O code.
    """
    current_os = get_os()

    if current_os in ("linux", "darwin"):
        return os.getuid() == 0  # type: ignore[attr-defined]
    elif current_os == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    return False


def require_admin(operation: str) -> None:
    """Raise PermissionError with a helpful message if not running elevated.

    Args:
        operation: Description of the operation that requires elevation,
                   e.g. "access physical disk /dev/sda".

    Raises:
        PermissionError: If the process lacks elevated privileges.
    """
    if not is_admin():
        current_os = get_os()
        if current_os in ("linux", "darwin"):
            hint = "Run with: sudo pyrecovery ..."
        else:
            hint = "Run as Administrator: right-click → 'Run as administrator'"

        raise PermissionError(
            f"Elevated privileges required to {operation}.\n{hint}"
        )


class UnsupportedPlatformError(Exception):
    """Raised when PyRecovery encounters an unsupported operating system."""
    pass
