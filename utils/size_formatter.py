"""
pyrecovery.utils.size_formatter — Human-readable size formatting and parsing.

Handles conversion between raw byte counts and human-friendly strings
like "4.2 GB" or "512 KB", and the reverse ("64k" → 65536).
"""

from __future__ import annotations

import re

# Binary size units (IEC standard: powers of 1024)
_SIZE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]

# Pattern for parsing human-readable sizes: "64k", "1.5GB", "512 MB", "100"
_SIZE_PATTERN = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*([KMGTPE]?B?|[KMGTPE])\s*$",
    re.IGNORECASE,
)

# Multiplier lookup (case-insensitive key → bytes)
_UNIT_MULTIPLIERS: dict[str, int] = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "m": 1024 ** 2,
    "mb": 1024 ** 2,
    "g": 1024 ** 3,
    "gb": 1024 ** 3,
    "t": 1024 ** 4,
    "tb": 1024 ** 4,
    "p": 1024 ** 5,
    "pb": 1024 ** 5,
    "e": 1024 ** 6,
    "eb": 1024 ** 6,
}


def format_size(size_bytes: int) -> str:
    """Convert a byte count to a human-readable string.

    Uses binary units (1 KB = 1024 bytes) which is standard in disk/forensic
    contexts where sector alignment matters.

    Args:
        size_bytes: Size in bytes (must be >= 0).

    Returns:
        Formatted string like ``"4.2 GB"``, ``"512 B"``, ``"0 B"``.

    Examples:
        >>> format_size(0)
        '0 B'
        >>> format_size(1536)
        '1.5 KB'
        >>> format_size(1073741824)
        '1.0 GB'
    """
    if size_bytes < 0:
        raise ValueError(f"Size cannot be negative: {size_bytes}")
    if size_bytes == 0:
        return "0 B"

    value = float(size_bytes)
    for unit in _SIZE_UNITS:
        if abs(value) < 1024.0:
            if value == int(value) and unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0

    # Reached exabytes — format with last unit
    return f"{value:.1f} {_SIZE_UNITS[-1]}"


def parse_size(size_str: str) -> int:
    """Parse a human-readable size string into bytes.

    Accepts formats like ``"64k"``, ``"1.5GB"``, ``"512 MB"``, ``"4096"``.
    Case-insensitive. The ``B`` suffix is optional.

    Args:
        size_str: Human-readable size string.

    Returns:
        Size in bytes as an integer.

    Raises:
        ValueError: If the string cannot be parsed.

    Examples:
        >>> parse_size("64k")
        65536
        >>> parse_size("1.5 GB")
        1610612736
        >>> parse_size("4096")
        4096
    """
    # Try plain integer first
    stripped = size_str.strip()
    try:
        return int(stripped)
    except ValueError:
        pass

    match = _SIZE_PATTERN.match(stripped)
    if not match:
        raise ValueError(
            f"Cannot parse size string: '{size_str}'. "
            f"Expected format: '64k', '1.5GB', '512 MB', etc."
        )

    number = float(match.group(1))
    unit = match.group(2).lower()

    if unit not in _UNIT_MULTIPLIERS:
        raise ValueError(f"Unknown size unit: '{match.group(2)}'")

    return int(number * _UNIT_MULTIPLIERS[unit])
