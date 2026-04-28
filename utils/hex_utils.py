"""
pyrecovery.utils.hex_utils — Hex formatting utilities for forensic display.

Provides classic hex dump output (like ``xxd`` or ``hexdump -C``) and
compact hex string conversion for logging and reporting.
"""

from __future__ import annotations


def hex_dump(data: bytes, offset: int = 0, width: int = 16) -> str:
    """Format raw bytes as a classic hex dump with ASCII sidebar.

    Args:
        data: Raw bytes to format.
        offset: Starting byte offset for display (cosmetic, for alignment).
        width: Number of bytes per line (default 16).

    Returns:
        Multi-line string in the format::

            00000000  89 50 4E 47 0D 0A 1A 0A  00 00 00 0D 49 48 44 52  |.PNG........IHDR|

    Example:
        >>> print(hex_dump(b"Hello, World!", offset=0))
        00000000  48 65 6C 6C 6F 2C 20 57  6F 72 6C 64 21           |Hello, World!   |
    """
    lines: list[str] = []

    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        addr = f"{offset + i:08X}"

        # Hex portion: split into two groups of width/2 for readability
        hex_parts: list[str] = []
        for j, byte in enumerate(chunk):
            if j == width // 2:
                hex_parts.append("")  # Extra space at midpoint
            hex_parts.append(f"{byte:02X}")

        hex_str = " ".join(hex_parts)
        # Pad to fixed width so ASCII column aligns
        expected_len = width * 3 + 1  # 3 chars per byte + 1 midpoint space
        hex_str = hex_str.ljust(expected_len)

        # ASCII portion: replace non-printable bytes with '.'
        ascii_str = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        ascii_str = ascii_str.ljust(width)

        lines.append(f"{addr}  {hex_str} |{ascii_str}|")

    return "\n".join(lines)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to a compact hex string with spaces.

    Args:
        data: Raw bytes to convert.

    Returns:
        Space-separated hex string, e.g. ``"FF D8 FF E0"``.

    Example:
        >>> bytes_to_hex(b'\\xff\\xd8\\xff\\xe0')
        'FF D8 FF E0'
    """
    return " ".join(f"{b:02X}" for b in data)


def compare_bytes(a: bytes, b: bytes) -> list[int]:
    """Find byte offsets where two byte sequences differ.

    Args:
        a: First byte sequence.
        b: Second byte sequence.

    Returns:
        Sorted list of offsets where ``a[i] != b[i]``.
        Only compares up to ``min(len(a), len(b))``.
        If lengths differ, all extra positions are included.

    Example:
        >>> compare_bytes(b'\\x00\\x01\\x02', b'\\x00\\xFF\\x02')
        [1]
    """
    max_len = max(len(a), len(b))
    diffs: list[int] = []

    for i in range(max_len):
        byte_a = a[i] if i < len(a) else None
        byte_b = b[i] if i < len(b) else None
        if byte_a != byte_b:
            diffs.append(i)

    return diffs
