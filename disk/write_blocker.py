"""
pyrecovery.disk.write_blocker — Software write-blocker for forensic safety.

Design rationale:
    In digital forensics, *any* write to evidence media — even a single byte —
    can invalidate the entire chain of custody and make evidence inadmissible
    in court. Hardware write-blockers are standard equipment in forensics labs,
    but they're not always available (especially for disk image files).

    This module provides equivalent protection in software by wrapping a file
    object and intercepting all write-family operations. Any attempted write
    raises ``WriteBlockerViolation`` with a full stack trace, making it
    immediately obvious which code path attempted the forbidden operation.

Usage::

    with WriteBlocker(open("/dev/sdb", "rb")) as wb:
        data = wb.read(512)     # OK — reads are proxied transparently
        wb.write(b"\\x00")      # BLOCKED — raises WriteBlockerViolation
"""

from __future__ import annotations

import traceback
from datetime import datetime, timezone
from typing import BinaryIO, NoReturn, Any

from utils.logger import get_logger

logger = get_logger(__name__)


class WriteBlockerViolation(Exception):
    """Raised when a write operation is attempted on a forensically-protected source.

    This exception is intentionally NOT a subclass of IOError/OSError because
    it represents a *logic error* in the application (something tried to write
    to evidence), not a transient I/O condition. It should never be caught
    in normal application flow.
    """
    pass


class WriteBlocker:
    """Software write-blocker that wraps a binary file object.

    Transparently proxies all read operations. Intercepts and blocks:
    ``write()``, ``writelines()``, ``truncate()``.

    Every blocked attempt is logged with:
    - ISO 8601 timestamp
    - The specific operation attempted
    - Full Python call stack (for debugging the offending code)

    Thread safety: NOT thread-safe. Use one WriteBlocker per thread.
    """

    def __init__(self, file_obj: BinaryIO) -> None:
        """Wrap a binary file object with write protection.

        Args:
            file_obj: An open binary file object (must support read/seek/tell).

        Note:
            The file_obj should already be opened in read-only mode ('rb').
            The WriteBlocker is a safety net — it catches programming errors
            where code accidentally calls write() on a forensic source.
        """
        self._file = file_obj
        self._violation_count = 0
        logger.debug(
            "WriteBlocker active on %s",
            getattr(file_obj, "name", repr(file_obj)),
        )

    # ── Proxied read operations (transparent pass-through) ──────────────

    def read(self, size: int = -1) -> bytes:
        """Read up to ``size`` bytes from the underlying file.

        Args:
            size: Maximum bytes to read. -1 reads to EOF.

        Returns:
            Raw bytes read from the source.
        """
        return self._file.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek to a position in the underlying file.

        Args:
            offset: Byte offset.
            whence: Reference point (0=start, 1=current, 2=end).

        Returns:
            The new absolute position.
        """
        return self._file.seek(offset, whence)

    def tell(self) -> int:
        """Return the current file position.

        Returns:
            Absolute byte position in the file.
        """
        return self._file.tell()

    def readable(self) -> bool:
        """Indicate that this stream supports reading.

        Returns:
            Always True.
        """
        return True

    def writable(self) -> bool:
        """Indicate that this stream does NOT support writing.

        Returns:
            Always False. This is a read-only forensic wrapper.
        """
        return False

    def seekable(self) -> bool:
        """Indicate whether the underlying stream supports seeking.

        Returns:
            True if the underlying file is seekable.
        """
        return self._file.seekable()

    @property
    def name(self) -> str:
        """Name/path of the underlying file."""
        return getattr(self._file, "name", "<unknown>")

    @property
    def closed(self) -> bool:
        """Whether the underlying file is closed."""
        return self._file.closed

    def fileno(self) -> int:
        """Return the underlying file descriptor.

        Needed for mmap() and os.fstat() to work through the wrapper.
        """
        return self._file.fileno()

    # ── Blocked write operations ────────────────────────────────────────

    def _block_write(self, operation: str) -> NoReturn:
        """Block a write operation and raise WriteBlockerViolation.

        Args:
            operation: Name of the blocked operation for logging.

        Raises:
            WriteBlockerViolation: Always raised with full context.
        """
        self._violation_count += 1
        timestamp = datetime.now(timezone.utc).isoformat()
        stack = traceback.format_stack()
        stack_str = "".join(stack[:-1])  # Exclude this frame

        source_name = getattr(self._file, "name", repr(self._file))

        logger.critical(
            "WRITE BLOCKER VIOLATION #%d at %s\n"
            "Operation: %s\n"
            "Source: %s\n"
            "Call stack:\n%s",
            self._violation_count,
            timestamp,
            operation,
            source_name,
            stack_str,
        )

        raise WriteBlockerViolation(
            f"FORENSIC VIOLATION: {operation}() attempted on protected source "
            f"'{source_name}' at {timestamp}. "
            f"This is violation #{self._violation_count}. "
            f"Evidence integrity may be compromised if this write succeeded."
        )

    def write(self, data: Any) -> NoReturn:
        """BLOCKED: Writing to forensic evidence is forbidden.

        Raises:
            WriteBlockerViolation: Always.
        """
        self._block_write("write")

    def writelines(self, lines: Any) -> NoReturn:
        """BLOCKED: Writing to forensic evidence is forbidden.

        Raises:
            WriteBlockerViolation: Always.
        """
        self._block_write("writelines")

    def truncate(self, size: Any = None) -> NoReturn:
        """BLOCKED: Truncating forensic evidence is forbidden.

        Raises:
            WriteBlockerViolation: Always.
        """
        self._block_write("truncate")

    # ── Lifecycle ───────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying file handle."""
        if not self._file.closed:
            self._file.close()
            logger.debug("WriteBlocker released (violations: %d)", self._violation_count)

    def __enter__(self) -> "WriteBlocker":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit — closes the file."""
        self.close()

    def __repr__(self) -> str:
        source = getattr(self._file, "name", repr(self._file))
        return f"WriteBlocker(source={source}, violations={self._violation_count})"
