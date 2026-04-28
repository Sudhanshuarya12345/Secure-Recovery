"""
pyrecovery.carving.base_signature — Abstract base class for file format signatures.

Every supported file format implements this interface. A signature defines:
1. How to DETECT the file (magic byte headers + optional secondary check)
2. How to SIZE the file (parse header for declared size, or scan for footer)
3. How to VALIDATE a carved file (structural integrity check)

Design rationale:
- headers is a list because many formats have multiple magic variants
  (e.g., JPEG has FF D8 FF E0, FF D8 FF E1, FF D8 FF DB, FF D8 FF EE)
- header_offset handles formats where magic isn't at byte 0
  (e.g., MP4 has 'ftyp' at offset 4, not 0)
- get_size() returns None when size can't be parsed from the header,
  forcing the engine to fall back to footer scanning or max_size
- validate() is a post-carve check to reject false positives
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseSignature(ABC):
    """Abstract base class for all file format signatures.

    Subclasses MUST set: name, extension, category, headers
    Subclasses MUST implement: get_size()
    Subclasses SHOULD override: validate() for format-specific integrity checks
    """

    # ── Required class attributes (set by subclass) ─────────────────

    name: str = ""
    """Human-readable format name, e.g. 'JPEG Image'."""

    extension: str = ""
    """File extension without dot, e.g. 'jpg'."""

    category: str = ""
    """Output category: 'images', 'documents', 'archives', 'media', 'system'."""

    headers: list[bytes] = []
    """Magic byte sequences that identify this format.
    Multiple entries for formats with variant headers."""

    # ── Optional tuning (override in subclass as needed) ────────────

    header_offset: int = 0
    """Byte offset where the header appears within the file.
    Most formats have headers at offset 0. MP4 has 'ftyp' at offset 4."""

    footer: bytes | None = None
    """End-of-file marker bytes, if the format defines one.
    Used for footer-scanning when get_size() returns None."""

    min_size: int = 512
    """Minimum valid file size in bytes. Files smaller than this are rejected."""

    max_size: int = 50 * 1024 * 1024
    """Maximum extraction size in bytes (default 50 MB).
    Used as the upper bound when scanning for footers or when size is unknown."""

    # ── Abstract methods ────────────────────────────────────────────

    @abstractmethod
    def get_size(self, data: bytes, offset: int) -> int | None:
        """Parse the file header/structure to determine exact file size.

        Args:
            data: Raw bytes buffer containing at least max_size bytes from offset.
            offset: Position in the buffer where the file header was found.

        Returns:
            Exact file size in bytes if determinable from the header, or None
            if size cannot be parsed. When None is returned, the carving engine
            falls back to footer scanning (if footer is defined) or max_size.

        Implementation notes:
            - Use struct.unpack for binary field parsing
            - Be defensive: check bounds before every read
            - Return None rather than guessing when header is malformed
        """

    # ── Optional overrides ──────────────────────────────────────────

    def validate(self, data: bytes) -> bool:
        """Post-carve structural validation of the extracted file.

        Called after extraction with the full carved file data. Return False
        to reject the file (it will be placed in partial/ instead of the
        category folder).

        Args:
            data: Complete carved file bytes.

        Returns:
            True if the file passes structural validation, False otherwise.

        Default implementation always returns True. Override for format-specific
        checks (e.g., verify JPEG has valid markers, PDF has xref table).
        """
        return True

    # ── Built-in methods ────────────────────────────────────────────

    def match_header(self, data: bytes, offset: int) -> bool:
        """Check if any registered header matches at the given position.

        Handles header_offset: for a format like MP4 where the 'ftyp' magic
        is at file offset 4, the engine finds potential matches by checking
        data[offset + header_offset].

        Args:
            data: Raw bytes buffer.
            offset: Position to check (this is where the file would start).

        Returns:
            True if any header variant matches at the expected position.
        """
        check_pos = offset + self.header_offset

        for header in self.headers:
            end_pos = check_pos + len(header)
            if end_pos > len(data):
                continue
            if data[check_pos:end_pos] == header:
                return True

        return False

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"name={self.name!r}, ext={self.extension!r}, "
            f"category={self.category!r}, "
            f"headers={len(self.headers)}, "
            f"footer={'yes' if self.footer else 'no'})"
        )
