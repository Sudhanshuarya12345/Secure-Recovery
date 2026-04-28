"""SQLite signature — 'SQLite format 3\\x00' (16-byte header).
Size from page_size * page_count."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class SQLiteSignature(BaseSignature):
    name = "SQLite Database"
    extension = "sqlite"
    category = "system"
    headers = [b'SQLite format 3\x00']
    footer = None
    max_size = 200 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        if len(data) < offset + 32:
            return None
        # Page size at offset 16 (BE uint16). Value 1 means 65536.
        page_size = struct.unpack_from('>H', data, offset + 16)[0]
        if page_size == 1:
            page_size = 65536
        # Page count at offset 28 (BE uint32)
        page_count = struct.unpack_from('>I', data, offset + 28)[0]
        if page_count == 0:
            return None
        total = page_size * page_count
        return total if total <= self.max_size else None
