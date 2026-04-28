"""ZIP signature — PK 03 04 local file header, PK 05 06 end of central directory."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class ZIPSignature(BaseSignature):
    name = "ZIP Archive"
    extension = "zip"
    category = "archives"
    headers = [b'PK\x03\x04']
    footer = b'PK\x05\x06'
    max_size = 200 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # Scan for EOCD footer

    def validate(self, data: bytes) -> bool:
        # Must not be a DOCX (those have [Content_Types].xml)
        if b'[Content_Types].xml' in data[:8192]:
            return False  # Let DOCX signature handle it
        return len(data) >= 22  # Minimum ZIP size (empty archive)
