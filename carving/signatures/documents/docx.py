"""DOCX/XLSX/PPTX signature — ZIP-based Office Open XML format.
Uses PK header (50 4B 03 04) with internal structure validation."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class DOCXSignature(BaseSignature):
    name = "Office DOCX/XLSX/PPTX"
    extension = "docx"
    category = "documents"
    headers = [b'PK\x03\x04']
    footer = b'PK\x05\x06'  # End of central directory record
    max_size = 100 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # Scan for EOCD footer

    def validate(self, data: bytes) -> bool:
        if len(data) < 30:
            return False
        # Check for [Content_Types].xml or word/ or xl/ or ppt/ in the ZIP
        # These distinguish Office docs from generic ZIPs
        text = data[:8192]
        return (b'[Content_Types].xml' in text or b'word/' in text or
                b'xl/' in text or b'ppt/' in text)
