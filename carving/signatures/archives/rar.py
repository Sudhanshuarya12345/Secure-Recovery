"""RAR4/RAR5 signatures."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class RAR4Signature(BaseSignature):
    name = "RAR4 Archive"
    extension = "rar"
    category = "archives"
    headers = [b'Rar!\x1a\x07\x00']
    footer = b'\xc4\x3d\x7b\x00\x40\x07\x00'
    max_size = 200 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # Scan for footer

class RAR5Signature(BaseSignature):
    name = "RAR5 Archive"
    extension = "rar5"
    category = "archives"
    headers = [b'Rar!\x1a\x07\x01\x00']
    footer = None
    max_size = 200 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None
