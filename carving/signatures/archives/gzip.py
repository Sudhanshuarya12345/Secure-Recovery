"""GZIP signature — 1F 8B 08 (deflate compression method)."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class GZIPSignature(BaseSignature):
    name = "GZIP Archive"
    extension = "gz"
    category = "archives"
    headers = [b'\x1f\x8b\x08']
    footer = None
    max_size = 100 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

    def validate(self, data: bytes) -> bool:
        if len(data) < 10:
            return False
        # Byte 2 must be 0x08 (deflate compression)
        return data[2] == 0x08
