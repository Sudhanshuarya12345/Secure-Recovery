"""PNG signature — 89504E47 header, IEND chunk footer."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class PNGSignature(BaseSignature):
    name = "PNG Image"
    extension = "png"
    category = "images"
    headers = [b'\x89PNG\r\n\x1a\n']
    footer = b'IEND\xae\x42\x60\x82'
    max_size = 30 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # Scan for IEND chunk

    def validate(self, data: bytes) -> bool:
        if len(data) < 24:
            return False
        # IHDR chunk type must be at offset 12
        return data[12:16] == b'IHDR'
