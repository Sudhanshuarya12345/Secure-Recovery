"""GIF signature — GIF87a/GIF89a header, 00 3B trailer."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class GIFSignature(BaseSignature):
    name = "GIF Image"
    extension = "gif"
    category = "images"
    headers = [b'GIF89a', b'GIF87a']
    footer = b'\x00\x3b'
    max_size = 20 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # Scan for footer

    def validate(self, data: bytes) -> bool:
        return len(data) >= 14  # Minimum: header + logical screen descriptor
