"""WebP signature — RIFF container with WEBP fourcc at offset 8."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class WebPSignature(BaseSignature):
    name = "WebP Image"
    extension = "webp"
    category = "images"
    headers = [b'RIFF']
    footer = None
    max_size = 30 * 1024 * 1024

    def match_header(self, data: bytes, offset: int) -> bool:
        # RIFF header + WEBP fourcc at offset 8
        if offset + 12 > len(data):
            return False
        return data[offset:offset+4] == b'RIFF' and data[offset+8:offset+12] == b'WEBP'

    def get_size(self, data: bytes, offset: int) -> int | None:
        # RIFF file size at offset 4 (LE uint32) + 8 bytes for RIFF header
        if len(data) < offset + 8:
            return None
        riff_size = struct.unpack_from('<I', data, offset + 4)[0]
        total = riff_size + 8
        if total > self.max_size or total < 12:
            return None
        return total
