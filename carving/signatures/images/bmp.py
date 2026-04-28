"""BMP signature — 42 4D header, file size at bytes 2-5."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class BMPSignature(BaseSignature):
    name = "BMP Image"
    extension = "bmp"
    category = "images"
    headers = [b'BM']
    footer = None
    max_size = 50 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        # BMP file size stored as LE uint32 at offset 2 (per BMP spec)
        if len(data) < offset + 6:
            return None
        size = struct.unpack_from('<I', data, offset + 2)[0]
        if 14 <= size <= self.max_size:
            return size
        return None

    def validate(self, data: bytes) -> bool:
        if len(data) < 26:
            return False
        # Check DIB header size at offset 14 (should be 12, 40, 108, or 124)
        dib_size = struct.unpack_from('<I', data, 14)[0]
        return dib_size in (12, 40, 52, 56, 108, 124)
