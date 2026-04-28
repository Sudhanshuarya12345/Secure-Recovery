"""JPEG signature — FF D8 FF (multiple JFIF/EXIF/plain variants), footer FF D9."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class JPEGSignature(BaseSignature):
    name = "JPEG Image"
    extension = "jpg"
    category = "images"
    headers = [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xdb',
               b'\xff\xd8\xff\xee', b'\xff\xd8\xff\xfe']
    footer = b'\xff\xd9'
    min_size = 100
    max_size = 25 * 1024 * 1024  # 25 MB

    def get_size(self, data: bytes, offset: int) -> int | None:
        # JPEG has no single size field; must scan for FFD9 footer
        return None

    def validate(self, data: bytes) -> bool:
        if len(data) < 4:
            return False
        # Must start with FF D8 FF
        if data[0:3] != b'\xff\xd8\xff':
            return False
        # Must end with FF D9 (allow trailing garbage up to 2 bytes)
        if data[-2:] == b'\xff\xd9':
            return True
        if len(data) > 4 and data[-3:-1] == b'\xff\xd9':
            return True
        # If carved by max_size, footer may be missing — still accept
        return True
