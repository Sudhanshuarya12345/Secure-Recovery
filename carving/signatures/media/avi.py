"""AVI signature — RIFF container with AVI fourcc."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class AVISignature(BaseSignature):
    name = "AVI Video"
    extension = "avi"
    category = "media"
    headers = [b'RIFF']
    footer = None
    max_size = 500 * 1024 * 1024

    def match_header(self, data: bytes, offset: int) -> bool:
        if offset + 12 > len(data):
            return False
        return data[offset:offset+4] == b'RIFF' and data[offset+8:offset+12] == b'AVI '

    def get_size(self, data: bytes, offset: int) -> int | None:
        if len(data) < offset + 8:
            return None
        riff_size = struct.unpack_from('<I', data, offset + 4)[0]
        total = riff_size + 8
        if total > self.max_size or total < 12:
            return None
        return total
