"""WAV signature — RIFF container with WAVE fourcc."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class WAVSignature(BaseSignature):
    name = "WAV Audio"
    extension = "wav"
    category = "media"
    headers = [b'RIFF']
    footer = None
    max_size = 200 * 1024 * 1024

    def match_header(self, data: bytes, offset: int) -> bool:
        if offset + 12 > len(data):
            return False
        return data[offset:offset+4] == b'RIFF' and data[offset+8:offset+12] == b'WAVE'

    def get_size(self, data: bytes, offset: int) -> int | None:
        if len(data) < offset + 8:
            return None
        riff_size = struct.unpack_from('<I', data, offset + 4)[0]
        total = riff_size + 8
        if total > self.max_size or total < 12:
            return None
        return total
