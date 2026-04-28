"""MP4/MOV signature — ftyp box at offset 4 (ISO Base Media File Format)."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class MP4Signature(BaseSignature):
    name = "MP4/MOV Video"
    extension = "mp4"
    category = "media"
    headers = [b'ftyp']
    header_offset = 4  # ftyp appears at byte 4, not byte 0
    footer = None
    max_size = 500 * 1024 * 1024  # 500 MB

    def get_size(self, data: bytes, offset: int) -> int | None:
        # ISO BMFF: walk box chain. Each box: 4-byte size (BE) + 4-byte type
        pos = offset
        total = 0
        while pos + 8 <= len(data):
            box_size = struct.unpack_from('>I', data, pos)[0]
            if box_size == 0:
                break  # Box extends to EOF
            if box_size < 8:
                break  # Invalid
            total = (pos - offset) + box_size
            pos += box_size
            if pos > offset + self.max_size:
                break
        return total if total > 8 else None

    def validate(self, data: bytes) -> bool:
        if len(data) < 8:
            return False
        # First box size should be reasonable, type should be 'ftyp'
        box_size = struct.unpack_from('>I', data, 0)[0]
        return data[4:8] == b'ftyp' and 8 <= box_size <= 1024
