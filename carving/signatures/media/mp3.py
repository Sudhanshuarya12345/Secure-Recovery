"""MP3 signature — ID3v2 tag header (49 44 33)."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class MP3Signature(BaseSignature):
    name = "MP3 Audio"
    extension = "mp3"
    category = "media"
    headers = [b'ID3']
    footer = None
    max_size = 30 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        # ID3v2 tag size: syncsafe integer at offset 6-9
        # Each byte uses only 7 bits (MSB always 0)
        if len(data) < offset + 10:
            return None
        b6, b7, b8, b9 = data[offset+6], data[offset+7], data[offset+8], data[offset+9]
        # Validate syncsafe (MSB of each byte must be 0)
        if any(b & 0x80 for b in (b6, b7, b8, b9)):
            return None
        tag_size = (b6 << 21) | (b7 << 14) | (b8 << 7) | b9
        # Total = 10-byte header + tag_size + audio (estimate audio as max_size)
        # We can't determine audio length from ID3 alone
        return None  # Fall back to max_size since we can't know audio length
