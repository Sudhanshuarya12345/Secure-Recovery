"""TIFF signature — II (little-endian) or MM (big-endian) + 0x002A magic."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class TIFFSignature(BaseSignature):
    name = "TIFF Image"
    extension = "tiff"
    category = "images"
    headers = [b'II\x2a\x00', b'MM\x00\x2a']
    footer = None
    max_size = 100 * 1024 * 1024  # TIFFs can be large

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # TIFF size requires parsing full IFD chain; use max_size

    def validate(self, data: bytes) -> bool:
        return len(data) >= 8
