"""7-Zip signature — 37 7A BC AF 27 1C."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class SevenZipSignature(BaseSignature):
    name = "7-Zip Archive"
    extension = "7z"
    category = "archives"
    headers = [b'7z\xbc\xaf\x27\x1c']
    footer = None
    max_size = 200 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None
