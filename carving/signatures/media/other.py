"""Additional media signatures: MKV, FLAC, OGG."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class MKVSignature(BaseSignature):
    """MKV/WebM — EBML header 1A 45 DF A3."""
    name = "MKV Video"
    extension = "mkv"
    category = "media"
    headers = [b'\x1a\x45\xdf\xa3']
    footer = None
    max_size = 500 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

class FLACSignature(BaseSignature):
    """FLAC audio — fLaC magic."""
    name = "FLAC Audio"
    extension = "flac"
    category = "media"
    headers = [b'fLaC']
    footer = None
    max_size = 100 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

class OGGSignature(BaseSignature):
    """OGG container — OggS magic."""
    name = "OGG Audio"
    extension = "ogg"
    category = "media"
    headers = [b'OggS']
    footer = None
    max_size = 50 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None
