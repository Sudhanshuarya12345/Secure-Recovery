"""PE/EXE signature — MZ header (4D 5A) for Windows executables and DLLs."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class PESignature(BaseSignature):
    name = "PE Executable"
    extension = "exe"
    category = "system"
    headers = [b'MZ']
    footer = None
    max_size = 50 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # PE size requires parsing optional header + sections

    def validate(self, data: bytes) -> bool:
        if len(data) < 64:
            return False
        # e_lfanew at offset 60 points to PE signature
        e_lfanew = struct.unpack_from('<I', data, 60)[0]
        if e_lfanew + 4 > len(data):
            return False
        return data[e_lfanew:e_lfanew+4] == b'PE\x00\x00'
