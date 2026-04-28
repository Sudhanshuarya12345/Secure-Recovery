"""ELF signature — 7F 45 4C 46 (Unix executables and shared libraries)."""
from __future__ import annotations
import struct
from carving.base_signature import BaseSignature

class ELFSignature(BaseSignature):
    name = "ELF Binary"
    extension = "elf"
    category = "system"
    headers = [b'\x7fELF']
    footer = None
    max_size = 50 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        if len(data) < offset + 64:
            return None
        # EI_CLASS: offset 4 — 1=32-bit, 2=64-bit
        ei_class = data[offset + 4]
        if ei_class == 1:  # 32-bit
            if len(data) < offset + 52:
                return None
            e_shoff = struct.unpack_from('<I', data, offset + 32)[0]
            e_shnum = struct.unpack_from('<H', data, offset + 48)[0]
            e_shentsize = struct.unpack_from('<H', data, offset + 46)[0]
        elif ei_class == 2:  # 64-bit
            if len(data) < offset + 64:
                return None
            e_shoff = struct.unpack_from('<Q', data, offset + 40)[0]
            e_shnum = struct.unpack_from('<H', data, offset + 60)[0]
            e_shentsize = struct.unpack_from('<H', data, offset + 58)[0]
        else:
            return None
        total = e_shoff + (e_shnum * e_shentsize)
        return total if 64 <= total <= self.max_size else None

    def validate(self, data: bytes) -> bool:
        if len(data) < 16:
            return False
        return data[4] in (1, 2) and data[5] in (1, 2)  # Class and endianness
