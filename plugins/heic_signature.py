"""
Example plugin: HEIC/HEIF image format signature.

HEIC (High Efficiency Image Container) uses the ISO Base Media File Format
(ISO/IEC 14496-12), same as MP4/MOV. The key difference is the 'ftyp' box
contains HEIC-specific brand identifiers.

Structure:
  +0:  Box size (4 bytes, big-endian)
  +4:  Box type "ftyp" (4 bytes)
  +8:  Major brand (4 bytes): "heic", "heix", "mif1", etc.
  +12: Minor version (4 bytes)
  +16: Compatible brands (variable)
"""

from carving.base_signature import BaseSignature
import struct


class HEICSignature(BaseSignature):

    name = "HEIC Image"
    extension = "heic"
    category = "images"
    headers = [b'ftyp']
    header_offset = 4  # "ftyp" appears at byte 4
    footer = None
    max_size = 50 * 1024 * 1024
    min_size = 100

    # HEIC-compatible brand identifiers
    HEIC_BRANDS = {b'heic', b'heix', b'mif1', b'heim', b'heis', b'avif'}

    def get_size(self, data: bytes, offset: int) -> int | None:
        """Walk ISO BMFF boxes to find total file size."""
        if offset + 8 > len(data):
            return None

        pos = offset
        while pos + 8 <= len(data):
            box_size = struct.unpack('>I', data[pos:pos + 4])[0]
            if box_size == 0:
                # Box extends to end of file — can't determine
                return None
            if box_size == 1 and pos + 16 <= len(data):
                # Extended size (64-bit)
                box_size = struct.unpack('>Q', data[pos + 8:pos + 16])[0]
            if box_size < 8:
                return None

            pos += box_size
            if pos - offset > self.max_size:
                return None

        total = pos - offset
        return total if total > self.min_size else None

    def validate(self, data: bytes) -> bool:
        """Validate that the ftyp box contains HEIC-compatible brands."""
        if len(data) < 16:
            return False

        # Check box size at offset 0
        box_size = struct.unpack('>I', data[0:4])[0]
        if box_size < 12 or box_size > len(data):
            return False

        # Check major brand
        major_brand = data[8:12]
        if major_brand in self.HEIC_BRANDS:
            return True

        # Check compatible brands within ftyp box
        for i in range(16, min(box_size, len(data)) - 3, 4):
            if data[i:i + 4] in self.HEIC_BRANDS:
                return True

        return False
