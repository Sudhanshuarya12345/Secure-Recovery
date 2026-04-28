"""Additional system and misc signatures: PSD, ICO, XML/SVG, HTML, Java CLASS, LUKS, VMDK."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class PSDSignature(BaseSignature):
    """Adobe Photoshop PSD — 38 42 50 53 ('8BPS')."""
    name = "PSD Image"
    extension = "psd"
    category = "images"
    headers = [b'8BPS']
    footer = None
    max_size = 200 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

class ICOSignature(BaseSignature):
    """Windows Icon — 00 00 01 00."""
    name = "ICO Icon"
    extension = "ico"
    category = "images"
    headers = [b'\x00\x00\x01\x00']
    footer = None
    min_size = 22
    max_size = 1 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None
    def validate(self, data: bytes) -> bool:
        if len(data) < 6:
            return False
        import struct
        count = struct.unpack_from('<H', data, 4)[0]
        return 1 <= count <= 100  # Reasonable icon count

class XMLSignature(BaseSignature):
    """XML/SVG — <?xml header."""
    name = "XML Document"
    extension = "xml"
    category = "documents"
    headers = [b'<?xml']
    footer = b'>'
    max_size = 10 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

class HTMLSignature(BaseSignature):
    """HTML — <!DOCTYPE header."""
    name = "HTML Document"
    extension = "html"
    category = "documents"
    headers = [b'<!DOCTYPE', b'<!doctype', b'<html', b'<HTML']
    footer = b'</html>'
    max_size = 10 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

class JavaClassSignature(BaseSignature):
    """Java class file — CA FE BA BE."""
    name = "Java Class"
    extension = "class"
    category = "system"
    headers = [b'\xca\xfe\xba\xbe']
    footer = None
    max_size = 10 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

class LUKSSignature(BaseSignature):
    """LUKS encrypted volume header — 4C 55 4B 53 BA BE."""
    name = "LUKS Encrypted"
    extension = "luks"
    category = "system"
    headers = [b'LUKS\xba\xbe']
    footer = None
    max_size = 2 * 1024 * 1024  # Just capture the header region
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None

class VMDKSignature(BaseSignature):
    """VMware VMDK disk image — 4B 44 4D 56 ('KDMV')."""
    name = "VMDK Image"
    extension = "vmdk"
    category = "system"
    headers = [b'KDMV']
    footer = None
    max_size = 100 * 1024 * 1024
    def get_size(self, data: bytes, offset: int) -> int | None:
        return None
