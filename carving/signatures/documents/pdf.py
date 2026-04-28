"""PDF signature — %PDF- header, %%EOF footer."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class PDFSignature(BaseSignature):
    name = "PDF Document"
    extension = "pdf"
    category = "documents"
    headers = [b'%PDF-']
    footer = b'%%EOF'
    max_size = 100 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        return None  # Scan for %%EOF footer

    def validate(self, data: bytes) -> bool:
        if len(data) < 20:
            return False
        # Check for PDF version after %PDF-
        return data[5:6] in (b'1', b'2')
