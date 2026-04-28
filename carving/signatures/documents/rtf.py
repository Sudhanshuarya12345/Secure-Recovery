"""RTF signature — {\\rtf1 header, matching closing brace footer."""
from __future__ import annotations
from carving.base_signature import BaseSignature

class RTFSignature(BaseSignature):
    name = "RTF Document"
    extension = "rtf"
    category = "documents"
    headers = [b'{\\rtf1']
    footer = b'}'
    max_size = 20 * 1024 * 1024

    def get_size(self, data: bytes, offset: int) -> int | None:
        # Track brace nesting depth to find the matching closing brace
        depth = 0
        for i in range(offset, min(offset + self.max_size, len(data))):
            if data[i:i+1] == b'{':
                depth += 1
            elif data[i:i+1] == b'}':
                depth -= 1
                if depth == 0:
                    return i - offset + 1
        return None
