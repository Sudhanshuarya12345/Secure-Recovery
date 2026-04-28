"""
pyrecovery.carving.validator — Post-extraction validation to reject false positives.

File carving produces false positives because magic byte sequences can appear
in unrelated data (e.g., a JPEG header inside a ZIP archive, or random bytes
that happen to match 'MZ'). This module applies heuristic checks to reject
obviously invalid carved files.

Validation hierarchy:
1. Size check: reject if < sig.min_size
2. Signature-specific validate() method (format-aware checks)
3. Null-byte ratio: reject if > 95% null bytes (likely free space, not a file)
4. Quick entropy check: reject if entropy < 0.3 (constant data, not a file)
"""

from __future__ import annotations

import math
from collections import Counter

from carving.base_signature import BaseSignature
from utils.logger import get_logger

logger = get_logger(__name__)


class CarvedFileValidator:
    """Validate carved file data to reject false positives.

    Returns (is_valid, reason) tuples. If is_valid is False, the file
    is moved to partial/ instead of the category folder.
    """

    def validate(
        self, data: bytes, sig: BaseSignature
    ) -> tuple[bool, str]:
        """Run all validation checks on carved file data.

        Args:
            data: The complete carved file bytes.
            sig: The signature that matched this file.

        Returns:
            Tuple of (is_valid, reason). reason is empty string if valid.
        """
        # 1. Minimum size check
        if len(data) < sig.min_size:
            return False, f"Too small: {len(data)} bytes < min {sig.min_size}"

        # 2. Null-byte ratio (skip for compressed/encrypted formats)
        if sig.category not in ("archives",):
            null_ratio = self.null_byte_ratio(data)
            if null_ratio > 0.95:
                return False, f"Null-byte ratio too high: {null_ratio:.1%}"

        # 3. Basic entropy check (skip for compressed/encrypted/archive formats)
        if sig.category not in ("archives", "media"):
            entropy = self.basic_entropy(data[:4096])
            if entropy < 0.3 and len(data) > 1024:
                return False, f"Entropy too low: {entropy:.2f} bits/byte"

        # 4. Signature-specific validation
        try:
            if not sig.validate(data):
                return False, f"Format-specific validation failed for {sig.name}"
        except Exception as e:
            logger.debug("Validation error for %s: %s", sig.name, e)
            return False, f"Validation exception: {e}"

        return True, ""

    @staticmethod
    def null_byte_ratio(data: bytes) -> float:
        """Calculate the fraction of bytes that are 0x00.

        Args:
            data: Raw bytes to analyze.

        Returns:
            Float between 0.0 (no nulls) and 1.0 (all nulls).
        """
        if not data:
            return 0.0
        return data.count(0) / len(data)

    @staticmethod
    def basic_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence.

        Args:
            data: Raw bytes (typically first 4KB of carved file).

        Returns:
            Entropy in bits per byte. Range:
            - 0.0: completely uniform (e.g., all zeros)
            - ~4.0: English text
            - ~6.0: structured binary (executables, images)
            - ~7.5: compressed data
            - ~8.0: encrypted or random data
        """
        if not data:
            return 0.0

        length = len(data)
        counts = Counter(data)
        entropy = 0.0

        for count in counts.values():
            if count == 0:
                continue
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy
