"""
pyrecovery.advanced.classifier.content_classifier — Heuristic file content analysis.

Combines multiple signals to classify unknown data:
1. Shannon entropy (randomness measure)
2. Byte frequency distribution (ASCII text vs binary)
3. Magic number scanning (known file headers)
4. Printable character ratio
5. NULL byte density
6. Chi-squared uniformity test

This is used when:
- Carved files have no clear header match
- Fragments need classification before reassembly
- Disk regions need to be categorized (free space, wiped, encrypted, data)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from advanced.classifier.entropy import (
    shannon_entropy,
    classify_entropy,
    chi_squared_test,
    byte_frequency_distribution,
)
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContentAnalysis:
    """Result of content classification."""
    content_type: str           # Primary classification
    confidence: float           # 0.0 to 1.0
    entropy: float              # Shannon entropy (bits/byte)
    entropy_class: str          # Human-readable entropy category
    chi_squared: float          # Chi-squared uniformity statistic
    printable_ratio: float      # Ratio of printable ASCII bytes
    null_ratio: float           # Ratio of NULL (0x00) bytes
    ascii_ratio: float          # Ratio of bytes in 0x20-0x7E range
    high_byte_ratio: float      # Ratio of bytes > 0x7F
    details: dict               # Additional analysis data

    def to_dict(self) -> dict:
        return {
            "content_type": self.content_type,
            "confidence": self.confidence,
            "entropy": self.entropy,
            "entropy_class": self.entropy_class,
            "chi_squared": self.chi_squared,
            "printable_ratio": self.printable_ratio,
            "null_ratio": self.null_ratio,
        }


class ContentClassifier:
    """Heuristic content classifier for unknown data blocks.

    Usage::

        classifier = ContentClassifier()
        result = classifier.classify(data)
        print(f"{result.content_type} (confidence={result.confidence:.0%})")
    """

    # Content type constants
    TYPE_TEXT_ASCII = "text/ascii"
    TYPE_TEXT_UTF8 = "text/utf8"
    TYPE_TEXT_HTML = "text/html"
    TYPE_TEXT_XML = "text/xml"
    TYPE_TEXT_JSON = "text/json"
    TYPE_TEXT_SOURCE = "text/source_code"
    TYPE_BINARY_EXEC = "binary/executable"
    TYPE_BINARY_DATA = "binary/structured"
    TYPE_COMPRESSED = "binary/compressed"
    TYPE_ENCRYPTED = "binary/encrypted"
    TYPE_EMPTY = "empty/zeroed"
    TYPE_SPARSE = "empty/sparse"
    TYPE_WIPED = "empty/wiped"
    TYPE_UNKNOWN = "unknown"

    # Magic signatures for quick identification
    _MAGIC_SIGS: list[tuple[bytes, int, str]] = [
        (b'\x89PNG', 0, "image/png"),
        (b'\xff\xd8\xff', 0, "image/jpeg"),
        (b'GIF8', 0, "image/gif"),
        (b'BM', 0, "image/bmp"),
        (b'%PDF', 0, "application/pdf"),
        (b'PK\x03\x04', 0, "archive/zip"),
        (b'\x1f\x8b', 0, "archive/gzip"),
        (b'Rar!\x1a\x07', 0, "archive/rar"),
        (b'7z\xbc\xaf\x27\x1c', 0, "archive/7zip"),
        (b'\x7fELF', 0, "binary/elf"),
        (b'MZ', 0, "binary/pe"),
        (b'SQLite format 3', 0, "database/sqlite"),
        (b'\xfe\xed\xfe\xed', 0, "binary/java_class"),
        (b'LUKS\xba\xbe', 0, "encrypted/luks"),
        (b'-FVE-FS-', 3, "encrypted/bitlocker"),
        (b'<!DOCTYPE', 0, "text/html"),
        (b'<?xml', 0, "text/xml"),
    ]

    def classify(self, data: bytes, sample_size: int = 65536) -> ContentAnalysis:
        """Classify content using multi-signal heuristics.

        Args:
            data: Data to classify.
            sample_size: Max bytes to analyze (for performance).

        Returns:
            ContentAnalysis with type, confidence, and metrics.
        """
        if not data:
            return self._empty_result()

        sample = data[:sample_size] if len(data) > sample_size else data
        length = len(sample)

        # Step 1: Quick magic number check
        magic_type = self._check_magic(sample)

        # Step 2: Compute statistical metrics
        entropy = shannon_entropy(sample)
        entropy_class = classify_entropy(entropy)
        chi_sq = chi_squared_test(sample)

        # Byte category ratios
        null_count = sample.count(0)
        printable_count = sum(1 for b in sample if 0x20 <= b <= 0x7E)
        ascii_count = sum(1 for b in sample if 0x09 <= b <= 0x7E)
        high_count = sum(1 for b in sample if b > 0x7F)
        whitespace_count = sum(1 for b in sample if b in (0x09, 0x0A, 0x0D, 0x20))

        null_ratio = null_count / length
        printable_ratio = printable_count / length
        ascii_ratio = ascii_count / length
        high_ratio = high_count / length

        # Step 3: Classification logic
        content_type, confidence = self._determine_type(
            magic_type=magic_type,
            entropy=entropy,
            chi_sq=chi_sq,
            null_ratio=null_ratio,
            printable_ratio=printable_ratio,
            ascii_ratio=ascii_ratio,
            high_ratio=high_ratio,
            sample=sample,
        )

        return ContentAnalysis(
            content_type=content_type,
            confidence=confidence,
            entropy=entropy,
            entropy_class=entropy_class,
            chi_squared=chi_sq,
            printable_ratio=round(printable_ratio, 4),
            null_ratio=round(null_ratio, 4),
            ascii_ratio=round(ascii_ratio, 4),
            high_byte_ratio=round(high_ratio, 4),
            details={
                "sample_size": length,
                "magic_detected": magic_type or "none",
            },
        )

    def classify_region(
        self, data: bytes, block_size: int = 4096
    ) -> list[ContentAnalysis]:
        """Classify sequential blocks within a data region.

        Useful for mapping content types across a disk image or partition.

        Args:
            data: Full data to analyze.
            block_size: Size of each classification block.

        Returns:
            List of ContentAnalysis, one per block.
        """
        results: list[ContentAnalysis] = []
        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]
            results.append(self.classify(block))
        return results

    def _check_magic(self, data: bytes) -> str | None:
        """Check for known magic numbers."""
        for sig, offset, file_type in self._MAGIC_SIGS:
            if len(data) > offset + len(sig):
                if data[offset:offset + len(sig)] == sig:
                    return file_type
        return None

    def _determine_type(
        self,
        magic_type: str | None,
        entropy: float,
        chi_sq: float,
        null_ratio: float,
        printable_ratio: float,
        ascii_ratio: float,
        high_ratio: float,
        sample: bytes,
    ) -> tuple[str, float]:
        """Multi-signal classification decision tree.

        Returns:
            Tuple of (content_type, confidence).
        """
        # If magic matched, that's the strongest signal
        if magic_type:
            return magic_type, 0.95

        # All zeros → zeroed/wiped
        if null_ratio > 0.99:
            return self.TYPE_EMPTY, 0.99

        # Almost all same byte → wiped with pattern
        if entropy < 0.1:
            return self.TYPE_WIPED, 0.95

        # Very low entropy with lots of nulls → sparse
        if entropy < 1.0 and null_ratio > 0.80:
            return self.TYPE_SPARSE, 0.90

        # High entropy + uniform distribution → encrypted or random
        if entropy > 7.9 and 200 < chi_sq < 350:
            return self.TYPE_ENCRYPTED, 0.85

        # High entropy but not quite uniform → compressed
        if entropy > 7.0:
            return self.TYPE_COMPRESSED, 0.75

        # High printable ratio → text
        if printable_ratio > 0.90:
            return self._classify_text(sample, printable_ratio)

        # Moderate printable + some structure → source code or markup
        if printable_ratio > 0.70 and ascii_ratio > 0.85:
            return self._classify_text(sample, printable_ratio)

        # High byte ratio with moderate entropy → UTF-8 text
        if high_ratio > 0.10 and printable_ratio > 0.40 and entropy < 6.5:
            return self.TYPE_TEXT_UTF8, 0.60

        # Moderate entropy with some structure → structured binary
        if 4.0 < entropy < 7.0:
            return self.TYPE_BINARY_DATA, 0.60

        # Low-moderate entropy → structured binary
        if 2.0 < entropy < 4.0:
            return self.TYPE_BINARY_DATA, 0.50

        return self.TYPE_UNKNOWN, 0.30

    @staticmethod
    def _classify_text(sample: bytes, printable_ratio: float) -> tuple[str, float]:
        """Sub-classify text content."""
        # Convert sample head to string for pattern matching
        try:
            text = sample[:4096].decode('ascii', errors='ignore')
        except Exception:
            return (ContentClassifier.TYPE_TEXT_ASCII, 0.70)

        lower = text.lower()

        # HTML
        if '<html' in lower or '<!doctype html' in lower or '</div>' in lower:
            return (ContentClassifier.TYPE_TEXT_HTML, 0.90)

        # XML
        if '<?xml' in lower or '</' in text[:500]:
            return (ContentClassifier.TYPE_TEXT_XML, 0.85)

        # JSON
        stripped = text.lstrip()
        if stripped.startswith('{') or stripped.startswith('['):
            if '"' in text and ':' in text:
                return (ContentClassifier.TYPE_TEXT_JSON, 0.80)

        # Source code heuristics
        code_markers = ['def ', 'class ', 'function ', 'import ', 'include ',
                        '#include', 'public ', 'private ', 'return ', 'var ']
        code_hits = sum(1 for m in code_markers if m in text)
        if code_hits >= 2:
            return (ContentClassifier.TYPE_TEXT_SOURCE, 0.75)

        # Generic ASCII text
        confidence = min(0.95, printable_ratio)
        return (ContentClassifier.TYPE_TEXT_ASCII, confidence)

    @staticmethod
    def _empty_result() -> ContentAnalysis:
        return ContentAnalysis(
            content_type="empty/null",
            confidence=1.0,
            entropy=0.0,
            entropy_class="empty",
            chi_squared=0.0,
            printable_ratio=0.0,
            null_ratio=1.0,
            ascii_ratio=0.0,
            high_byte_ratio=0.0,
            details={},
        )
