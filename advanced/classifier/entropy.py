"""
pyrecovery.advanced.classifier.entropy — Shannon entropy analysis.

Shannon entropy measures the information density of a byte stream.
The result is in bits per byte (0.0 to 8.0):

    0.0         — Constant data (all same byte value)
    0.0 – 1.0   — Nearly empty / sparse data (lots of zeroes)
    1.0 – 5.0   — Structured / text data (ASCII, XML, source code)
    5.0 – 6.5   — Rich structured data (executables, databases)
    6.5 – 7.5   — Compressed data (ZIP, GZIP, JPEG, MP3)
    7.5 – 7.9   — Well-compressed or packed data
    7.9 – 8.0   — Encrypted or random data (AES, /dev/urandom)

Forensic use cases:
- Distinguish encrypted vs unencrypted partitions
- Identify compressed file regions within carved data
- Detect wiped/zeroed regions on disk
- Validate recovered file integrity (encrypted file should be ~8.0)

The implementation uses a single-pass O(n) frequency count with
precomputed log2 table for performance.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Precomputed -p*log2(p) table for byte probabilities at common data sizes
# This avoids repeated log2 calls in hot loops
_LOG2_CACHE: dict[int, float] = {}


def shannon_entropy(data: bytes | bytearray, sample_size: int = 0) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Args:
        data: Input bytes.
        sample_size: If > 0, sample only this many bytes (from start).
                     Useful for large files where full entropy isn't needed.

    Returns:
        Entropy in bits per byte (0.0 to 8.0).
        Returns 0.0 for empty data.
    """
    if not data:
        return 0.0

    if sample_size > 0 and len(data) > sample_size:
        data = data[:sample_size]

    length = len(data)
    if length <= 1:
        return 0.0

    # Count byte frequencies
    freq = Counter(data)

    # Calculate entropy: H = -Σ p(x) * log2(p(x))
    entropy = 0.0
    for count in freq.values():
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 6)


def classify_entropy(entropy: float) -> str:
    """Classify entropy value into a human-readable category.

    Args:
        entropy: Shannon entropy in bits/byte (0.0 to 8.0).

    Returns:
        Classification string.
    """
    if entropy < 0.5:
        return "empty"
    elif entropy < 2.0:
        return "sparse"
    elif entropy < 5.0:
        return "structured"
    elif entropy < 6.5:
        return "rich_structured"
    elif entropy < 7.5:
        return "compressed"
    elif entropy < 7.9:
        return "highly_compressed"
    else:
        return "encrypted_or_random"


def entropy_histogram(
    data: bytes,
    block_size: int = 4096,
) -> list[tuple[int, float, str]]:
    """Generate entropy values for sequential blocks.

    Useful for visualizing encrypted vs plaintext regions on a disk.

    Args:
        data: Input data.
        block_size: Size of each analysis block.

    Returns:
        List of (offset, entropy, classification) tuples.
    """
    results: list[tuple[int, float, str]] = []

    for offset in range(0, len(data), block_size):
        block = data[offset:offset + block_size]
        e = shannon_entropy(block)
        c = classify_entropy(e)
        results.append((offset, e, c))

    return results


def byte_frequency_distribution(data: bytes) -> dict[int, float]:
    """Calculate normalized byte frequency distribution.

    Returns:
        Dict mapping byte value (0-255) to frequency (0.0-1.0).
    """
    if not data:
        return {}

    freq = Counter(data)
    length = len(data)
    return {byte_val: count / length for byte_val, count in sorted(freq.items())}


def chi_squared_test(data: bytes) -> float:
    """Pearson's chi-squared test for uniform distribution.

    For truly random/encrypted data, each byte value (0-255) should appear
    with equal frequency (len/256). Higher values = more deviation from
    uniform distribution.

    Interpretation:
    - Random data:  χ² ≈ 256 (± ~50)
    - Structured:   χ² >> 256
    - Constant:     χ² → ∞

    Returns:
        Chi-squared statistic.
    """
    if not data:
        return 0.0

    length = len(data)
    expected = length / 256.0
    if expected == 0:
        return 0.0

    freq = Counter(data)
    chi_sq = 0.0
    for byte_val in range(256):
        observed = freq.get(byte_val, 0)
        chi_sq += ((observed - expected) ** 2) / expected

    return round(chi_sq, 4)


def monte_carlo_pi_test(data: bytes) -> float:
    """Monte Carlo Pi estimation test for randomness.

    Treats consecutive byte pairs as (x, y) coordinates in a 256x256 grid.
    Counts how many fall within a quarter circle. For truly random data,
    the ratio approximates π/4 ≈ 0.7854.

    Returns:
        Estimated value of π. Closer to 3.14159 = more random.
    """
    if len(data) < 4:
        return 0.0

    inside = 0
    total = 0

    for i in range(0, len(data) - 3, 4):
        x = (data[i] << 8 | data[i + 1]) / 65535.0
        y = (data[i + 2] << 8 | data[i + 3]) / 65535.0
        if x * x + y * y <= 1.0:
            inside += 1
        total += 1

    if total == 0:
        return 0.0

    return round(4.0 * inside / total, 6)
