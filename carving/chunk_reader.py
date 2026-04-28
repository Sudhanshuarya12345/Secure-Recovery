"""
pyrecovery.carving.chunk_reader — Buffered, overlapping chunk I/O for carving.

Why overlap?
    File headers can land exactly at a chunk boundary. Without overlap, a JPEG
    header starting 3 bytes before the end of a 1 MB chunk would be split across
    two reads, causing the scanner to miss it entirely.

    The 1024-byte overlap ensures any file header up to 1024 bytes long is always
    fully contained within at least one chunk. Since the longest header we support
    is 16 bytes (SQLite), 1024 bytes provides ample margin.

Performance:
    Overlap adds <0.1% overhead (1024 bytes per 1 MB chunk = 0.097%).
"""

from __future__ import annotations

from typing import Iterator

from disk.reader import DiskReader
from utils.logger import get_logger

logger = get_logger(__name__)


class ChunkReader:
    """Buffered, overlapping chunk reader for the carving engine.

    Yields (absolute_offset, chunk_data) tuples where each chunk overlaps
    with the previous one by ``overlap`` bytes.

    Usage::

        reader = DiskReader("evidence.img")
        for offset, chunk in ChunkReader(reader, chunk_size=1_048_576):
            # scan chunk for signatures
            # offset is the absolute byte position of chunk[0]
    """

    def __init__(
        self,
        reader: DiskReader,
        chunk_size: int = 1_048_576,
        overlap: int = 1024,
    ) -> None:
        """Initialize the chunk reader.

        Args:
            reader: DiskReader instance (source of bytes).
            chunk_size: Size of each chunk in bytes (default: 1 MB).
            overlap: Number of bytes to overlap between chunks (default: 1024).
                     Must be less than chunk_size.

        Raises:
            ValueError: If overlap >= chunk_size.
        """
        if overlap >= chunk_size:
            raise ValueError(
                f"overlap ({overlap}) must be less than chunk_size ({chunk_size})"
            )

        self._reader = reader
        self._chunk_size = chunk_size
        self._overlap = overlap
        self._bytes_read = 0

    def __iter__(self) -> Iterator[tuple[int, bytes]]:
        """Yield (absolute_offset, chunk_data) tuples.

        Each chunk starts ``overlap`` bytes before the end of the previous
        chunk (except the first chunk which starts at offset 0).

        The ``absolute_offset`` is the byte position in the source where
        chunk[0] corresponds to. This allows the scanner to compute the
        absolute offset of any match found within the chunk.
        """
        total = self._reader.get_disk_size()
        pos = 0
        step = self._chunk_size - self._overlap

        while pos < total:
            read_size = min(self._chunk_size, total - pos)
            data = self._reader.read_at(pos, read_size)

            if not data:
                break

            self._bytes_read = pos + len(data)
            yield pos, data

            if len(data) < self._chunk_size:
                break  # Reached end of source

            pos += step

    @property
    def total_size(self) -> int:
        """Total size of the source in bytes."""
        return self._reader.get_disk_size()

    @property
    def bytes_read(self) -> int:
        """Total bytes read so far (for progress reporting)."""
        return self._bytes_read

    @property
    def chunk_size(self) -> int:
        """Configured chunk size."""
        return self._chunk_size

    @property
    def overlap(self) -> int:
        """Configured overlap size."""
        return self._overlap
