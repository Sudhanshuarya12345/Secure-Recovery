"""
pyrecovery.recovery.fragment_handler — Reassemble fragmented files.

When files are fragmented across non-contiguous disk clusters, the filesystem
parser may only recover partial data. This module attempts to reassemble
fragments by:

1. Signature-matching: Group fragments by file type using header/footer analysis
2. Content-continuity: Score candidate fragment orderings by byte-level continuity
3. Entropy-matching: Adjacent fragments should have similar entropy profiles
4. Size-validation: Reassembled file should match expected size from FS metadata

This is a best-effort heuristic — fragmented files without clear boundaries
may not be recoverable without filesystem metadata.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from advanced.classifier.entropy import shannon_entropy
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Fragment:
    """A single fragment (contiguous byte run) from disk."""
    fragment_id: int
    offset: int               # Disk offset where this fragment was found
    data: bytes               # Raw fragment data
    size: int                 # len(data)
    entropy: float = 0.0      # Shannon entropy
    file_type_hint: str = ""  # Detected file type from magic/context
    source_partition: int = -1
    cluster_start: int = -1   # Starting cluster number

    def __post_init__(self):
        self.size = len(self.data)
        self.entropy = shannon_entropy(self.data[:4096])  # Sample first 4KB


@dataclass
class ReassembledFile:
    """Result of fragment reassembly."""
    fragments: list[Fragment]
    total_size: int
    file_type: str
    confidence: float         # 0.0 to 1.0
    sha256: str
    data: bytes

    @property
    def fragment_count(self) -> int:
        return len(self.fragments)


class FragmentHandler:
    """Reassemble fragmented files from disk fragments.

    Usage::

        handler = FragmentHandler()

        # Add fragments found during recovery
        handler.add_fragment(Fragment(0, offset=1000, data=b'\\xff\\xd8\\xff...'))
        handler.add_fragment(Fragment(1, offset=5000, data=b'...more jpeg...'))
        handler.add_fragment(Fragment(2, offset=9000, data=b'...\\xff\\xd9'))

        # Attempt reassembly
        results = handler.reassemble()
        for r in results:
            print(f"Reassembled {r.file_type}: {r.fragment_count} fragments, "
                  f"confidence={r.confidence:.0%}")
    """

    # Known file headers for fragment grouping
    _HEADERS: list[tuple[bytes, str]] = [
        (b'\xff\xd8\xff', "jpeg"),
        (b'\x89PNG\r\n\x1a\n', "png"),
        (b'%PDF', "pdf"),
        (b'PK\x03\x04', "zip"),
        (b'\x7fELF', "elf"),
        (b'MZ', "pe"),
        (b'RIFF', "riff"),
        (b'GIF8', "gif"),
        (b'\x1f\x8b', "gzip"),
    ]

    # Known file footers
    _FOOTERS: dict[str, bytes] = {
        "jpeg": b'\xff\xd9',
        "png": b'IEND\xae\x42\x60\x82',
        "pdf": b'%%EOF',
    }

    def __init__(self) -> None:
        self._fragments: list[Fragment] = []
        self._next_id = 0

    def add_fragment(self, fragment: Fragment) -> None:
        """Add a fragment for reassembly."""
        self._fragments.append(fragment)

    def create_fragment(
        self, data: bytes, offset: int, **kwargs
    ) -> Fragment:
        """Create and register a fragment."""
        frag = Fragment(
            fragment_id=self._next_id,
            offset=offset,
            data=data,
            size=len(data),
            **kwargs,
        )
        self._next_id += 1
        self._fragments.append(frag)
        return frag

    def reassemble(
        self,
        expected_size: int = 0,
        file_type_hint: str = "",
    ) -> list[ReassembledFile]:
        """Attempt to reassemble fragments into complete files.

        Args:
            expected_size: Expected file size (0 = unknown).
            file_type_hint: Expected file type for guided reassembly.

        Returns:
            List of ReassembledFile candidates, sorted by confidence.
        """
        if not self._fragments:
            return []

        results: list[ReassembledFile] = []

        # Step 1: Identify header fragments
        header_frags = self._find_header_fragments()

        # Step 2: Identify footer fragments
        footer_frags = self._find_footer_fragments()

        # Step 3: For each header, try to build a complete file
        for header_frag, file_type in header_frags:
            candidate = self._build_file(
                header_frag, file_type, footer_frags, expected_size
            )
            if candidate:
                results.append(candidate)

        # Step 4: If no headers found, try sequential ordering by offset
        if not results and len(self._fragments) > 1:
            sequential = self._try_sequential_assembly(expected_size)
            if sequential:
                results.append(sequential)

        # Sort by confidence
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    @property
    def fragment_count(self) -> int:
        return len(self._fragments)

    def clear(self) -> None:
        self._fragments.clear()
        self._next_id = 0

    def _find_header_fragments(self) -> list[tuple[Fragment, str]]:
        """Find fragments that start with known file headers."""
        results: list[tuple[Fragment, str]] = []
        for frag in self._fragments:
            for header_bytes, file_type in self._HEADERS:
                if frag.data[:len(header_bytes)] == header_bytes:
                    results.append((frag, file_type))
                    break
        return results

    def _find_footer_fragments(self) -> dict[str, list[Fragment]]:
        """Find fragments containing known file footers."""
        results: dict[str, list[Fragment]] = {}
        for frag in self._fragments:
            for file_type, footer_bytes in self._FOOTERS.items():
                pos = frag.data.rfind(footer_bytes)
                if pos >= 0:
                    results.setdefault(file_type, []).append(frag)
        return results

    def _build_file(
        self,
        header_frag: Fragment,
        file_type: str,
        footer_frags: dict[str, list[Fragment]],
        expected_size: int,
    ) -> ReassembledFile | None:
        """Try to build a complete file starting from a header fragment."""
        # Start with header fragment
        ordered: list[Fragment] = [header_frag]
        used_ids = {header_frag.fragment_id}

        # Find candidates for middle/tail fragments
        remaining = [f for f in self._fragments if f.fragment_id not in used_ids]

        # Sort remaining by disk offset (proximity heuristic)
        remaining.sort(key=lambda f: f.offset)

        # Strategy: add fragments in offset order, checking entropy continuity
        for frag in remaining:
            if frag.fragment_id in used_ids:
                continue

            # Check entropy similarity (within 2.0 bits)
            if abs(frag.entropy - header_frag.entropy) < 2.0:
                ordered.append(frag)
                used_ids.add(frag.fragment_id)

            # Check if we found a footer
            if file_type in footer_frags:
                footer_candidates = [
                    f for f in footer_frags[file_type]
                    if f.fragment_id in used_ids
                ]
                if footer_candidates:
                    break

        # Assemble data
        assembled = b''.join(f.data for f in ordered)
        sha256 = hashlib.sha256(assembled).hexdigest()

        # Score confidence
        confidence = self._score_assembly(
            ordered, file_type, assembled, expected_size
        )

        if confidence < 0.1:
            return None

        return ReassembledFile(
            fragments=ordered,
            total_size=len(assembled),
            file_type=file_type,
            confidence=confidence,
            sha256=sha256,
            data=assembled,
        )

    def _try_sequential_assembly(self, expected_size: int) -> ReassembledFile | None:
        """Try assembling all fragments in disk-offset order."""
        sorted_frags = sorted(self._fragments, key=lambda f: f.offset)
        assembled = b''.join(f.data for f in sorted_frags)
        sha256 = hashlib.sha256(assembled).hexdigest()

        # Detect type from assembled data
        file_type = "unknown"
        for header_bytes, ft in self._HEADERS:
            if assembled[:len(header_bytes)] == header_bytes:
                file_type = ft
                break

        confidence = 0.3  # Low confidence for blind sequential
        if expected_size > 0 and abs(len(assembled) - expected_size) < 1024:
            confidence = 0.6

        return ReassembledFile(
            fragments=sorted_frags,
            total_size=len(assembled),
            file_type=file_type,
            confidence=confidence,
            sha256=sha256,
            data=assembled,
        )

    @staticmethod
    def _score_assembly(
        fragments: list[Fragment],
        file_type: str,
        assembled: bytes,
        expected_size: int,
    ) -> float:
        """Score the quality of a fragment assembly."""
        score = 0.0

        # Has valid header → +0.3
        score += 0.3

        # Has matching footer → +0.3
        footers = FragmentHandler._FOOTERS
        if file_type in footers and assembled.endswith(footers[file_type]):
            score += 0.3

        # Size matches expected → +0.2
        if expected_size > 0:
            size_ratio = len(assembled) / expected_size
            if 0.95 < size_ratio < 1.05:
                score += 0.2
            elif 0.8 < size_ratio < 1.2:
                score += 0.1

        # Entropy consistency across fragments → +0.2
        if len(fragments) > 1:
            entropies = [f.entropy for f in fragments]
            avg_e = sum(entropies) / len(entropies)
            max_dev = max(abs(e - avg_e) for e in entropies)
            if max_dev < 1.0:
                score += 0.2
            elif max_dev < 2.0:
                score += 0.1

        return min(1.0, score)
