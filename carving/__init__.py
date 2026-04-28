# pyrecovery/carving — File carving engine and signature-based file recovery
#
# Carving recovers files from raw bytes using format-specific magic byte
# signatures, without requiring any filesystem metadata. This is the
# technique of last resort — it works even on completely destroyed filesystems.

from carving.engine import CarvingEngine, CarvedFile, CarvingResult
from carving.base_signature import BaseSignature
from carving.registry import SignatureRegistry
from carving.chunk_reader import ChunkReader
from carving.validator import CarvedFileValidator
from carving.deduplicator import Deduplicator

__all__ = [
    "CarvingEngine",
    "CarvedFile",
    "CarvingResult",
    "BaseSignature",
    "SignatureRegistry",
    "ChunkReader",
    "CarvedFileValidator",
    "Deduplicator",
]
