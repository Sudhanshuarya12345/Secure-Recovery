# pyrecovery/filesystem — Filesystem parsers for recovery
#
# Each parser reads filesystem metadata structures (superblocks, allocation
# tables, directory entries) to recover files using filesystem-level information.
# This is more accurate than carving because it preserves filenames, timestamps,
# directory hierarchy, and can detect logically deleted files.

from filesystem.fat32 import FAT32Parser
from filesystem.ntfs import NTFSParser
from filesystem.ext import EXTParser

__all__ = ["FAT32Parser", "NTFSParser", "EXTParser"]
