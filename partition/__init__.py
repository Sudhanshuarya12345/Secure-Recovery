# pyrecovery/partition — MBR and GPT partition table parsing.
#
# Partition tables map the logical layout of a disk:
# - MBR (Master Boot Record): Legacy, up to 4 primary partitions, 2TB max
# - GPT (GUID Partition Table): Modern, 128+ partitions, 8ZB max
#
# Both formats must be parsed to know WHERE each filesystem starts,
# which is required before any filesystem-aware recovery can begin.

from partition.mbr import MBRParser, MBRPartitionEntry
from partition.gpt import GPTParser, GPTPartitionEntry
from partition.scanner import PartitionScanner, DetectedPartition

__all__ = [
    "MBRParser", "MBRPartitionEntry",
    "GPTParser", "GPTPartitionEntry",
    "PartitionScanner", "DetectedPartition",
]
