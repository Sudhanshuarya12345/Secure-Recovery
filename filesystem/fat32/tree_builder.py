import os
import math
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict

from disk.reader import DiskReader
from filesystem.fat32 import FATBootSector
from filesystem.models import DirectoryNode

@dataclass
class FATEntry:
    name: str
    is_deleted: bool
    is_directory: bool
    size: int
    first_cluster: int
    created_at: datetime | None
    modified_at: datetime | None
    accessed_at: datetime | None
    parent_path: str
    full_path: str
    cluster_chain: List[int]
    data_intact: bool

class FATTreeBuilder:
    def __init__(self, reader: DiskReader, boot_sector: FATBootSector, fat_table: Dict[int, int], partition_start_lba: int = 0):
        self.reader = reader
        self.bs = boot_sector
        self.fat_table = fat_table
        self.entries: List[FATEntry] = []
        self._part_start = partition_start_lba

    def build(self) -> DirectoryNode:
        """Returns root DirectoryNode with full tree."""
        root = DirectoryNode(name="/", path="/", is_directory=True)
        self._walk_directory(
            cluster=self.bs.root_cluster,
            parent_path="/",
            parent_node=root
        )
        return root

    def _walk_directory(self, cluster: int, parent_path: str, parent_node: DirectoryNode, depth: int = 0):
        if depth > 32:
            return
            
        entries_data = self._read_chain(cluster, max_size=self.bs.cluster_size * 256)
        if not entries_data:
            return
            
        i = 0
        lfn_parts = []

        while i < len(entries_data):
            entry_bytes = entries_data[i:i+32]
            if len(entry_bytes) < 32 or entry_bytes == b'\x00' * 32:
                break

            first_byte = entry_bytes[0]
            if first_byte == 0x00:
                break
                
            if first_byte == 0x2E:
                i += 32
                continue

            attribute = entry_bytes[11]

            if attribute == 0x0F:
                lfn_parts.insert(0, self._parse_lfn_entry(entry_bytes))
                i += 32
                continue

            is_deleted = (first_byte == 0xE5)
            if is_deleted:
                name_bytes = b'_' + entry_bytes[1:8]
            else:
                name_bytes = entry_bytes[0:8]

            if lfn_parts:
                filename = ''.join(lfn_parts)
                lfn_parts = []
            else:
                short_name = name_bytes.rstrip(b' ').decode('ascii', errors='replace')
                extension = entry_bytes[8:11].rstrip(b' ').decode('ascii', errors='replace')
                filename = f"{short_name}.{extension}" if extension else short_name

            if filename in ('.', '..'):
                i += 32
                continue

            # Volume label
            if attribute & 0x08:
                i += 32
                continue

            first_cluster_hi = struct.unpack_from('<H', entry_bytes, 20)[0]
            first_cluster_lo = struct.unpack_from('<H', entry_bytes, 26)[0]
            first_cluster = (first_cluster_hi << 16) | first_cluster_lo
            file_size = struct.unpack_from('<I', entry_bytes, 28)[0]

            created_at = self._parse_fat_datetime(entry_bytes, 14, 16)
            modified_at = self._parse_fat_datetime(entry_bytes, 22, 24)
            accessed_date = self._parse_fat_date(entry_bytes, 18)

            full_path = parent_path.rstrip('/') + '/' + filename
            cluster_chain = self._get_cluster_chain(first_cluster)
            data_intact = len(cluster_chain) > 0 or first_cluster == 0

            entry = FATEntry(
                name=filename,
                is_deleted=is_deleted,
                is_directory=bool(attribute & 0x10),
                size=file_size,
                first_cluster=first_cluster,
                created_at=created_at,
                modified_at=modified_at,
                accessed_at=datetime(accessed_date.year, accessed_date.month, accessed_date.day) if accessed_date else None,
                parent_path=parent_path,
                full_path=full_path,
                cluster_chain=cluster_chain,
                data_intact=data_intact
            )
            self.entries.append(entry)

            child_node = DirectoryNode(
                name=filename, 
                path=full_path, 
                deleted=is_deleted, 
                is_directory=entry.is_directory,
                entry=entry
            )
            parent_node.children.append(child_node)

            if entry.is_directory and first_cluster >= 2:
                if not is_deleted or (is_deleted and data_intact):
                    self._walk_directory(first_cluster, full_path, child_node, depth + 1)

            i += 32

    def _parse_lfn_entry(self, entry: bytes) -> str:
        chars = bytearray()
        for start, end in [(1, 11), (14, 26), (28, 32)]:
            chars.extend(entry[start:end])
        try:
            text = chars.decode('utf-16-le', errors='replace')
            return text.split('\x00')[0].split('\xff')[0]
        except (UnicodeDecodeError, ValueError):
            return ""

    def _parse_fat_datetime(self, data: bytes, time_offset: int, date_offset: int) -> datetime | None:
        try:
            time_val = struct.unpack_from('<H', data, time_offset)[0]
            date_val = struct.unpack_from('<H', data, date_offset)[0]
            if date_val == 0: return None
            
            h = (time_val >> 11) & 0x1F
            m = (time_val >> 5) & 0x3F
            s = (time_val & 0x1F) * 2
            Y = ((date_val >> 9) & 0x7F) + 1980
            M = (date_val >> 5) & 0x0F
            D = date_val & 0x1F
            
            if M == 0 or D == 0: return None
            return datetime(Y, M, D, h, m, min(s, 59))
        except Exception:
            return None

    def _parse_fat_date(self, data: bytes, date_offset: int) -> datetime | None:
        try:
            date_val = struct.unpack_from('<H', data, date_offset)[0]
            if date_val == 0: return None
            
            Y = ((date_val >> 9) & 0x7F) + 1980
            M = (date_val >> 5) & 0x0F
            D = date_val & 0x1F
            
            if M == 0 or D == 0: return None
            return datetime(Y, M, D)
        except Exception:
            return None

    def _get_cluster_chain(self, start: int) -> List[int]:
        chain = []
        visited = set()
        current = start
        while current >= 2:
            if current in visited:
                break
            if current >= 0x0FFFFFF7:
                break
            chain.append(current)
            visited.add(current)
            current = self.fat_table.get(current, 0x0FFFFFFF)
        return chain

    def _read_chain(self, start_cluster: int, max_size: int = 0) -> bytes:
        result = bytearray()
        cluster = start_cluster
        visited = set()

        while cluster >= 2 and cluster < 0x0FFFFFF8 and len(result) < (max_size if max_size else 10 * 1024 * 1024):
            if cluster in visited:
                break
            visited.add(cluster)

            cluster_data = self._read_cluster(cluster)
            result.extend(cluster_data)

            cluster = self.fat_table.get(cluster, 0x0FFFFFFF)

        return bytes(result)

    def _read_cluster(self, cluster: int) -> bytes:
        sector = self.bs.data_start_sector + (cluster - 2) * self.bs.sectors_per_cluster
        abs_sector = self._part_start + sector
        offset = abs_sector * self.bs.bytes_per_sector
        return self.reader.read_at(offset, self.bs.cluster_size)

    def recover_file(self, entry: FATEntry, output_path: str):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        if entry.cluster_chain:
            self._recover_via_chain(entry, output_path)
        else:
            self._recover_sequential_fallback(entry, output_path)

    def _recover_via_chain(self, entry: FATEntry, output_path: str):
        bytes_remaining = entry.size
        with open(output_path, 'wb') as out:
            for cluster in entry.cluster_chain:
                if bytes_remaining <= 0:
                    break
                data = self._read_cluster(cluster)
                to_write = min(len(data), bytes_remaining)
                out.write(data[:to_write])
                bytes_remaining -= to_write

    def _recover_sequential_fallback(self, entry: FATEntry, output_path: str):
        clusters_needed = math.ceil(entry.size / self.bs.cluster_size)
        with open(output_path, 'wb') as out:
            bytes_written = 0
            for i in range(clusters_needed):
                cluster = entry.first_cluster + i
                data = self._read_cluster(cluster)
                to_write = min(len(data), entry.size - bytes_written)
                out.write(data[:to_write])
                bytes_written += to_write
