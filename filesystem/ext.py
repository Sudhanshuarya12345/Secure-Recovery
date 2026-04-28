"""
pyrecovery.filesystem.ext — EXT2/3/4 filesystem parser for file recovery.

EXT key structures:
1. Superblock at offset 1024: filesystem geometry, inode count, block size
2. Block Group Descriptor Table: locates inode tables per block group
3. Inode Table: one inode per file/directory (128 or 256 bytes each)
4. Directory Entries: variable-length entries within directory data blocks

Deleted file recovery in EXT:
- Inode deletion_time is set but inode data often remains
- Block pointers in deleted inodes may still be valid
- In EXT4 with extents, extent tree in deleted inodes can recover large files
- Journal ($JOURNAL) may contain old copies of deleted inodes (future work)

Block addressing:
- EXT2/3: 12 direct + 1 indirect + 1 double-indirect + 1 triple-indirect
- EXT4: Extent tree (more efficient, handles large files better)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from disk.reader import DiskReader
from utils.logger import get_logger
from utils.size_formatter import format_size

logger = get_logger(__name__)


@dataclass
class EXTSuperblock:
    """Parsed EXT superblock (at offset 1024 within the partition)."""
    inodes_count: int = 0
    blocks_count: int = 0
    block_size: int = 1024
    blocks_per_group: int = 0
    inodes_per_group: int = 0
    inode_size: int = 128
    magic: int = 0
    volume_label: str = ""
    fs_version: str = "ext2"  # ext2, ext3, ext4
    compat_features: int = 0
    incompat_features: int = 0
    ro_compat_features: int = 0

    @property
    def block_group_count(self) -> int:
        if self.blocks_per_group == 0:
            return 0
        return (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group


@dataclass
class EXTInode:
    """Parsed EXT inode."""
    inode_number: int
    mode: int               # File type and permissions
    uid: int
    file_size: int
    access_time: int
    create_time: int
    modify_time: int
    delete_time: int        # Non-zero = deleted
    links_count: int
    blocks: int             # 512-byte blocks allocated
    flags: int
    # Block pointers (EXT2/3) or extent header (EXT4)
    block_data: bytes = b""  # Raw 60 bytes of block/extent data
    is_deleted: bool = False
    is_directory: bool = False
    is_regular_file: bool = False
    is_symlink: bool = False
    filename: str = ""       # Populated during directory walk
    path: str = ""           # Full path


class EXTParser:
    """Parse EXT2/3/4 filesystems for file recovery.

    Usage::

        parser = EXTParser(reader, partition_start_lba=2048)
        if parser.initialize():
            files = parser.list_files(include_deleted=True)
            for f in files:
                data = parser.read_file(f)
    """

    # Inode type mask (from mode field)
    S_IFMT = 0xF000
    S_IFREG = 0x8000  # Regular file
    S_IFDIR = 0x4000  # Directory
    S_IFLNK = 0xA000  # Symbolic link

    def __init__(self, reader: DiskReader, partition_start_lba: int = 0) -> None:
        self._reader = reader
        self._part_start = partition_start_lba
        self._sb: EXTSuperblock | None = None
        self._bgd: list[dict] = []  # Block group descriptors
        self._initialized = False

    def initialize(self) -> bool:
        """Parse superblock and block group descriptors.

        Returns:
            True if valid EXT filesystem found.
        """
        sb_data = self._read_partition_bytes(1024, 256)
        if len(sb_data) < 256:
            return False

        self._sb = self._parse_superblock(sb_data)
        if self._sb is None or self._sb.magic != 0xEF53:
            return False

        self._load_block_group_descriptors()
        self._initialized = True

        logger.info(
            "EXT initialized: version=%s, block_size=%d, "
            "inodes=%d, blocks=%d, label=%r",
            self._sb.fs_version, self._sb.block_size,
            self._sb.inodes_count, self._sb.blocks_count,
            self._sb.volume_label,
        )
        return True

    def list_files(
        self, include_deleted: bool = True
    ) -> list[EXTInode]:
        """List all files by walking directory tree from root inode.

        Args:
            include_deleted: Include deleted inodes found in directory entries.

        Returns:
            List of EXTInode entries.
        """
        if not self._initialized or self._sb is None:
            return []

        results: list[EXTInode] = []
        # EXT root directory is always inode 2
        self._walk_directory(2, "/", results, include_deleted)
        return results

    def read_file(self, inode: EXTInode) -> bytes:
        """Read file data from inode block pointers or extents.

        Args:
            inode: EXTInode to read.

        Returns:
            File content bytes.
        """
        if not self._initialized or self._sb is None:
            return b""

        if inode.file_size == 0:
            return b""

        # Check if using extents (EXT4) or block pointers (EXT2/3)
        uses_extents = bool(inode.flags & 0x80000)  # EXT4_EXTENTS_FL

        if uses_extents:
            blocks = self._parse_extents(inode.block_data, inode.file_size)
        else:
            blocks = self._parse_block_pointers(inode.block_data, inode.file_size)

        # Read blocks
        result = bytearray()
        block_size = self._sb.block_size

        for block_num in blocks:
            if block_num == 0:
                result.extend(b'\x00' * block_size)  # Sparse block
            else:
                data = self._read_block(block_num)
                result.extend(data)
            if len(result) >= inode.file_size:
                break

        return bytes(result[:inode.file_size])

    @property
    def superblock(self) -> EXTSuperblock | None:
        return self._sb

    # ── Private methods ─────────────────────────────────────────────

    def _parse_superblock(self, data: bytes) -> EXTSuperblock | None:
        """Parse the 256-byte EXT superblock."""
        magic = struct.unpack_from('<H', data, 56)[0]
        if magic != 0xEF53:
            return None

        inodes = struct.unpack_from('<I', data, 0)[0]
        blocks = struct.unpack_from('<I', data, 4)[0]
        block_size_shift = struct.unpack_from('<I', data, 24)[0]
        block_size = 1024 << block_size_shift

        blocks_per_group = struct.unpack_from('<I', data, 32)[0]
        inodes_per_group = struct.unpack_from('<I', data, 40)[0]

        compat = struct.unpack_from('<I', data, 92)[0]
        incompat = struct.unpack_from('<I', data, 96)[0]
        ro_compat = struct.unpack_from('<I', data, 100)[0]

        label_bytes = data[120:136]
        label = label_bytes.decode('utf-8', errors='replace').rstrip('\x00')

        # Determine version
        if incompat & 0x0040 or incompat & 0x0080:
            version = "ext4"
        elif compat & 0x0004:  # has_journal
            version = "ext3"
        else:
            version = "ext2"

        # Inode size (>= revision 1)
        revision = struct.unpack_from('<I', data, 76)[0]
        inode_size = struct.unpack_from('<H', data, 88)[0] if revision >= 1 else 128

        return EXTSuperblock(
            inodes_count=inodes,
            blocks_count=blocks,
            block_size=block_size,
            blocks_per_group=blocks_per_group,
            inodes_per_group=inodes_per_group,
            inode_size=inode_size,
            magic=magic,
            volume_label=label,
            fs_version=version,
            compat_features=compat,
            incompat_features=incompat,
            ro_compat_features=ro_compat,
        )

    def _load_block_group_descriptors(self) -> None:
        """Load block group descriptor table."""
        assert self._sb is not None
        bg_count = self._sb.block_group_count
        if bg_count == 0:
            return

        # BGD table starts at block 1 (or block 2 if block_size=1024)
        if self._sb.block_size == 1024:
            bgd_offset = 2 * self._sb.block_size
        else:
            bgd_offset = 1 * self._sb.block_size

        # Each descriptor is 32 bytes (64 bytes in EXT4 with 64-bit)
        desc_size = 32
        bgd_data = self._read_partition_bytes(bgd_offset, bg_count * desc_size)

        self._bgd = []
        for i in range(bg_count):
            offset = i * desc_size
            if offset + 32 > len(bgd_data):
                break
            self._bgd.append({
                "block_bitmap": struct.unpack_from('<I', bgd_data, offset + 0)[0],
                "inode_bitmap": struct.unpack_from('<I', bgd_data, offset + 4)[0],
                "inode_table": struct.unpack_from('<I', bgd_data, offset + 8)[0],
                "free_blocks": struct.unpack_from('<H', bgd_data, offset + 12)[0],
                "free_inodes": struct.unpack_from('<H', bgd_data, offset + 14)[0],
                "used_dirs": struct.unpack_from('<H', bgd_data, offset + 16)[0],
            })

        logger.debug("Loaded %d block group descriptors", len(self._bgd))

    def _read_inode(self, inode_num: int) -> EXTInode | None:
        """Read and parse a single inode by number."""
        assert self._sb is not None
        if inode_num == 0:
            return None

        # Inode numbers are 1-based
        bg_index = (inode_num - 1) // self._sb.inodes_per_group
        inode_index = (inode_num - 1) % self._sb.inodes_per_group

        if bg_index >= len(self._bgd):
            return None

        inode_table_block = self._bgd[bg_index]["inode_table"]
        inode_offset = (inode_table_block * self._sb.block_size +
                        inode_index * self._sb.inode_size)

        data = self._read_partition_bytes(inode_offset, self._sb.inode_size)
        if len(data) < 128:
            return None

        return self._parse_inode(data, inode_num)

    def _parse_inode(self, data: bytes, inode_num: int) -> EXTInode:
        """Parse raw inode data (128+ bytes)."""
        mode = struct.unpack_from('<H', data, 0)[0]
        uid = struct.unpack_from('<H', data, 2)[0]
        size_lo = struct.unpack_from('<I', data, 4)[0]
        atime = struct.unpack_from('<I', data, 8)[0]
        ctime = struct.unpack_from('<I', data, 12)[0]
        mtime = struct.unpack_from('<I', data, 16)[0]
        dtime = struct.unpack_from('<I', data, 20)[0]
        links = struct.unpack_from('<H', data, 26)[0]
        blocks = struct.unpack_from('<I', data, 28)[0]
        flags = struct.unpack_from('<I', data, 32)[0]

        # Size: for regular files, high 32 bits at offset 108 (if revision >= 1)
        size_hi = struct.unpack_from('<I', data, 108)[0] if len(data) > 108 else 0
        file_size = (size_hi << 32) | size_lo

        # Block data (60 bytes at offset 40)
        block_data = data[40:100]

        file_type = mode & self.S_IFMT

        return EXTInode(
            inode_number=inode_num,
            mode=mode,
            uid=uid,
            file_size=file_size,
            access_time=atime,
            create_time=ctime,
            modify_time=mtime,
            delete_time=dtime,
            links_count=links,
            blocks=blocks,
            flags=flags,
            block_data=block_data,
            is_deleted=(dtime != 0),
            is_directory=(file_type == self.S_IFDIR),
            is_regular_file=(file_type == self.S_IFREG),
            is_symlink=(file_type == self.S_IFLNK),
        )

    def _walk_directory(
        self,
        inode_num: int,
        path: str,
        results: list[EXTInode],
        include_deleted: bool,
        depth: int = 0,
    ) -> None:
        """Recursively walk directory entries."""
        if depth > 32:
            return

        inode = self._read_inode(inode_num)
        if inode is None or not inode.is_directory:
            return

        dir_data = self.read_file(inode)
        if not dir_data:
            return

        pos = 0
        while pos + 8 < len(dir_data):
            entry_inode = struct.unpack_from('<I', dir_data, pos)[0]
            rec_len = struct.unpack_from('<H', dir_data, pos + 4)[0]
            name_len = dir_data[pos + 6]

            if rec_len == 0:
                break

            if pos + 7 < len(dir_data):
                file_type = dir_data[pos + 7]
            else:
                file_type = 0

            if name_len > 0 and pos + 8 + name_len <= len(dir_data):
                name = dir_data[pos + 8:pos + 8 + name_len].decode(
                    'utf-8', errors='replace'
                )
            else:
                name = ""

            pos += rec_len

            if name in (".", "..") or name == "":
                continue

            if entry_inode == 0:
                continue

            child_inode = self._read_inode(entry_inode)
            if child_inode is None:
                continue

            child_inode.filename = name
            child_inode.path = path + name

            if not include_deleted and child_inode.is_deleted:
                continue

            if child_inode.is_directory:
                child_inode.path += "/"
                results.append(child_inode)
                self._walk_directory(
                    entry_inode, child_inode.path,
                    results, include_deleted, depth + 1,
                )
            else:
                results.append(child_inode)

    def _parse_block_pointers(
        self, block_data: bytes, file_size: int
    ) -> list[int]:
        """Parse EXT2/3 block pointers (12 direct + indirect)."""
        assert self._sb is not None
        blocks_needed = (file_size + self._sb.block_size - 1) // self._sb.block_size
        result: list[int] = []

        # 12 direct block pointers (offsets 0-47, 4 bytes each)
        for i in range(min(12, blocks_needed)):
            block = struct.unpack_from('<I', block_data, i * 4)[0]
            result.append(block)

        if len(result) >= blocks_needed:
            return result

        # Indirect block (offset 48)
        indirect = struct.unpack_from('<I', block_data, 48)[0]
        if indirect > 0:
            result.extend(
                self._read_indirect_block(indirect, blocks_needed - len(result))
            )

        if len(result) >= blocks_needed:
            return result

        # Double indirect (offset 52)
        dindirect = struct.unpack_from('<I', block_data, 52)[0]
        if dindirect > 0:
            result.extend(
                self._read_double_indirect(dindirect, blocks_needed - len(result))
            )

        return result[:blocks_needed]

    def _parse_extents(self, block_data: bytes, file_size: int) -> list[int]:
        """Parse EXT4 extent tree from inode block_data."""
        assert self._sb is not None
        blocks_needed = (file_size + self._sb.block_size - 1) // self._sb.block_size

        # Extent header: magic=0xF30A, entries, max, depth, generation
        if len(block_data) < 12:
            return []

        magic = struct.unpack_from('<H', block_data, 0)[0]
        if magic != 0xF30A:
            # Fall back to block pointers
            return self._parse_block_pointers(block_data, file_size)

        entries = struct.unpack_from('<H', block_data, 2)[0]
        depth = struct.unpack_from('<H', block_data, 6)[0]

        result: list[int] = []

        if depth == 0:
            # Leaf node: extent entries start at offset 12
            for i in range(entries):
                offset = 12 + i * 12
                if offset + 12 > len(block_data):
                    break
                # ee_block = struct.unpack_from('<I', block_data, offset)[0]
                ee_len = struct.unpack_from('<H', block_data, offset + 4)[0]
                ee_start_hi = struct.unpack_from('<H', block_data, offset + 6)[0]
                ee_start_lo = struct.unpack_from('<I', block_data, offset + 8)[0]
                start_block = (ee_start_hi << 32) | ee_start_lo

                # Uninitialized extent flag
                actual_len = ee_len & 0x7FFF

                for j in range(actual_len):
                    result.append(start_block + j)
        else:
            # Internal node: index entries point to child blocks
            for i in range(entries):
                offset = 12 + i * 12
                if offset + 12 > len(block_data):
                    break
                ei_leaf_hi = struct.unpack_from('<H', block_data, offset + 6)[0]
                ei_leaf_lo = struct.unpack_from('<I', block_data, offset + 8)[0]
                child_block = (ei_leaf_hi << 32) | ei_leaf_lo

                child_data = self._read_block(child_block)
                child_blocks = self._parse_extents(child_data, file_size)
                result.extend(child_blocks)

        return result[:blocks_needed]

    def _read_indirect_block(self, block_num: int, max_blocks: int) -> list[int]:
        """Read an indirect block (array of block numbers)."""
        assert self._sb is not None
        data = self._read_block(block_num)
        entries_per_block = self._sb.block_size // 4
        result: list[int] = []

        for i in range(min(entries_per_block, max_blocks)):
            block = struct.unpack_from('<I', data, i * 4)[0]
            if block == 0:
                break
            result.append(block)

        return result

    def _read_double_indirect(self, block_num: int, max_blocks: int) -> list[int]:
        """Read a double-indirect block."""
        assert self._sb is not None
        data = self._read_block(block_num)
        entries_per_block = self._sb.block_size // 4
        result: list[int] = []

        for i in range(entries_per_block):
            if len(result) >= max_blocks:
                break
            indirect_block = struct.unpack_from('<I', data, i * 4)[0]
            if indirect_block == 0:
                break
            result.extend(
                self._read_indirect_block(indirect_block, max_blocks - len(result))
            )

        return result

    def _read_block(self, block_num: int) -> bytes:
        """Read a single filesystem block."""
        assert self._sb is not None
        offset = block_num * self._sb.block_size
        return self._read_partition_bytes(offset, self._sb.block_size)

    def _read_partition_bytes(self, offset: int, size: int) -> bytes:
        """Read bytes at offset relative to partition start."""
        abs_offset = self._part_start * self._reader.sector_size + offset
        return self._reader.read_at(abs_offset, size)
