"""
pyrecovery.recovery.directory_tree — Reconstruct directory hierarchy from FS metadata.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional, Iterator
from utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class TreeNode:
    name: str
    is_directory: bool = False
    is_deleted: bool = False
    size: int = 0
    inode: int = -1
    parent_inode: int = -1
    children: list["TreeNode"] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    _full_path: str = ""

    @property
    def full_path(self) -> str:
        return self._full_path or self.name

    @property
    def child_count(self) -> int:
        return len(self.children)

    @property
    def total_descendants(self) -> int:
        count = len(self.children)
        for child in self.children:
            count += child.total_descendants
        return count


class DirectoryTree:
    def __init__(self) -> None:
        self._nodes: dict[int, TreeNode] = {}
        self._root = TreeNode(name="/", is_directory=True, inode=0)
        self._nodes[0] = self._root
        self._built = False

    def add_entry(self, name: str, inode: int = -1, parent: int = -1,
                  is_dir: bool = False, is_deleted: bool = False,
                  size: int = 0, metadata: dict | None = None) -> TreeNode:
        node = TreeNode(name=name, is_directory=is_dir, is_deleted=is_deleted,
                        size=size, inode=inode, parent_inode=parent,
                        metadata=metadata or {})
        if inode >= 0:
            self._nodes[inode] = node
        self._built = False
        return node

    def add_path(self, path: str, is_deleted: bool = False,
                 size: int = 0, metadata: dict | None = None) -> TreeNode:
        parts = PurePosixPath(path).parts
        current = self._root
        for i, part in enumerate(parts):
            if part == "/":
                continue
            existing = next((c for c in current.children if c.name == part), None)
            if existing:
                current = existing
                continue
            is_last = (i == len(parts) - 1)
            node = TreeNode(name=part, is_directory=not is_last,
                            is_deleted=is_deleted if is_last else False,
                            size=size if is_last else 0,
                            metadata=(metadata or {}) if is_last else {})
            current.children.append(node)
            current = node
        self._set_paths(self._root, "")
        return current

    def build(self) -> None:
        orphans: list[TreeNode] = []
        for inode, node in self._nodes.items():
            if inode == 0:
                continue
            parent_inode = node.parent_inode
            if parent_inode in self._nodes:
                parent = self._nodes[parent_inode]
                if node not in parent.children:
                    parent.children.append(node)
            elif parent_inode == 0 or parent_inode == -1:
                if node not in self._root.children:
                    self._root.children.append(node)
            else:
                orphans.append(node)
        if orphans:
            orphan_dir = TreeNode(name="_orphaned", is_directory=True, inode=-999)
            orphan_dir.children = orphans
            self._root.children.append(orphan_dir)
        self._sort_tree(self._root)
        self._set_paths(self._root, "")
        self._built = True

    def walk(self) -> Iterator[str]:
        if not self._built:
            self.build()
        yield from self._walk_node(self._root)

    def walk_all(self) -> Iterator[tuple[str, TreeNode]]:
        if not self._built:
            self.build()
        yield from self._walk_all_node(self._root)

    def get_orphans(self) -> list[TreeNode]:
        orphan_dir = next((c for c in self._root.children if c.name == "_orphaned"), None)
        return orphan_dir.children if orphan_dir else []

    @property
    def root(self) -> TreeNode:
        return self._root

    @property
    def total_files(self) -> int:
        return sum(1 for _ in self.walk())

    def render_tree(self, max_depth: int = 10) -> str:
        if not self._built:
            self.build()
        lines: list[str] = []
        self._render_node(self._root, "", True, lines, 0, max_depth)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        if not self._built:
            self.build()
        return self._node_to_dict(self._root)

    def get_stats(self) -> dict:
        if not self._built:
            self.build()
        total_files = total_dirs = total_size = deleted_files = max_depth = 0
        for path, node in self.walk_all():
            depth = path.count("/")
            max_depth = max(max_depth, depth)
            if node.is_directory:
                total_dirs += 1
            else:
                total_files += 1
                total_size += node.size
                if node.is_deleted:
                    deleted_files += 1
        return {"total_files": total_files, "total_directories": total_dirs,
                "total_size": total_size, "deleted_files": deleted_files,
                "max_depth": max_depth, "orphaned_count": len(self.get_orphans())}

    def _walk_node(self, node: TreeNode) -> Iterator[str]:
        if not node.is_directory:
            yield node.full_path
        for child in node.children:
            yield from self._walk_node(child)

    def _walk_all_node(self, node: TreeNode) -> Iterator[tuple[str, TreeNode]]:
        yield node.full_path, node
        for child in node.children:
            yield from self._walk_all_node(child)

    def _sort_tree(self, node: TreeNode) -> None:
        node.children.sort(key=lambda n: (not n.is_directory, n.name.lower()))
        for child in node.children:
            if child.is_directory:
                self._sort_tree(child)

    def _set_paths(self, node: TreeNode, parent_path: str) -> None:
        node._full_path = f"{parent_path}/{node.name}" if parent_path else node.name or "/"
        for child in node.children:
            self._set_paths(child, node._full_path)

    def _render_node(self, node, prefix, is_last, lines, depth, max_depth):
        if depth > max_depth:
            return
        if depth == 0:
            lines.append(f"{'D' if node.is_directory else 'F'} {node.name or '/'}")
        else:
            conn = "└── " if is_last else "├── "
            d = " [DEL]" if node.is_deleted else ""
            s = f" ({node.size:,}B)" if not node.is_directory else ""
            lines.append(f"{prefix}{conn}{node.name}{s}{d}")
        for i, child in enumerate(node.children):
            il = (i == len(node.children) - 1)
            cp = prefix + ("    " if is_last else "│   ") if depth > 0 else ""
            self._render_node(child, cp, il, lines, depth + 1, max_depth)

    def _node_to_dict(self, node: TreeNode) -> dict:
        d: dict = {"name": node.name, "is_directory": node.is_directory}
        if not node.is_directory:
            d["size"] = node.size
        if node.is_deleted:
            d["is_deleted"] = True
        if node.children:
            d["children"] = [self._node_to_dict(c) for c in node.children]
        return d
