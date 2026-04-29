from typing import Dict, List, Optional
import os

from filesystem.models import DirectoryNode
from filesystem.ntfs import NTFSParser, NTFSFileEntry

class NTFSTreeBuilder:
    def __init__(self, parser: NTFSParser):
        self.parser = parser

    def build(self, include_deleted: bool = True, max_records: int = 200000) -> DirectoryNode:
        """Scan MFT and build a complete directory tree."""
        entries = self.parser.list_files(include_deleted=include_deleted, max_records=max_records)
        
        # Root node
        root = DirectoryNode(name="/", path="/", is_directory=True)
        
        # Dictionary to map mft_index to DirectoryNode
        node_map: Dict[int, DirectoryNode] = {5: root} # MFT index 5 is the root directory
        
        # First pass: create nodes for directories
        for entry in entries:
            if entry.is_directory:
                node = DirectoryNode(
                    name=entry.filename,
                    path=entry.path,
                    deleted=entry.is_deleted,
                    is_directory=True,
                    entry=entry
                )
                node_map[entry.mft_index] = node
                
        # Second pass: link directories and add files
        for entry in entries:
            parent_mft = entry.parent_mft
            
            # Find parent node, fallback to root if orphaned
            parent_node = node_map.get(parent_mft, root)
            
            if entry.is_directory:
                # Node already created in first pass, just link it
                node = node_map[entry.mft_index]
                if node is not root: # Don't link root to itself
                    parent_node.children.append(node)
            else:
                # Create and link file node
                file_node = DirectoryNode(
                    name=entry.filename,
                    path=entry.path,
                    deleted=entry.is_deleted,
                    is_directory=False,
                    entry=entry
                )
                parent_node.children.append(file_node)
                
        return root

    def recover_file(self, entry: NTFSFileEntry, output_path: str):
        """Recover a file to the output path."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        data = self.parser.read_file(entry)
        with open(output_path, 'wb') as f:
            f.write(data)
