from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class DirectoryNode:
    name: str
    path: str
    deleted: bool = False
    is_directory: bool = True
    children: List['DirectoryNode'] = field(default_factory=list)
    
    # Store the actual recovered entry (FATEntry or MFTEntry)
    entry: Optional[any] = None
