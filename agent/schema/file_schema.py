from enum import Enum
from dataclasses import dataclass
from typing import Optional


class FileEventAction(str , Enum):
    CREATE      = "create"
    READ        = "read"
    UPDATE      = "update"   # content modified
    RENAME      = "rename"
    DELETE      = "delete"
    CHMOD       = "chmod"
    CHOWN       = "chown"






@dataclass
class FileInfo:
    path:           str  = ""
    name:           str  = ""
    extension:      str  = ""
    directory:      str  = ""
    size_bytes:     Optional[int]  = None
    sha256:         Optional[str]  = None
    sha1:           Optional[str]  = None
    md5:            Optional[str]  = None
    inode:          Optional[int]  = None
    permissions:    Optional[str]  = None   # e.g. "644" or "rwxr-xr-x"
    owner:          Optional[str]  = None
    group:          Optional[str]  = None
    created_at:     Optional[str]  = None
    modified_at:    Optional[str]  = None
    old_path:       Optional[str]  = None   # for renames
    old_sha256:     Optional[str]  = None   # hash before modification
