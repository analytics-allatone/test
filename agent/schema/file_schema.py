import uuid
import socket
import platform
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

class EventCategory(str, Enum):
    FILE = "file"

class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

class EventAction(str, Enum):
    CREATE = "create"
    DELETE = "delete"
    UPDATE = "update"
    RENAME = "rename"

@dataclass
class FileEvent:

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    category: str = EventCategory.FILE
    action: str = ""
    outcome: str = EventOutcome.UNKNOWN
    severity: str = Severity.INFO
    collector: str = "file_watcher"
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    # --- Flattened File Context (No nesting) ---
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_extension: Optional[str] = None
    file_directory: Optional[str] = None
    file_old_path: Optional[str] = None
    file_old_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_inode: Optional[int] = None
    file_modified_at: Optional[str] = None
    file_created_at: Optional[str] = None
    file_permissions: Optional[str] = None
    file_owner: Optional[str] = None
    file_group: Optional[str] = None
    file_sha256: Optional[str] = None
    file_sha1: Optional[str] = None
    file_md5: Optional[str] = None

    # --- Flattened User Context (No nesting) ---
    user_name: Optional[str] = None
    user_uid: Optional[int] = None
    user_gid: Optional[int] = None
    user_effective_uid: Optional[int] = None
    user_effective_gid: Optional[int] = None
    user_home_dir: Optional[str] = None
    user_shell: Optional[str] = None

    # --- Threat Intelligence Context ---
    risk_score: Optional[float] = None
    anomaly: Optional[bool] = None
    ioc_match: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to plain key-value dict, dropping nulls and resolving Enums/dates."""
        def clean(obj):
            if isinstance(obj, dict):
                return {k: clean(v) for k, v in obj.items() if v is not None}
            elif isinstance(obj, list):
                return [clean(i) for i in obj]
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, Enum):
                return obj.value
            return obj
        return clean(asdict(self))