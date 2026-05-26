"""
Sentinel Agent - Flat Auth Event Schema
A flat, non-nested schema tailored strictly for the Authentication Collector.
"""

import uuid
import socket
import platform
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

# --- Enums ---
class EventCategory(str, Enum):
    AUTH = "authentication"

class EventAction(str, Enum):
    LOGIN       = "login"
    LOGOUT      = "logout"
    LOGIN_FAIL  = "login_failed"
    SUDO        = "sudo"
    SSH_ACCEPT  = "ssh_accepted"
    SSH_FAIL    = "ssh_failed"
    PASSWD_CHG  = "password_change"
    USER_ADD    = "user_add"
    USER_DEL    = "user_delete"

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


# --- Default Host Field Resolvers ---
def _get_ip_addresses() -> List[str]:
    try:
        return [
            info[4][0]
            for info in socket.getaddrinfo(socket.gethostname(), None)
            if info[4][0] not in ('127.0.0.1', '::1')
        ]
    except Exception:
        return []


@dataclass
class AuthEvent:
    """Universal completely flattened authentication security event."""
    
    # Core Identity Fields
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    # Classification
    category: str = EventCategory.AUTH
    action: str = ""
    outcome: str = EventOutcome.UNKNOWN
    severity: str = Severity.INFO
    tags: List[str] = field(default_factory=list)
    collector: str = ""        

    # Flattened User Fields
    user_name: Optional[str] = None
    user_terminal: Optional[str] = None
    user_session_id: Optional[str] = None

    # Flattened Process Fields
    process_pid: Optional[int] = None
    process_name: Optional[str] = None

    # Flattened Authentication Metadata Fields
    auth_method: Optional[str] = None       # password | key | token
    auth_source_ip: Optional[str] = None
    auth_source_port: Optional[int] = None
    auth_failure_reason: Optional[str] = None
    auth_sudo_command: Optional[str] = None
    auth_pam_module: Optional[str] = None
    auth_session_type: Optional[str] = None   # ssh | tty | pts | rdp

    # Flattened Intelligence Layers
    mitre_tactic: Optional[str] = None   
    mitre_technique: Optional[str] = None 
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to clean flat dict, removing keys with None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}