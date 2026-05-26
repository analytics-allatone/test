import uuid
import socket
import platform
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

class EventCategory(str, Enum):
    USB = "usb"


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

@dataclass
class USBEvent:
    # --- Core Metadata ---
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    category: str = EventCategory.USB
    action: str = ""  # usb_connected, usb_disconnected, usb_raw_device, usb_autorun_found, usb_data_transfer
    outcome: str = EventOutcome.UNKNOWN
    severity: str = Severity.INFO
    collector: str = "usb_monitor"
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    # --- Flattened USB Device Context ---
    usb_device_path: Optional[str] = None
    usb_mountpoint: Optional[str] = None
    usb_fstype: Optional[str] = None
    usb_mount_options: Optional[str] = None
    usb_label: Optional[str] = None
    usb_vendor: Optional[str] = None
    usb_model: Optional[str] = None
    usb_serial_number: Optional[str] = None
    usb_size_bytes: Optional[int] = None
    usb_used_bytes: Optional[int] = None
    usb_transfer_delta_bytes: Optional[int] = None

    # --- Accompanying File/Target Context (e.g., for Autorun Alerts) ---
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_directory: Optional[str] = None

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