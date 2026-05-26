import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum
import socket
import platform

class EventCategory(str, Enum):
    NETWORK = "network"

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
class NetworkEvent:
    # --- Core Identify & Meta ---
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    category: str = EventCategory.NETWORK
    action: str = ""
    outcome: str = EventOutcome.UNKNOWN
    severity: str = Severity.INFO
    collector: str = "network_monitor"
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    # --- Flattened Network Metrics & Telemetry ---
    network_direction: Optional[str] = None          # inbound | outbound
    network_transport: Optional[str] = None          # tcp | udp
    network_protocol: Optional[str] = None           # http | dns | ssh | unknown ...
    network_src_ip: Optional[str] = None
    network_src_port: Optional[int] = None
    network_dst_ip: Optional[str] = None
    network_dst_port: Optional[int] = None
    network_connection_status: Optional[str] = None  # ESTABLISHED, LISTEN, etc.
    network_is_private_ip: Optional[bool] = None
    network_bytes_sent: Optional[int] = None          # For bandwidth anomalies
    network_bytes_recv: Optional[int] = None          # For bandwidth anomalies
    network_dns_query: Optional[str] = None           # Placed here for flat dns extensions
    network_dns_response: Optional[List[str]] = None

    # --- Flattened Process Context ---
    process_pid: Optional[int] = None
    process_ppid: Optional[int] = None
    process_name: Optional[str] = None
    process_executable: Optional[str] = None
    process_command_line: Optional[str] = None
    process_user: Optional[str] = None

    # --- Threat Intelligence Fields ---
    risk_score: Optional[float] = None
    anomaly: Optional[bool] = None
    ioc_match: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to flat dictionary and filter out None values."""
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