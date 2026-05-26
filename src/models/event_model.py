import uuid
import json
from datetime import datetime , timezone
from db.base import Base
from sqlalchemy import (
    Column, Integer, BigInteger, String, TIMESTAMP ,
    Boolean , Float , TypeDecorator
)
from sqlalchemy.dialects.postgresql import JSONB



class ForceDateTime(TypeDecorator):
    """Natively converts string ISO timestamps to datetime objects at the query boundary."""
    impl = TIMESTAMP(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if isinstance(value, str):
            clean_str = value.replace("Z", "+00:00")
            return datetime.fromisoformat(clean_str)
        return value
    
class AuthEvents(Base):
    __tablename__ = "auth_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)
    agent_id = Column(Integer , nullable = False , index = True)
    action = Column(String , nullable = False)
    outcome = Column(String , nullable = False)
    severity = Column(String , nullable = False)
    tags = Column(JSONB , nullable=True, default=list)
    collector = Column(String)
    username = Column(String)
    user_terminal = Column(String)
    user_session_id = Column(String)
    process_pid = Column(Integer)
    process_name = Column(String)
    auth_method = Column(String)
    auth_source_ip = Column(String)
    auth_source_port = Column(Integer)
    auth_failure_reason = Column(String)
    auth_sudo_command = Column(String)
    auth_pam_module = Column(String)
    auth_session_type = Column(String)
    mitre_tactic = Column(String)
    mitre_technique = Column(String)
    notes = Column(String)
    timestamp = Column(ForceDateTime)
    ingested_at =  Column(TIMESTAMP(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))





class FileEvents(Base):
    __tablename__ = "file_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)
    agent_id = Column(Integer , nullable = False , index = True)
    action = Column(String , nullable = False)
    outcome = Column(String , nullable = False)
    severity = Column(String , nullable = False)
    collector = Column(String , nullable = False)
    tags = Column(JSONB , nullable=True, default=list)
    notes = Column(String)

    # --- Flattened File Context (No nesting) ---
    file_path = Column(String)
    file_name = Column(String)
    file_extension = Column(String)
    file_directory = Column(String)
    file_old_path = Column(String)
    file_old_sha256 = Column(String)
    file_size_bytes = Column(Integer)
    file_inode = Column(String)
    file_modified_at = Column(ForceDateTime)
    file_created_at = Column(ForceDateTime)
    file_permissions = Column(String)
    file_owner = Column(String)
    file_group = Column(String)
    file_sha256 = Column(String)
    file_sha1 = Column(String)
    file_md5 = Column(String)

    # --- Flattened User Context (No nesting) ---
    user_name = Column(String)
    user_uid = Column(Integer)
    user_gid = Column(Integer)
    user_effective_uid = Column(Integer)
    user_effective_gid = Column(Integer)
    user_home_dir = Column(String)
    user_shell = Column(String)

    # --- Threat Intelligence Context ---
    risk_score = Column(Float)
    anomaly = Column(Boolean , default = False)
    ioc_match = Column(String)
    mitre_tactic = Column(String)
    mitre_technique = Column(String)

    timestamp = Column(ForceDateTime)
    ingested_at =  Column(TIMESTAMP(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))



class NetworkEvents(Base):
    __tablename__ = "network_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)
    agent_id = Column(Integer , nullable = False , index = True)
    action = Column(String , nullable = False)
    outcome = Column(String , nullable = False)
    severity = Column(String , nullable = False)
    collector = Column(String , nullable = False)
    tags = Column(JSONB , nullable=True, default=list)
    notes = Column(String)

    # --- Flattened Network Metrics & Telemetry ---
    network_direction = Column(String)
    network_transport = Column(String)
    network_protocol = Column(String)
    network_src_ip = Column(String)
    network_src_port = Column(Integer)
    network_dst_ip = Column(String)
    network_dst_port = Column(Integer)
    network_connection_status = Column(String)
    network_is_private_ip = Column(Boolean)
    network_bytes_sent = Column(Integer)
    network_bytes_recv = Column(Integer)
    network_dns_query = Column(String)
    network_dns_response = Column(JSONB , nullable=True, default=list)

    # --- Flattened Process Context ---
    process_pid = Column(Integer)
    process_ppid = Column(Integer)
    process_name = Column(String)
    process_executable = Column(String)
    process_command_line = Column(String)
    process_user = Column(String)

    # --- Threat Intelligence Fields ---
    risk_score = Column(Float)
    anomaly = Column(Boolean , default = False)
    ioc_match = Column(String)
    mitre_tactic = Column(String)
    mitre_technique = Column(String)

    timestamp = Column(ForceDateTime)
    ingested_at =  Column(TIMESTAMP(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))




class ProcessEvents(Base):
    __tablename__ = "process_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)
    agent_id = Column(Integer , nullable = False , index = True)
    action = Column(String , nullable = False)
    outcome = Column(String , nullable = False)
    severity = Column(String , nullable = False)
    collector = Column(String , nullable = False)
    tags = Column(JSONB , nullable=True, default=list)
    notes = Column(String)

    # --- Flattened Process Context (No nesting) ---
    process_pid = Column(Integer)
    process_ppid = Column(Integer)
    process_name = Column(String)
    process_executable = Column(String)
    process_command_line = Column(String)
    process_working_dir = Column(String)
    process_start_time = Column(ForceDateTime)
    process_user = Column(String)
    process_cpu_percent = Column(Float)
    process_memory_rss_mb = Column(Float)
    process_sha256 = Column(String)

    # --- Threat Intelligence Context ---
    risk_score = Column(Float)
    anomaly = Column(Boolean , default = False)
    ioc_match = Column(String)
    mitre_tactic = Column(String)
    mitre_technique = Column(String)

    timestamp = Column(ForceDateTime)
    ingested_at =  Column(TIMESTAMP(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))





class USBEvents(Base):
    __tablename__ = "usb_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)
    agent_id = Column(Integer , nullable = False , index = True)
    action = Column(String , nullable = False)
    outcome = Column(String , nullable = False)
    severity = Column(String , nullable = False)
    collector = Column(String , nullable = False)
    tags = Column(JSONB , nullable=True, default=list)
    notes = Column(String)

    # --- Flattened USB Device Context ---
    usb_device_path = Column(String)
    usb_mountpoint = Column(String)
    usb_fstype = Column(String)
    usb_mount_options = Column(String)
    usb_label = Column(String)
    usb_vendor = Column(String)
    usb_model = Column(String)
    usb_serial_number = Column(String)
    usb_size_bytes = Column(Integer)
    usb_used_bytes = Column(Integer)
    usb_transfer_delta_bytes = Column(Integer)

    # --- Accompanying File/Target Context (e.g., for Autorun Alerts) ---
    file_path = Column(String)
    file_name = Column(String)
    file_directory = Column(String)

    # --- Threat Intelligence Context ---
    risk_score = Column(Float)
    anomaly = Column(Boolean , default = False)
    ioc_match = Column(String)
    mitre_tactic = Column(String)
    mitre_technique = Column(String)

    timestamp = Column(ForceDateTime)
    ingested_at =  Column(TIMESTAMP(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))