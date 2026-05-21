import uuid
import json
from datetime import datetime
from db.base import Base
from sqlalchemy import (
    Column, Integer, BigInteger, String,
    Text, Boolean, DateTime, Float, func, TypeDecorator
)

# 🛠️ 1. Custom List Handler for Tags in SQLite (Since SQLite has no ARRAY type)
class SQLiteList(TypeDecorator):
    """Safely coerces Python lists into JSON text strings for SQLite storage."""
    impl = Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return []


class MachineLogs(Base):
    __tablename__ = "machine_logs"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    machine_id = Column(Integer, nullable=False, index=True)

    # 🌟 FIX: PostgreSQL UUID -> SQLite compatible String(36)
    event_id = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, nullable=False)

    # 🌟 FIX: Added default handling for SQLite timestamps
    timestamp = Column(DateTime, nullable=False, default=func.now)
    ingested_at = Column(DateTime, nullable=False, server_default=func.now())

    category = Column(String(32), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    outcome = Column(String(32), nullable=False)
    severity = Column(String(16), nullable=False, index=True)

    # 🌟 FIX: PostgreSQL ARRAY -> Custom SQLite List type
    tags = Column(SQLiteList, nullable=True)

    collector = Column(String(128), nullable=True)
    from sqlalchemy import JSON
    raw_log = Column(JSON, nullable=True)

    # 🌟 FIX: PostgreSQL JSONB -> Standard cross-dialect JSON
    host = Column(Base.metadata.type_api_registry.get('JSON', Text) if hasattr(Base.metadata, 'type_api_registry') else String, nullable=False)
    # A cleaner approach for standard JSON columns across dialects:
    host = Column(JSON, nullable=False)
    file = Column(JSON, nullable=True)
    user = Column(JSON, nullable=True)
    process = Column(JSON, nullable=True)
    network = Column(JSON, nullable=True)
    auth = Column(JSON, nullable=True)

    # File data
    file_path = Column(String, nullable=True)
    file_sha256 = Column(String(64), nullable=True, index=True)

    # Process data
    process_name = Column(String(256), nullable=True)
    process_pid = Column(Integer, nullable=True, index=True)
    process_sha256 = Column(String(64), nullable=True)
    username = Column(String(128), nullable=True, index=True)

    # Network data
    net_src_ip = Column(String(64), nullable=True, index=True)
    net_src_port = Column(Integer, nullable=True)
    net_dst_ip = Column(String(64), nullable=True, index=True)
    net_dst_port = Column(Integer, nullable=True)
    net_protocol = Column(String(32), nullable=True)

    # Threat Intelligence & Metadata
    risk_score = Column(Float, nullable=True)
    anomaly = Column(Boolean, default=False)
    ioc_match = Column(String, nullable=True)
    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique = Column(String(64), nullable=True)
    notes = Column(Text, nullable=True)
