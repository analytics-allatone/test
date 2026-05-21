from sqlalchemy import Boolean, Column,Integer, String, TIMESTAMP , Text , TypeDecorator
from datetime import datetime , timezone
from db.base import MasterBase
import json




class SQLiteList(TypeDecorator):
    """Safely coerces Python lists into JSON text strings for SQLite storage."""
    impl = Text

    def process_bind_param(self, value, dialect):
        """Converts Python List -> JSON String (when saving to DB)"""
        if value is not None:
            return json.dumps(value)
        return None

    def process_result_value(self, value, dialect):
        """Converts JSON String -> Python List (when reading from DB)"""
        if value is not None:
            return json.loads(value)
        return []


class User(MasterBase):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String , nullable = False , index = True)
    country_code = Column(String , nullable = False)
    phone_number = Column(String , nullable = False)
    password = Column(String , nullable = False)


class AgentDBData(MasterBase):
    __tablename__ = "agent_db_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_name = Column(String ,nullable = False ,  unique = True)
    mac_address = Column(String)
    host_name = Column(String)
    main_ip = Column(String , unique = True)

    all_ips = Column(SQLiteList , nullable=True)
    system = Column(String)
    release = Column(String)
    version = Column(String)
    machine_architecture = Column(String)

    is_active = Column(Boolean , default = False)
    created_at = Column(TIMESTAMP, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    deactivated_at = Column(TIMESTAMP, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))