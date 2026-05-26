from sqlalchemy import Boolean, Column,Integer, String, TIMESTAMP
from datetime import datetime , timezone
from db.base import Base
from sqlalchemy.dialects.postgresql import JSONB



class Agents(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_name = Column(String ,nullable = False ,  unique = True)
    mac_address = Column(String)
    host_name = Column(String)
    main_ip = Column(String)

    all_ips = Column(JSONB , nullable=True , default=list)
    os = Column(String)
    release = Column(String)
    version = Column(String)
    machine_architecture = Column(String)

    status = Column(String , nullable = True , index = True)
    group_id = Column(Integer , nullable = True)

    is_active = Column(Boolean , default = False)
    created_at = Column(TIMESTAMP, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    deactivated_at = Column(TIMESTAMP, nullable=True)



class AgentGroups(Base):
    __tablename__ = "agent_groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    group_name = Column(String ,nullable = False ,  unique = True)
