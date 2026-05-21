import os
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
from sqlalchemy import insert

from db.base import MasterBase , Base
from models.master_model import User, AgentDBData
from models.data_log_model import MachineLogs

load_dotenv()

"""
Database Configuration and Initialization Module for Dynamic SQLite.

This module sets up dynamic, asynchronous database engines using SQLAlchemy and aiosqlite.
It includes:
- Dynamic AsyncEngine factory for handling multiple SQLite databases (.db files).
- Context-managed async session generators.
- A lifecycle function to create master tables dynamically inside any target database.

Functions:
-----------
- get_dynamic_engine(db_name: str) -> AsyncEngine:
    Retrieves or initializes a cached AsyncEngine for a given SQLite file.

- get_async_db(db_name: str):
    Async context manager generator that yields an `AsyncSession` for a specific database.

- create_db_and_tables(db_name: str):
    Initializes core master database tables (User, AgentDBData) from MasterBase.metadata
    within the specified SQLite target.
"""

# Global engine registry to keep track of connections across different SQLite files
_engines: dict[str, AsyncEngine] = {}
db_dir_name = "databases"
os.makedirs(db_dir_name, exist_ok=True)


def check_db_exists(db_name: str) -> bool:
    """
    Returns True if the specific SQLite database file exists on the disk,
    otherwise returns False.
    """
    # Normalize the file path exactly like get_dynamic_engine
    if not db_name.endswith(".db"):
        file_path = f"{db_dir_name}/{db_name}.db"
    else:
        file_path = db_name
        
    return os.path.exists(file_path)


def get_dynamic_engine(db_name: str) -> AsyncEngine:
    """
    Returns a cached AsyncEngine instance for a specific SQLite database file.
    Creates it if it does not yet exist.
    """
    # Enforce standard database naming convention
    if not db_name.endswith(".db"):
        db_name = f"{db_dir_name}/{db_name}.db"
        
    if db_name not in _engines:
        # Using aiosqlite protocol for asynchronous file access
        db_url = f"sqlite+aiosqlite:///{db_name}"
        
        # check_same_thread=False is safe and required for multi-threaded async frameworks like FastAPI
        _engines[db_name] = create_async_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=False # Set to True if you want to inspect raw SQL queries generated in console
        )
    return _engines[db_name]


@asynccontextmanager
async def get_async_db(db_name: str):
    """
    Async context manager providing a scoped AsyncSession for a designated target database.

    Examples:
    ---------
    >>> async with get_async_db("agent_workspace") as session:
    >>>     result = await session.execute(select(User))
    >>>     data = result.scalars().all()
    """
    engine = get_dynamic_engine(db_name)
    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()



async def create_db_and_tables(db_name: str):
    """
    Initializes the specific SQLite database and builds the structural schema 
    defined inside `MasterBase.metadata`. 

    This handles creating your core initial tables ('user' and 'agent_db_data') on demand or at startup.

    Raises:
    -------
    - RuntimeError: If an exception occurs while binding connections or generating tables.
    """
    print(f"Running with Database: '{db_name}'...")
    engine = get_dynamic_engine(db_name)
    
    async with engine.begin() as conn:
        try:        
            # Builds only tables that directly inherit from MasterBase
            await conn.run_sync(MasterBase.metadata.create_all)
            print(f"Successfully initialized master tables in '{db_name}'.")
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to initialize tables with data: {str(e)}")
        
async def register_new_agent(meta_data):
    try:
        async with get_async_db("master_database") as session:
            new_agent = AgentDBData(
                agent_name = meta_data.get("agent_name"),
                mac_address = meta_data.get("mac_address"),
                host_name = meta_data.get("host_name"),
                main_ip = meta_data.get("main_ipv4"),

                all_ips = meta_data.get("all_ips"),
                system = meta_data.get("system"),
                release = meta_data.get("release"),
                version =  meta_data.get("version"),
                machine_architecture = meta_data.get("machine_architecture"),

                is_active = True
            )
            session.add(new_agent)
            await session.commit()
    except Exception as e:
        print(f"ERROR: {str(e)}")


async def push_data_to_db(data_to_push):
    meta_data = data_to_push["meta_data"]
    log_data = data_to_push["log_data"]

    agent_name = meta_data.get("agent_name")
    if not agent_name:
        return
    
    if not check_db_exists(agent_name):
        await create_agent_db_and_tables(agent_name)
        await register_new_agent(meta_data)
    
    
    try:
        from datetime import datetime
        async with get_async_db(agent_name) as session:
            bulk_records = []
            
            for log in log_data:
                raw_timestamp = log.get("timestamp")
                parsed_timestamp = None
                
                if raw_timestamp:
                    try:
                        # 2. Parse ISO string back into a native Python datetime object 🚀
                        # Handles 'Z' or '+00:00' offsets automatically
                        parsed_timestamp = datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00"))
                    except Exception:
                        # Fallback if the string format is corrupted
                        parsed_timestamp = datetime.now()
                else:
                    # Fallback if no timestamp was provided at all
                    parsed_timestamp = datetime.now()

                bulk_records.append({
                    "machine_id": log.get("machine_id", 0),
                    "timestamp": parsed_timestamp,
                    "category": log.get("category", "unknown"),
                    "action": log.get("action", "unknown"),
                    "outcome": log.get("outcome", "unknown"),
                    "severity": log.get("severity", "info"),
                    "tags": log.get("tags", []),
                    "collector": log.get("collector"),
                    "raw_log": log.get("raw_log"),
                    
                    # Passing raw Python dicts/lists directly works because 
                    # we switched these columns to the generic SQLAlchemy JSON type!
                    "host": log.get("host", {}),  # Cannot be null based on your model
                    "file": log.get("file"),
                    "user": log.get("user"),
                    "process": log.get("process"),
                    "network": log.get("network"),
                    "auth": log.get("auth"),
                    
                    "file_path": log.get("file_path"),
                    "file_sha256": log.get("file_sha256"),
                    "process_name": log.get("process_name"),
                    "process_pid": log.get("process_pid"),
                    "process_sha256": log.get("process_sha256"),
                    "username": log.get("username"),
                    
                    "net_src_ip": log.get("net_src_ip"),
                    "net_src_port": log.get("net_src_port"),
                    "net_dst_ip": log.get("net_dst_ip"),
                    "net_dst_port": log.get("net_dst_port"),
                    "net_protocol": log.get("net_protocol"),
                    
                    "risk_score": log.get("risk_score", 0.0),
                    "anomaly": log.get("anomaly", False),
                    "ioc_match": log.get("ioc_match"),
                    "mitre_tactic": log.get("mitre_tactic"),
                    "mitre_technique": log.get("mitre_technique"),
                    "notes": log.get("notes")
                })
            
            # 4. Compile and commit the batch as a single file-write operation [1]
            await session.execute(
                insert(MachineLogs),
                bulk_records
            )
            await session.commit()
            print(f"⚡ Successfully bulk inserted {len(bulk_records)} records into '{agent_name}.db'")
            
    except Exception as e:
        print(f"❌ Failed executing bulk operation inside '{agent_name}.db': {e}")
    



async def create_agent_db_and_tables(db_name: str):
    engine = get_dynamic_engine(db_name)
    
    async with engine.begin() as conn:
        try:        
            
            await conn.run_sync(Base.metadata.create_all)
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to initialize tables with data: {str(e)}")