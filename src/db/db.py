import os
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
from sqlalchemy import insert
from contextlib import asynccontextmanager
from db.base import Base
from models.user_model import User
from models.agent_model import AgentGroups , Agents
from models.event_model import AuthEvents , ProcessEvents , NetworkEvents , USBEvents , FileEvents
import json
from datetime import datetime

load_dotenv()


dbuser = os.environ.get("DB_USER")
dbpassword = os.environ.get("DB_PASSWORD")
dbendpoint = os.environ.get("DB_ENDPOINT")
# dbname = os.environ.get("DB_NAME")
dbname = "testdb"


DATABASE_URL_ASYNC=f"postgresql+asyncpg://{dbuser}:{dbpassword}@{dbendpoint}:5432/{dbname}"

async_engine: AsyncEngine = create_async_engine(DATABASE_URL_ASYNC)

AsyncSessionLocal = sessionmaker(
    async_engine, class_=AsyncSession, expire_on_commit=False
)




async def get_async_db():
    """
    Async context manager providing a scoped AsyncSession for a designated target database.

    Examples:
    ---------
    >>> async with get_async_db() as session:
    >>>     result = await session.execute(select(User))
    >>>     data = result.scalars().all()
    """

    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

get_async_session = asynccontextmanager(get_async_db)

async def create_db_and_tables():
   
    print(f"Running with Database...")
    
    
    async with async_engine.begin() as conn:
        try:        
            await conn.run_sync(Base.metadata.create_all)
        except SQLAlchemyError as e:
            raise RuntimeError(message = f"Failed to initialize tables with data: {str(e)}")
        

CATEGORIES_TABLE_MAPPING = {
    "authentication": AuthEvents ,
    "file": FileEvents,
    "network": NetworkEvents,
    "process": ProcessEvents ,
    "usb" : USBEvents
    }



        
async def push_data_to_db(data_to_push , agents_map):
    meta_data = data_to_push.get("meta_data")
    events_data = data_to_push.get("event_data")

    agent_name = meta_data.get("agent_name")
    agent_id = agents_map.get(agent_name)
    category_wise_data = {}
    available_categories = []
    for ed in events_data:
        cat = ed.get("category")
        if cat:
            ed["agent_id"] = agent_id
            if not category_wise_data.get(cat):
                available_categories.append(cat)
                category_wise_data[cat] = []
                if isinstance(ed.get("tags"), str):
                    try:
                        ed["tags"] = json.loads(ed["tags"])
                    except Exception:
                        ed["tags"] = [ed["tags"]] # Fallback array
            
            category_wise_data[cat].append(ed)
    try:
        for cat, records in category_wise_data.items():
                model_class = CATEGORIES_TABLE_MAPPING[cat]
                
                # 1. Get valid column names for this specific SQLAlchemy model
                valid_columns = set(model_class.__table__.columns.keys())
                
                # 2. Filter out any extra keys from the incoming dictionaries
                cleaned_records = [
                    {k: v for k, v in record.items() if k in valid_columns}
                    for record in records
                ]
                
                # 3. Execute bulk insert if there are valid records to push
                if cleaned_records:
                    async with get_async_session() as session:
                        await session.execute(
                            insert(model_class),
                            cleaned_records
                        )
                        await session.commit()
    except Exception as e:
        print(f"Failed to psuh data in db {str(e)}")
