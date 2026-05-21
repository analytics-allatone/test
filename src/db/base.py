from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncAttrs

class Base(AsyncAttrs, DeclarativeBase):
    pass 

class MasterBase(AsyncAttrs, DeclarativeBase):
    pass 