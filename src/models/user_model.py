from sqlalchemy import Boolean, Column,Integer, String, TIMESTAMP
from datetime import datetime , timezone
from db.base import Base
from sqlalchemy.dialects.postgresql import JSONB




class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String , nullable = False , index = True)
    country_code = Column(String , nullable = False)
    phone_number = Column(String , nullable = False)
    password = Column(String , nullable = False)