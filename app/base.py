"""
    SQLAlchemy declarative base.

    Separated from database.py so Alembic's envy.py can import Base
    Without triggering async engine creation. The engine lives in database.py 
    which is never imported by the migration runner. 

"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
