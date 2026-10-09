"""
    Database configuration and connection management.

    Uses SQLAlchemy's async engine so database queries don't block
    the FastAPI event loop — the same principle as aiofiles for storage.

    Why asyncpg not psycopg2?
    asyncpg is a pure-async PostgreSQL driver — it yields control to
    the event loop during every query. psycopg2 is synchronous and
    would block the event loop the same way synchronous file I/O did
    before we switched to aiofiles.
"""
import os

from app.config import settings
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from app.base import Base  # ← import from base, not defined here

# Read from environment -Never hardcode credentials in source code
DATABASE_URL = settings.database_url

# TESTING env var is set by conftest.py before app imports
# NullPool in tests eliminates "Future attached to a different loop" errors when using pytest-asyncio
_use_null_pool = os.environ.get("TESTING", "false").lower() in ("1", "true", "yes")

# Create_async_engine is the async version of create_engine - the connection pool to PostgreSQL
# pool_pre_ping=True ensures that connections are checked for liveness before being used.
# It catches and handles any dropped connections, preventing errors during queries.
# These stale connections may appear healthy but have been closed by the server (Common after server restarts)
engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,  # Check connections for liveness before using them
    echo=False,  # Log SQL queries for debugging
    poolclass=NullPool if _use_null_pool else None,  # Use NullPool for testing to avoid connection pooling issues
)

# AsyncSession is the async version of Session - it manages database transactions and queries asynchronously.
# sessionmaker is a factory for creating new Session objects. It is configured to use the async engine and not expire objects on commit.
# expire_on_commit=False means that objects will not be expired (i.e., their state will not be cleared) after a commit, allowing them to be reused without reloading from the database.
AsyncSessionLocal = async_sessionmaker(engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_db():

    """
    Dependency function to provide a database session for FastAPI routes.

    This function is used with FastAPI's dependency injection system.
    It creates a new database session for each request and ensures that
    the session is properly closed after the request is completed.

    Yields:
        AsyncSession: An asynchronous database session.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()  # Commit the transaction if no exceptions occurred
        except Exception:
            await session.rollback()  # Rollback the transaction in case of an exception
            raise  # Re-raise the exception to be handled by FastAPI
        finally:
            await session.close()  # Ensure the session is closed after use

            