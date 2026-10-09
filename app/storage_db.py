"""
This module contains the StorageDB class, which is responsible for managing the storage of data in a database. 
It provides methods for connecting to the database, executing queries, and handling transactions. The StorageDB class is designed
to provide a simple and efficient way to interact with the database.

It replaces the previous storage.py module, which was used for storing data in a file-based format (JSONL). 
The StorageDB class uses SQLAlchemy to interact with the database, providing a more robust and scalable solution for data storage.

Mantains the same interface as the previous storage.py module, allowing for easy migration of existing code to use the new database storage solution.
The contract is identical:
  save_scan(scan_id, data)  → None
  load_scan(scan_id)        → dict | None

Callers don't know or care whether data is in files or a database.

"""
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.models_db import Scan


logger = logging.getLogger(__name__)


async def save_scan(scan_id: str, data: Dict[str, Any]) -> None:
    """ 
    Save or Update scan using scan_id column as primary key. This is the async version for use in FastAPI routes (Async context). 

    """
    from app.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        try:
            # Query by scan_id column
            result = await session.execute(select(Scan).where(Scan.scan_id == scan_id))
            existing_scan = result.scalar_one_or_none()

            if existing_scan is None:
                # Create a new scan record
                scan = Scan(
                    scan_id = data["scan_id"],
                    target = data.get("target", ""),
                    status = data.get("status", "in_progress"),
                    created_at = datetime.now(timezone.utc),
                    updated_at = datetime.now(timezone.utc),
                    error = data.get("error"),
                    results = data.get("results", []),
                )
                session.add(scan)
            else:
                # Update the existing scan record
                await session.execute(
                    update(Scan)
                    .where(Scan.scan_id == scan_id)
                    .values(
                        status = data.get("status", existing_scan.status),
                        updated_at = datetime.now(timezone.utc),
                        error = data.get("error", existing_scan.error),
                        results = data.get("results", existing_scan.results),
                    )
                )

            await session.commit()

        except Exception as e:
            await session.rollback()
            raise IOError(f"Failed to save scan data for scan_id {scan_id}: {str(e)}") from e


async def load_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Load scan data from the database.

    Args:
        scan_id (str): The unique identifier for the scan.

    Returns:
        Optional[Dict[str, Any]]: The scan data if found, otherwise None.
    """
    from app.database import AsyncSessionLocal
    
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(Scan).where(Scan.scan_id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                return None
            
            return {
                "scan_id": scan.scan_id,
                "target": scan.target,
                "status": scan.status,
                "created_at": scan.created_at.isoformat(),
                "updated_at": scan.updated_at.isoformat(),
                "error": scan.error,
                "results": scan.results,
            }

        except Exception as e:
            raise IOError(f"Failed to load scan data for scan_id {scan_id}: {str(e)}") from e


async def get_scans_by_target(
        target: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
    """
    Get all scans for a given target.

    Args:
        target (str): The target for which to retrieve scans.
        limit (int): The maximum number of scans to retrieve.

    Returns:
        List[Dict[str, Any]]: A list of scan data dictionaries.

    Return the N most recent scans for a given target URL.

    Why ORDER BY timestamp DESC?
    Callers almost always want recent history first — the most recent
    scan is the current state, older scans provide the historical baseline.
    Reversing requires the caller to reverse — wasteful.

    Why limit=10?
    Unbounded history queries can return thousands of rows for active targets.
    10 is enough for trend analysis (weekly scans for 10 weeks).
    Callers needing more can pass limit explicitly.
    """

    from app.database import AsyncSessionLocal
    from app.models_db import Scan
    from sqlalchemy import select, desc

    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(
                select(Scan)
                .where(Scan.target == target)
                .order_by(desc(Scan.updated_at))
                .limit(limit)
            )
            scans = result.scalars().all()
            return [scan.to_dict() for scan in scans]

        except Exception as e:
            raise IOError(f"Failed to retrieve scans for target {target}: {str(e)}") from e


async def get_all_targets() -> List[str]:
    """
    Get all unique targets from the scans table.

    Returns:
        List[str]: A list of unique target strings.
    """
    from app.database import AsyncSessionLocal
    from app.models_db import Scan
    from sqlalchemy import select, distinct

    factory = AsyncSessionLocal()
    async with factory as session:
        try:
            result = await session.execute(
                select(distinct(Scan.target))
                .order_by(Scan.target)
            )
            return [row[0] for row in result.fetchall()]

        except Exception as e:
            raise IOError(f"Failed to retrieve unique targets: {str(e)}") from e


def save_scan_sync(scan_id: str, data: Dict[str, Any]) -> None:
    """"
    Synchronous save for use in Celery workeys (Synchronous context).

    Celery workers run in their own process with no asyncio event loop.
    We use a synchronous SQLAlchemy session here — the same data,
    different access pattern.
    
    """
    import psycopg2
    import os
    import json

    # Database connection parameters
    conn_str = os.environ.get(
        "DATABASE_URL_SYNC", 
        "postgresql://${DB_USERNAME}:${DB_PASSWORD}@postgres:5432/${DB_USERNAME}"
    )

    try:
        conn = psycopg2.connect(conn_str)
        cursor = conn.cursor()

        # Check if the scan already exists
        cursor.execute("""
            INSERT INTO scans (scan_id, target, status, created_at, updated_at, error, results)
            VALUES (%s, %s, %s, NOW(), NOW(), %s, %s)
            ON CONFLICT (scan_id) DO UPDATE SET
                status = EXCLUDED.status,
                updated_at = NOW(),
                error = EXCLUDED.error,
                results = EXCLUDED.results
        """, (
            data["scan_id"],
            data.get("target", ""),
            data.get("status", "in_progress"),
            data.get("error"),
            json.dumps(data.get("results", []))
        ))

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        raise IOError(f"Failed to save scan data for scan_id {scan_id}: {str(e)}") from e
    
    