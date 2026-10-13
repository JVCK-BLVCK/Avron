"""
This module contains the database connection and session management for the application.
It uses SQLAlchemy's async engine to ensure that database queries do not block the FastAPI event
loop, similar to how aiofiles handles asynchronous file I/O.

Separate from models.py (Pydantic) to maintain the distinction:
  models.py    — HTTP contract (what the API sends/receives)
  models_db.py — Storage contract (what the database contains)

These two representations of a "scan" serve different masters:
  Pydantic validates and serialises HTTP data
  SQLAlchemy maps Python objects to database rows
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Integer, String, DateTime, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.base import Base


class Scan(Base):
    """
    Represents a scan record in the database.

    Column design decisions:
      scan_id: UUID as string — matches existing scan_id format,
               avoids UUID type compatibility issues across DBs
      results: JSON column — Nuclei findings are variable-structure dicts,
               JSON is the correct type (not a separate findings table)
               because findings are always read and written together,
               never queried individually
      error:   Text not String — error messages have no predictable
               length limit; Text is unbounded

    """
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    results: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """
        Convert the Scan object to a dictionary representation.

        Returns:
            dict: A dictionary containing the scan's attributes.
        """
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status,
            "results": self.results,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
