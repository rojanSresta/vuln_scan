"""SQLAlchemy models"""

from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import declarative_base
from app.db.session import utc_now

Base = declarative_base()


class ScanRecord(Base):
    """Database model for scan records"""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, index=True)
    target_url = Column(String)
    status = Column(String)  # pending, running, done, error, cancelled
    progress = Column(Integer, default=0)
    message = Column(String)
    vulnerabilities = Column(JSON, default=list)
    results = Column(JSON, default=list)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
