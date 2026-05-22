"""Base Pydantic schemas"""

from pydantic import BaseModel
from datetime import datetime


class TimestampedModel(BaseModel):
    """Base model with timestamps"""

    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True
