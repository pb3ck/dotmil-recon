from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

class Asset(BaseModel):
    """A discovered DoD asset."""

    domain: str
    source: str
    discovered_ai: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional fields - populated when available
    ip: Optional[str] = None
    org: Optional[str] = None
    cert_issued: Optional[datetime] = None
    cert_expires: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    live: Optional[bool] = None

    # TODO: metadata field for source-specific data (structure TBD)