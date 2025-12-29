from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class HttpProbeResult(BaseModel):
    """Results from HTTP probing a domain."""
    
    url: str
    status_code: int
    final_url: Optional[str] = None  # after redirects
    headers: dict[str, str] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)
    server: Optional[str] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    tls: bool = False
    error: Optional[str] = None  # error message if probe failed
    duration_ms: Optional[int] = None  # response time in milliseconds
    

class Asset(BaseModel):
    """A discovered DoD asset."""

    domain: str
    source: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional fields - populated when available
    ip: Optional[str] = None
    org: Optional[str] = None
    cert_issued: Optional[datetime] = None
    cert_expires: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    live: Optional[bool] = None
    
    # HTTP probe results
    http: Optional[HttpProbeResult] = None
    https: Optional[HttpProbeResult] = None

    # TODO: metadata field for source-specific data (structure TBD)