from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AuditLogItemResponse(BaseModel):
    id: int
    created_at: datetime
    ip_address: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    success: bool

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    logs: list[AuditLogItemResponse]
    total: int
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
