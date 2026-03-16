from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class TrojanInboundBase(BaseModel):
    remark: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    network: str = Field("tcp", min_length=1, max_length=32)
    sni: str = Field(..., min_length=1, max_length=255)
    alpn: str = Field("h2,http/1.1", min_length=1, max_length=64)
    fingerprint: str = Field("chrome", min_length=1, max_length=32)
    transport_settings: Optional[dict[str, Any]] = None
    is_active: bool = Field(True)

    @field_validator("remark", "network", "sni", "alpn", "fingerprint")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized


class TrojanInboundCreate(TrojanInboundBase):
    pass


class TrojanInboundUpdate(BaseModel):
    remark: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    network: Optional[str] = Field(default=None, min_length=1, max_length=32)
    sni: Optional[str] = Field(default=None, min_length=1, max_length=255)
    alpn: Optional[str] = Field(default=None, min_length=1, max_length=64)
    fingerprint: Optional[str] = Field(default=None, min_length=1, max_length=32)
    transport_settings: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None

    @field_validator("remark", "network", "sni", "alpn", "fingerprint")
    @classmethod
    def normalize_required_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized


class TrojanInboundResponse(TrojanInboundBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
