from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class VlessInboundBase(BaseModel):
    remark: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    network: str = Field("tcp", min_length=1, max_length=32)
    security: str = Field("reality", min_length=1, max_length=32)
    flow: Optional[str] = Field(default=None, max_length=64)
    sni: Optional[str] = Field(default=None, max_length=255)
    fingerprint: str = Field("chrome", min_length=1, max_length=32)
    spider_x: str = Field("/", min_length=1, max_length=255)
    transport_settings: Optional[dict[str, Any]] = None
    tls_settings: Optional[dict[str, Any]] = None
    is_active: bool = Field(True)

    @field_validator("remark", "network", "security", "fingerprint", "spider_x")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("flow", "sni")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class VlessInboundCreate(VlessInboundBase):
    pass


class VlessInboundUpdate(BaseModel):
    remark: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    network: Optional[str] = Field(default=None, min_length=1, max_length=32)
    security: Optional[str] = Field(default=None, min_length=1, max_length=32)
    flow: Optional[str] = Field(default=None, max_length=64)
    sni: Optional[str] = Field(default=None, max_length=255)
    fingerprint: Optional[str] = Field(default=None, min_length=1, max_length=32)
    spider_x: Optional[str] = Field(default=None, min_length=1, max_length=255)
    transport_settings: Optional[dict[str, Any]] = None
    tls_settings: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None

    @field_validator("remark", "network", "security", "fingerprint", "spider_x")
    @classmethod
    def normalize_required_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("flow", "sni")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class VlessInboundResponse(VlessInboundBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
