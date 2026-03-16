from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class HysteriaInboundBase(BaseModel):
    remark: str = Field(..., min_length=1, max_length=255)
    port: str = Field(..., min_length=1, max_length=64)
    up_mbps: Optional[int] = Field(default=None, ge=1)
    down_mbps: Optional[int] = Field(default=None, ge=1)
    obfs_password: Optional[str] = Field(default=None, max_length=255)
    masquerade: str = Field(default="https://www.bing.com", min_length=1, max_length=512)
    cert_mode: Literal["self_signed", "custom_domain"] = Field(default="self_signed")
    sni: Optional[str] = Field(default=None, max_length=255)
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None
    is_active: bool = Field(True)

    @field_validator("remark", "port", "masquerade")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("obfs_password", "sni", "cert_pem", "key_pem")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class HysteriaInboundCreate(HysteriaInboundBase):
    pass


class HysteriaInboundUpdate(BaseModel):
    remark: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[str] = Field(default=None, min_length=1, max_length=64)
    up_mbps: Optional[int] = Field(default=None, ge=1)
    down_mbps: Optional[int] = Field(default=None, ge=1)
    obfs_password: Optional[str] = Field(default=None, max_length=255)
    masquerade: Optional[str] = Field(default=None, min_length=1, max_length=512)
    cert_mode: Optional[Literal["self_signed", "custom_domain"]] = None
    sni: Optional[str] = Field(default=None, max_length=255)
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("remark", "port", "masquerade")
    @classmethod
    def normalize_required_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("obfs_password", "sni", "cert_pem", "key_pem")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class HysteriaInboundResponse(HysteriaInboundBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
