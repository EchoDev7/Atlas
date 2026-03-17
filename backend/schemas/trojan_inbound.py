from datetime import datetime
import secrets
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class TrojanInboundBase(BaseModel):
    remark: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    password: str = Field(default_factory=lambda: secrets.token_urlsafe(24), min_length=8, max_length=255)
    network: str = Field("tcp", min_length=1, max_length=32)
    cert_mode: Literal["self_signed", "custom_domain"] = Field("self_signed")
    sni: str = Field("www.microsoft.com", min_length=1, max_length=255)
    alpn: str = Field("h2,http/1.1", min_length=1, max_length=64)
    fingerprint: str = Field("chrome", min_length=1, max_length=32)
    transport_settings: Optional[dict[str, Any]] = Field(
        default_factory=lambda: {
            "path": "/",
            "host": "",
            "service_name": "",
            "multi_mode": False,
            "accept_proxy": False,
            "mode": "auto",
            "headers": {},
            "extra": None,
        }
    )
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None
    is_active: bool = Field(True)

    @field_validator("remark", "network", "cert_mode", "sni", "alpn", "fingerprint")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("password")
    @classmethod
    def normalize_password(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 8:
            raise ValueError("Password must be at least 8 characters")
        return normalized


class TrojanInboundCreate(TrojanInboundBase):
    pass


class TrojanInboundUpdate(BaseModel):
    remark: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    password: Optional[str] = Field(default=None, min_length=8, max_length=255)
    network: Optional[str] = Field(default=None, min_length=1, max_length=32)
    cert_mode: Optional[Literal["self_signed", "custom_domain"]] = None
    sni: Optional[str] = Field(default=None, min_length=1, max_length=255)
    alpn: Optional[str] = Field(default=None, min_length=1, max_length=64)
    fingerprint: Optional[str] = Field(default=None, min_length=1, max_length=32)
    transport_settings: Optional[dict[str, Any]] = None
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("remark", "network", "cert_mode", "sni", "alpn", "fingerprint")
    @classmethod
    def normalize_required_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("password")
    @classmethod
    def normalize_optional_password(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if len(normalized) < 8:
            raise ValueError("Password must be at least 8 characters")
        return normalized


class TrojanInboundResponse(TrojanInboundBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
