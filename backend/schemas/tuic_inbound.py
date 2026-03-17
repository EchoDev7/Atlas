from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class TuicInboundBase(BaseModel):
    remark: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    congestion_control: Literal["bbr", "cubic", "new_reno"] = Field(default="bbr")
    udp_relay_mode: Literal["native", "quic"] = Field(default="native")
    zero_rtt_handshake: bool = Field(False)
    alpn: str = Field(default="h3", min_length=1, max_length=64)
    cert_mode: Literal["self_signed", "custom_domain"] = Field(default="self_signed")
    sni: Optional[str] = Field(default=None, max_length=255)
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None
    is_active: bool = Field(True)

    @field_validator("remark", "alpn")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("sni", "cert_pem", "key_pem")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class TuicInboundCreate(TuicInboundBase):
    pass


class TuicInboundUpdate(BaseModel):
    remark: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    congestion_control: Optional[Literal["bbr", "cubic", "new_reno"]] = None
    udp_relay_mode: Optional[Literal["native", "quic"]] = None
    zero_rtt_handshake: Optional[bool] = None
    alpn: Optional[str] = Field(default=None, min_length=1, max_length=64)
    cert_mode: Optional[Literal["self_signed", "custom_domain"]] = None
    sni: Optional[str] = Field(default=None, max_length=255)
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("remark", "alpn")
    @classmethod
    def normalize_required_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("sni", "cert_pem", "key_pem")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class TuicInboundResponse(TuicInboundBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
