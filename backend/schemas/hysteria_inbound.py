from datetime import datetime
import re
import secrets
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class HysteriaInboundBase(BaseModel):
    remark: str = Field(..., min_length=1, max_length=255)
    port: str = Field(default="40000-50000", min_length=1, max_length=64)
    up_mbps: Optional[int] = Field(default=None, ge=0)
    down_mbps: Optional[int] = Field(default=None, ge=0)
    obfs_password: Optional[str] = Field(default_factory=lambda: secrets.token_urlsafe(18), max_length=255)
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

    @field_validator("port")
    @classmethod
    def validate_port_hopping_format(cls, value: str) -> str:
        normalized = value.strip()
        single_port_pattern = r"^\d{1,5}$"
        range_port_pattern = r"^(\d{1,5})-(\d{1,5})$"
        if re.fullmatch(single_port_pattern, normalized):
            port = int(normalized)
            if 1 <= port <= 65535:
                return normalized
            raise ValueError("Port must be between 1 and 65535")
        match = re.fullmatch(range_port_pattern, normalized)
        if not match:
            raise ValueError("Port must be a single port (443) or range (40000-50000)")
        start = int(match.group(1))
        end = int(match.group(2))
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError("Port range must be between 1 and 65535 and start <= end")
        return normalized

    @field_validator("obfs_password", "sni", "cert_pem", "key_pem")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("obfs_password")
    @classmethod
    def ensure_obfs_password(cls, value: Optional[str]) -> str:
        normalized = (value or "").strip()
        return normalized or secrets.token_urlsafe(18)


class HysteriaInboundCreate(HysteriaInboundBase):
    pass


class HysteriaInboundUpdate(BaseModel):
    remark: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[str] = Field(default=None, min_length=1, max_length=64)
    up_mbps: Optional[int] = Field(default=None, ge=0)
    down_mbps: Optional[int] = Field(default=None, ge=0)
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

    @field_validator("port")
    @classmethod
    def validate_optional_port_hopping_format(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        single_port_pattern = r"^\d{1,5}$"
        range_port_pattern = r"^(\d{1,5})-(\d{1,5})$"
        if re.fullmatch(single_port_pattern, normalized):
            port = int(normalized)
            if 1 <= port <= 65535:
                return normalized
            raise ValueError("Port must be between 1 and 65535")
        match = re.fullmatch(range_port_pattern, normalized)
        if not match:
            raise ValueError("Port must be a single port (443) or range (40000-50000)")
        start = int(match.group(1))
        end = int(match.group(2))
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError("Port range must be between 1 and 65535 and start <= end")
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
