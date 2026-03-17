from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


ShadowsocksMethod = Literal[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
]


class ShadowsocksInboundBase(BaseModel):
    remark: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=8388, ge=1, le=65535)
    method: ShadowsocksMethod = Field(default="2022-blake3-aes-128-gcm")
    password: str = Field(..., min_length=1, max_length=255)
    is_active: bool = Field(True)

    @field_validator("remark", "password")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized


class ShadowsocksInboundCreate(ShadowsocksInboundBase):
    pass


class ShadowsocksInboundUpdate(BaseModel):
    remark: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    method: Optional[ShadowsocksMethod] = None
    password: Optional[str] = Field(default=None, min_length=1, max_length=255)
    is_active: Optional[bool] = None

    @field_validator("remark", "password")
    @classmethod
    def normalize_required_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized


class ShadowsocksInboundResponse(ShadowsocksInboundBase):
    id: int

    class Config:
        from_attributes = True
