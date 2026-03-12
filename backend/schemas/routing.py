from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class RoutingRuleBase(BaseModel):
    rule_name: str = Field(..., min_length=1, max_length=64)
    ingress_iface: str = Field(..., min_length=1, max_length=32)
    fwmark: int = Field(..., ge=1, le=2147483647)
    proxy_port: int = Field(..., ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = Field("tcp")
    status: Literal["active", "inactive"] = Field("active")

    @field_validator("rule_name", "ingress_iface")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized


class RoutingRuleCreate(RoutingRuleBase):
    pass


class RoutingRuleUpdate(BaseModel):
    rule_name: str = Field(..., min_length=1, max_length=64)
    ingress_iface: str = Field(..., min_length=1, max_length=32)
    fwmark: int = Field(..., ge=1, le=2147483647)
    proxy_port: int = Field(..., ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = Field("tcp")
    status: Literal["active", "inactive"] = Field("active")

    @field_validator("rule_name", "ingress_iface")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized


class RoutingRuleResponse(RoutingRuleBase):
    id: int
    table_id: int
    table_name: str
    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True
