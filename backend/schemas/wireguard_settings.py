import ipaddress
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class WireGuardSettingsBase(BaseModel):
    interface_name: str = Field("wg0", min_length=1, max_length=32)
    listen_port: int = Field(51820, ge=1, le=65535)
    address_range: str = Field("10.9.0.0/24", min_length=9, max_length=64)

    @field_validator("interface_name")
    @classmethod
    def validate_interface_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Interface name cannot be empty")
        if any(char.isspace() for char in normalized):
            raise ValueError("Interface name cannot contain spaces")
        return normalized

    @field_validator("address_range")
    @classmethod
    def validate_address_range(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Address range cannot be empty")
        try:
            network = ipaddress.ip_network(normalized, strict=False)
        except ValueError as exc:
            raise ValueError("Address range must be a valid CIDR network (for example 10.9.0.0/24)") from exc
        if network.version != 4:
            raise ValueError("Address range must be an IPv4 CIDR network")
        return f"{network.network_address}/{network.prefixlen}"


class WireGuardSettingsUpdate(WireGuardSettingsBase):
    pass


class WireGuardSettingsResponse(WireGuardSettingsBase):
    id: int
    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True
