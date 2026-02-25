from datetime import datetime
import ipaddress
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class GeneralSettingsBase(BaseModel):
    public_ipv4_address: Optional[str] = Field(default=None, max_length=64)
    public_ipv6_address: Optional[str] = Field(default=None, max_length=64)
    global_ipv6_support: bool = Field(True)
    wan_interface: str = Field("eth0", min_length=1, max_length=32)

    admin_allowed_ips: str = Field("0.0.0.0/0", min_length=1)

    panel_domain: Optional[str] = Field(default=None, max_length=255)
    panel_https_port: int = Field(2053)
    subscription_domain: Optional[str] = Field(default=None, max_length=255)
    subscription_https_port: int = Field(2083)
    ssl_mode: Literal["none", "auto", "custom"] = Field("none")
    letsencrypt_email: Optional[str] = Field(default=None, max_length=255)
    force_https: bool = Field(False)
    auto_renew_ssl: bool = Field(True)
    custom_ssl_certificate: Optional[str] = Field(default=None)
    custom_ssl_private_key: Optional[str] = Field(default=None)

    system_timezone: str = Field("UTC", min_length=1, max_length=64)
    ntp_server: str = Field("pool.ntp.org", min_length=1, max_length=255)

    @field_validator("public_ipv4_address")
    @classmethod
    def validate_public_ipv4_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        try:
            ipaddress.IPv4Address(normalized)
        except ValueError as exc:
            raise ValueError("Public IPv4 address must be a valid IPv4 address") from exc
        return normalized

    @field_validator("public_ipv6_address")
    @classmethod
    def validate_public_ipv6_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        try:
            ipaddress.IPv6Address(normalized)
        except ValueError as exc:
            raise ValueError("Public IPv6 address must be a valid IPv6 address") from exc
        return normalized

    @field_validator("wan_interface", "admin_allowed_ips", "system_timezone", "ntp_server")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("panel_domain", "subscription_domain", "custom_ssl_certificate", "custom_ssl_private_key", "letsencrypt_email")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("panel_https_port")
    @classmethod
    def validate_panel_https_port(cls, value: int) -> int:
        allowed = {2053, 2083, 2087, 2096, 8443}
        if value not in allowed:
            raise ValueError("Panel HTTPS port must be one of: 2053, 2083, 2087, 2096, 8443")
        return value

    @field_validator("subscription_https_port")
    @classmethod
    def validate_subscription_https_port(cls, value: int) -> int:
        allowed = {2053, 2083, 2087, 2096, 8443}
        if value not in allowed:
            raise ValueError("Subscription HTTPS port must be one of: 2053, 2083, 2087, 2096, 8443")
        return value

    @model_validator(mode="after")
    def validate_ssl_settings(self):
        if self.ssl_mode == "auto" and not self.letsencrypt_email:
            raise ValueError("Let's Encrypt email is required when SSL mode is auto")

        if self.ssl_mode == "custom":
            if not self.custom_ssl_certificate or not self.custom_ssl_private_key:
                raise ValueError("Custom SSL certificate and private key are required when SSL mode is custom")

        if self.ssl_mode != "auto":
            self.letsencrypt_email = None

        if self.ssl_mode != "custom":
            self.custom_ssl_certificate = None
            self.custom_ssl_private_key = None

        return self


class GeneralSettingsUpdate(GeneralSettingsBase):
    pass


class GeneralSettingsResponse(GeneralSettingsBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class SSLCertificateIssueResponse(BaseModel):
    success: bool
    message: str
    is_mock: bool = False
    command: Optional[str] = None
