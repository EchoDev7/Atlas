from datetime import datetime
import ipaddress
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


_ALLOWED_PROTOCOLS = {"udp", "tcp", "udp6", "tcp6"}
_ALLOWED_DATA_CIPHERS = {"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
_ALLOWED_TLS_MODES = {"tls-crypt", "tls-auth", "none"}


class OpenVPNSettingsBase(BaseModel):
    port: int = Field(1194, ge=1, le=65535)
    protocol: str = Field("udp")
    device_type: str = Field("tun")
    topology: str = Field("subnet")
    ipv4_network: str = Field("10.8.0.0", min_length=7, max_length=32)
    ipv4_netmask: str = Field("255.255.255.0", min_length=7, max_length=32)
    ipv6_network: Optional[str] = Field(default=None, max_length=64)
    ipv6_prefix: Optional[int] = Field(default=None, ge=1, le=128)
    max_clients: int = Field(100, ge=1, le=100000)
    client_to_client: bool = Field(False)

    redirect_gateway: bool = Field(True)
    primary_dns: str = Field("8.8.8.8", min_length=3, max_length=64)
    secondary_dns: str = Field("1.1.1.1", min_length=3, max_length=64)
    block_outside_dns: bool = Field(False)
    push_custom_routes: Optional[str] = None

    data_ciphers: List[str] = Field(default_factory=lambda: ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"])
    tls_version_min: str = Field("1.2")
    tls_mode: str = Field("tls-crypt")
    auth_digest: str = Field("SHA256")
    reneg_sec: int = Field(3600, ge=0, le=86400)

    tun_mtu: int = Field(1500, ge=1200, le=9000)
    mssfix: int = Field(1450, ge=0, le=9000)
    sndbuf: int = Field(393216, ge=0, le=10485760)
    rcvbuf: int = Field(393216, ge=0, le=10485760)
    fast_io: bool = Field(False)
    explicit_exit_notify: int = Field(1, ge=0, le=10)

    keepalive_ping: int = Field(10, ge=1, le=3600)
    keepalive_timeout: int = Field(120, ge=1, le=7200)
    inactive_timeout: int = Field(300, ge=0, le=86400)
    management_port: int = Field(5555, ge=1, le=65535)
    verbosity: int = Field(3, ge=0, le=6)

    custom_directives: Optional[str] = None
    advanced_client_push: Optional[str] = None

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str) -> str:
        normalized = value.lower().strip()
        if normalized not in _ALLOWED_PROTOCOLS:
            raise ValueError("Protocol must be udp, tcp, udp6, or tcp6")
        return normalized

    @field_validator("device_type")
    @classmethod
    def validate_device_type(cls, value: str) -> str:
        normalized = value.lower().strip()
        if normalized not in {"tun", "tap"}:
            raise ValueError("Device type must be tun or tap")
        return normalized

    @field_validator("topology")
    @classmethod
    def validate_topology(cls, value: str) -> str:
        normalized = value.lower().strip()
        if normalized != "subnet":
            raise ValueError("Topology must be subnet")
        return normalized

    @field_validator("tls_version_min")
    @classmethod
    def validate_tls_version(cls, value: str) -> str:
        normalized = value.strip()
        if normalized not in {"1.2", "1.3"}:
            raise ValueError("TLS minimum version must be 1.2 or 1.3")
        return normalized

    @field_validator("tls_mode")
    @classmethod
    def validate_tls_mode(cls, value: str) -> str:
        normalized = value.lower().strip()
        if normalized not in _ALLOWED_TLS_MODES:
            raise ValueError("TLS mode must be tls-crypt, tls-auth, or none")
        return normalized

    @field_validator("auth_digest")
    @classmethod
    def validate_auth_digest(cls, value: str) -> str:
        normalized = value.upper().strip()
        if normalized not in {"SHA256", "SHA384", "SHA512"}:
            raise ValueError("Auth digest must be SHA256, SHA384, or SHA512")
        return normalized

    @field_validator("data_ciphers")
    @classmethod
    def validate_data_ciphers(cls, value: List[str]) -> List[str]:
        normalized = [cipher.upper().strip() for cipher in value if cipher and cipher.strip()]
        if not normalized:
            raise ValueError("At least one data cipher is required")
        invalid = [cipher for cipher in normalized if cipher not in _ALLOWED_DATA_CIPHERS]
        if invalid:
            raise ValueError(f"Unsupported data cipher(s): {', '.join(invalid)}")
        deduped: List[str] = []
        for cipher in normalized:
            if cipher not in deduped:
                deduped.append(cipher)
        return deduped

    @field_validator("ipv4_network")
    @classmethod
    def validate_ipv4_network(cls, value: str) -> str:
        normalized = value.strip()
        try:
            ipaddress.IPv4Address(normalized)
        except ValueError as exc:
            raise ValueError("IPv4 network must be a valid IPv4 address") from exc
        return normalized

    @field_validator("ipv4_netmask")
    @classmethod
    def validate_ipv4_netmask(cls, value: str) -> str:
        normalized = value.strip()
        try:
            ipaddress.IPv4Address(normalized)
        except ValueError as exc:
            raise ValueError("IPv4 netmask must be a valid IPv4 address") from exc
        return normalized

    @field_validator("ipv6_network")
    @classmethod
    def validate_ipv6_network(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        try:
            ipaddress.IPv6Address(normalized)
        except ValueError as exc:
            raise ValueError("IPv6 network must be a valid IPv6 address") from exc
        return normalized or None

    @model_validator(mode="after")
    def validate_ipv6_pair(self):
        if self.ipv6_network and self.ipv6_prefix is None:
            raise ValueError("IPv6 prefix is required when IPv6 network is set")
        if not self.ipv6_network and self.ipv6_prefix is not None:
            raise ValueError("IPv6 network is required when IPv6 prefix is set")
        return self

    @field_validator("primary_dns", "secondary_dns")
    @classmethod
    def normalize_dns(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("DNS value cannot be empty")
        return normalized

    @field_validator("push_custom_routes", "custom_directives", "advanced_client_push")
    @classmethod
    def normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class OpenVPNSettingsUpdate(OpenVPNSettingsBase):
    pass


class OpenVPNSettingsResponse(OpenVPNSettingsBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
