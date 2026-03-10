from datetime import datetime
import ipaddress
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


class GeneralSettingsBase(BaseModel):
    server_address: Optional[str] = Field(default=None, max_length=255)
    public_ipv4_address: Optional[str] = Field(default=None, max_length=64)
    public_ipv6_address: Optional[str] = Field(default=None, max_length=64)
    global_ipv6_support: bool = Field(True)
    wan_interface: str = Field("eth0", min_length=1, max_length=32)
    server_system_dns_primary: str = Field("1.1.1.1", min_length=3, max_length=64)
    server_system_dns_secondary: str = Field("8.8.8.8", min_length=3, max_length=64)

    admin_allowed_ips: str = Field("0.0.0.0/0", min_length=1)
    login_max_failed_attempts: int = Field(5, ge=1, le=20)
    login_block_duration_minutes: int = Field(15, ge=1, le=1440)

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

    is_tunnel_enabled: bool = Field(False)
    tunnel_mode: Literal["direct", "dnstt", "gost", "xray"] = Field("direct")
    foreign_server_ip: Optional[str] = Field(default=None, max_length=255)
    foreign_server_port: int = Field(22, ge=1, le=65535)
    foreign_ssh_user: str = Field("root", min_length=1, max_length=64)
    foreign_ssh_password: Optional[str] = Field(default=None, max_length=255)
    tunnel_architecture: Literal["relay", "standalone"] = Field("standalone")
    dnstt_domain: Optional[str] = Field(default=None, max_length=1024)
    dnstt_active_domain: Optional[str] = Field(default=None, max_length=255)
    dnstt_dns_resolver: str = Field("8.8.8.8", min_length=3, max_length=1024)
    dnstt_resolver_strategy: Literal["failover", "least-latency", "round-robin"] = Field("failover")
    dnstt_duplication_mode: Literal[1, 2, 3] = Field(1)
    dnstt_mtu_mode: Literal["preset", "adaptive"] = Field("preset")
    dnstt_mtu: int = Field(1232, ge=500, le=1400)
    dnstt_mtu_upload_min: int = Field(472, ge=256, le=1400)
    dnstt_mtu_upload_max: int = Field(1204, ge=256, le=1400)
    dnstt_mtu_download_min: int = Field(472, ge=256, le=1400)
    dnstt_mtu_download_max: int = Field(1204, ge=256, le=1400)
    dnstt_adaptive_per_resolver: bool = Field(True)
    dnstt_transport_probe_workers: int = Field(2, ge=1, le=8)
    dnstt_transport_retry_count: int = Field(2, ge=0, le=10)
    dnstt_transport_probe_timeout_ms: int = Field(2000, ge=500, le=15000)
    dnstt_transport_switch_threshold_percent: int = Field(20, ge=5, le=80)
    dnstt_telemetry: Optional[Dict[str, Any]] = Field(default=None)
    dnstt_telemetry_history: Optional[List[Dict[str, Any]]] = Field(default=None)
    dnstt_pubkey: Optional[str] = Field(default=None)
    dnstt_privkey: Optional[str] = Field(default=None)

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

    @field_validator("wan_interface", "admin_allowed_ips", "system_timezone", "ntp_server", "foreign_ssh_user")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value cannot be empty")
        return normalized

    @field_validator("server_system_dns_primary", "server_system_dns_secondary")
    @classmethod
    def validate_server_system_dns(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("DNS value cannot be empty")
        try:
            ipaddress.ip_address(normalized)
        except ValueError as exc:
            raise ValueError("Server DNS must be a valid IPv4 or IPv6 address") from exc
        return normalized

    @field_validator("dnstt_dns_resolver")
    @classmethod
    def validate_dnstt_dns_resolver(cls, value: str) -> str:
        normalized_entries: list[str] = []
        for raw_entry in value.split(","):
            entry = raw_entry.strip()
            if not entry:
                continue

            if entry.startswith(("http://", "https://")):
                parsed = urlparse(entry)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    raise ValueError("DNSTT DNS endpoint URL must include a valid scheme and host")
            else:
                try:
                    ipaddress.ip_address(entry)
                except ValueError as exc:
                    raise ValueError("DNSTT DNS endpoint must be a DoH URL or IP address") from exc

            normalized_entries.append(entry)

        if not normalized_entries:
            raise ValueError("At least one DNSTT DNS endpoint is required")

        return ", ".join(normalized_entries)

    @field_validator("dnstt_resolver_strategy")
    @classmethod
    def validate_dnstt_resolver_strategy(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("dnstt_duplication_mode")
    @classmethod
    def validate_dnstt_duplication_mode(cls, value: int) -> int:
        return int(value)

    @field_validator("dnstt_mtu")
    @classmethod
    def validate_dnstt_mtu(cls, value: int) -> int:
        return int(value)

    @field_validator("dnstt_mtu_mode")
    @classmethod
    def validate_dnstt_mtu_mode(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator(
        "dnstt_mtu_upload_min",
        "dnstt_mtu_upload_max",
        "dnstt_mtu_download_min",
        "dnstt_mtu_download_max",
        "dnstt_transport_probe_workers",
        "dnstt_transport_retry_count",
        "dnstt_transport_probe_timeout_ms",
        "dnstt_transport_switch_threshold_percent",
    )
    @classmethod
    def validate_dnstt_int_knobs(cls, value: int) -> int:
        return int(value)

    @field_validator("dnstt_domain")
    @classmethod
    def validate_dnstt_domain(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        normalized_entries: list[str] = []
        seen = set()
        for raw_entry in value.split(","):
            entry = raw_entry.strip().rstrip(".")
            if not entry:
                continue

            labels = entry.split(".")
            if len(labels) < 2:
                raise ValueError("Each DNSTT tunnel domain must contain at least one dot")

            for label in labels:
                if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
                    raise ValueError("DNSTT tunnel domain labels must be 1-63 chars and cannot start/end with hyphen")
                if not all(char.isalnum() or char == "-" for char in label):
                    raise ValueError("DNSTT tunnel domains may only contain letters, digits, dots, and hyphens")

            normalized_entry = entry.lower()
            if normalized_entry in seen:
                continue
            seen.add(normalized_entry)
            normalized_entries.append(entry)

        if not normalized_entries:
            return None

        return ", ".join(normalized_entries)

    @field_validator("dnstt_active_domain")
    @classmethod
    def validate_dnstt_active_domain(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().rstrip(".")
        return normalized or None

    @model_validator(mode="after")
    def validate_dnstt_mtu_ranges(self):
        if self.dnstt_mtu_upload_min > self.dnstt_mtu_upload_max:
            raise ValueError("DNSTT upload MTU min cannot be greater than max")
        if self.dnstt_mtu_download_min > self.dnstt_mtu_download_max:
            raise ValueError("DNSTT download MTU min cannot be greater than max")
        return self

    @field_validator("foreign_server_ip")
    @classmethod
    def validate_foreign_server_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        try:
            ipaddress.ip_address(normalized)
        except ValueError as exc:
            raise ValueError("Foreign server IP must be a valid IPv4 or IPv6 address") from exc
        return normalized

    @field_validator(
        "server_address",
        "panel_domain",
        "subscription_domain",
        "custom_ssl_certificate",
        "custom_ssl_private_key",
        "letsencrypt_email",
        "foreign_ssh_password",
        "dnstt_pubkey",
        "dnstt_privkey",
    )
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

    @model_validator(mode="after")
    def validate_dnstt_active_domain_selection(self):
        if not self.dnstt_domain:
            self.dnstt_active_domain = None
            return self

        domains = [item.strip().rstrip(".") for item in self.dnstt_domain.split(",") if item and item.strip()]
        if not domains:
            self.dnstt_active_domain = None
            return self

        if self.dnstt_active_domain:
            active = self.dnstt_active_domain.strip().rstrip(".")
            for candidate in domains:
                if candidate.lower() == active.lower():
                    self.dnstt_active_domain = candidate
                    return self

        self.dnstt_active_domain = domains[0]
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


class SSLCertificateIssueRequest(BaseModel):
    domains: List[str] = Field(default_factory=list)
