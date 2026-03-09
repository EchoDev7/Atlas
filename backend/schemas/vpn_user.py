# Atlas — VPN User and Config Pydantic schemas
# Phase 2 Enhancements: Multi-protocol architecture

from pydantic import BaseModel, Field, model_validator, field_validator
from typing import Optional, List
from datetime import datetime


_BYTES_PER_GB = 1024 ** 3


# ============================================================================
# VPN User Schemas
# ============================================================================

class VPNUserBase(BaseModel):
    """Base schema for VPN User"""
    username: str = Field(..., min_length=3, max_length=100, description="Username for VPN authentication")
    description: Optional[str] = Field(None, description="Optional description")
    data_limit_gb: Optional[float] = Field(None, ge=0, description="Data limit in GB (null = unlimited)")
    traffic_limit_bytes: Optional[int] = Field(None, ge=0, description="Traffic limit in bytes (null = unlimited)")
    traffic_used_bytes: int = Field(0, ge=0, description="Already consumed traffic in bytes")
    expiry_date: Optional[datetime] = Field(None, description="Expiration date (null = no expiry)")
    access_start_at: Optional[datetime] = Field(None, description="Account validity start timestamp")
    access_expires_at: Optional[datetime] = Field(None, description="Account validity end timestamp")
    max_devices: int = Field(1, ge=1, le=100, description="Maximum concurrent devices")
    max_concurrent_connections: Optional[int] = Field(None, ge=1, le=100, description="Maximum simultaneous connections")


class VPNUserCreate(BaseModel):
    """Schema for creating a new VPN user"""
    username: Optional[str] = Field(None, min_length=3, max_length=100, description="Username (auto-generated if not provided)")
    password: Optional[str] = Field(None, min_length=8, description="Password (auto-generated if not provided)")
    description: Optional[str] = Field(None, description="Optional description")
    data_limit_gb: Optional[float] = Field(None, ge=0, description="Data limit in GB (null = unlimited)")
    traffic_limit_bytes: Optional[int] = Field(None, ge=0, description="Traffic limit in bytes (null = unlimited)")
    traffic_used_bytes: int = Field(0, ge=0, description="Already consumed traffic in bytes")
    expiry_date: Optional[datetime] = Field(None, description="Expiration date (null = no expiry)")
    access_start_at: Optional[datetime] = Field(None, description="Account validity start timestamp")
    access_expires_at: Optional[datetime] = Field(None, description="Account validity end timestamp")
    max_devices: int = Field(1, ge=1, le=100, description="Maximum concurrent devices")
    max_concurrent_connections: Optional[int] = Field(None, ge=1, le=100, description="Maximum simultaneous connections")
    
    # Protocol generation toggles
    enable_openvpn: Optional[bool] = Field(None, description="Enable OpenVPN artifact generation")
    enable_wireguard: Optional[bool] = Field(None, description="Enable WireGuard artifact generation")
    # Backward-compatible aliases (deprecated)
    create_openvpn: Optional[bool] = Field(None, description="Deprecated alias for enable_openvpn")
    create_wireguard: Optional[bool] = Field(None, description="Deprecated alias for enable_wireguard")
    server_address: Optional[str] = Field(None, description="OpenVPN server address")
    server_port: int = Field(1194, description="OpenVPN server port")
    protocol_type: str = Field("udp", description="OpenVPN protocol (udp/tcp)")

    @model_validator(mode='before')
    @classmethod
    def normalize_accounting_inputs(cls, values):
        if not isinstance(values, dict):
            return values
        
        traffic_limit_bytes = values.get("traffic_limit_bytes")
        data_limit_gb = values.get("data_limit_gb")
        if traffic_limit_bytes is None and data_limit_gb is not None:
            values["traffic_limit_bytes"] = int(float(data_limit_gb) * _BYTES_PER_GB)

        access_expires_at = values.get("access_expires_at")
        expiry_date = values.get("expiry_date")
        if access_expires_at is None and expiry_date is not None:
            values["access_expires_at"] = expiry_date

        max_concurrent_connections = values.get("max_concurrent_connections")
        max_devices = values.get("max_devices")
        if max_concurrent_connections is None:
            values["max_concurrent_connections"] = max_devices or 1

        access_start_at = values.get("access_start_at")
        access_expires_at = values.get("access_expires_at")
        if access_start_at and access_expires_at and access_start_at >= access_expires_at:
            raise ValueError("access_start_at must be earlier than access_expires_at")

        enable_openvpn = values.get("enable_openvpn")
        enable_wireguard = values.get("enable_wireguard")

        if enable_openvpn is None:
            legacy_openvpn = values.get("create_openvpn")
            enable_openvpn = True if legacy_openvpn is None else bool(legacy_openvpn)
        else:
            enable_openvpn = bool(enable_openvpn)

        if enable_wireguard is None:
            legacy_wireguard = values.get("create_wireguard")
            enable_wireguard = True if legacy_wireguard is None else bool(legacy_wireguard)
        else:
            enable_wireguard = bool(enable_wireguard)

        if not enable_openvpn and not enable_wireguard:
            raise ValueError("At least one protocol must be enabled")

        values["enable_openvpn"] = enable_openvpn
        values["enable_wireguard"] = enable_wireguard

        return values


class VPNUserUpdate(BaseModel):
    """Schema for updating VPN user"""
    description: Optional[str] = None
    notes: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=8)
    data_limit_gb: Optional[float] = Field(None, ge=0)
    add_data_gb: Optional[float] = Field(None, ge=0)
    traffic_limit_bytes: Optional[int] = Field(None, ge=0)
    add_traffic_bytes: Optional[int] = Field(None, ge=0)
    traffic_used_bytes: Optional[int] = Field(None, ge=0)
    expiry_date: Optional[datetime] = None
    access_start_at: Optional[datetime] = None
    access_expires_at: Optional[datetime] = None
    extend_days: Optional[int] = Field(None, ge=1, le=3650)
    max_devices: Optional[int] = Field(None, ge=1, le=100)
    max_concurrent_connections: Optional[int] = Field(None, ge=1, le=100)
    current_connections: Optional[int] = Field(None, ge=0)
    is_enabled: Optional[bool] = None

    @model_validator(mode='before')
    @classmethod
    def normalize_update_inputs(cls, values):
        if not isinstance(values, dict):
            return values
        
        if values.get("traffic_limit_bytes") is None and values.get("data_limit_gb") is not None:
            values["traffic_limit_bytes"] = int(float(values["data_limit_gb"]) * _BYTES_PER_GB)

        if values.get("access_expires_at") is None and values.get("expiry_date") is not None:
            values["access_expires_at"] = values["expiry_date"]

        if values.get("max_concurrent_connections") is None and values.get("max_devices") is not None:
            values["max_concurrent_connections"] = values["max_devices"]

        access_start_at = values.get("access_start_at")
        access_expires_at = values.get("access_expires_at")
        if access_start_at and access_expires_at and access_start_at >= access_expires_at:
            raise ValueError("access_start_at must be earlier than access_expires_at")

        return values


class VPNUserResponse(BaseModel):
    """Schema for VPN user response"""
    id: int
    username: str
    max_devices: int
    max_concurrent_connections: int
    current_connections: int
    data_limit_gb: Optional[float]
    traffic_limit_bytes: Optional[int]
    traffic_used_bytes: int
    expiry_date: Optional[datetime]
    access_start_at: Optional[datetime]
    access_expires_at: Optional[datetime]
    total_bytes_sent: int
    total_bytes_received: int
    total_gb_used: float
    data_usage_percentage: float
    last_connected_at: Optional[datetime]
    is_enabled: bool
    is_expired: bool
    is_data_limit_exceeded: bool
    is_connection_limit_exceeded: bool
    is_active: bool
    is_online: bool = False  # Live connection status (mock for now)
    description: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]
    disabled_at: Optional[datetime]
    disabled_reason: Optional[str]
    
    # Protocol availability
    has_openvpn: bool
    has_wireguard: bool
    has_singbox: bool
    wg_public_key: Optional[str] = None
    wg_allocated_ip: Optional[str] = None
    
    class Config:
        from_attributes = True


class VPNUserDetailResponse(VPNUserResponse):
    """Detailed schema for VPN user with configs"""
    configs: List['VPNConfigResponse'] = []
    
    class Config:
        from_attributes = True


class VPNUserListResponse(BaseModel):
    """Schema for paginated user list"""
    users: List[VPNUserResponse]
    total: int
    page: int
    page_size: int


class VPNUserCredentials(BaseModel):
    """Schema for returning user credentials after creation"""
    username: str
    password: str
    message: str = "Save these credentials securely. Password cannot be retrieved later."


# ============================================================================
# VPN Config Schemas
# ============================================================================

class VPNConfigBase(BaseModel):
    """Base schema for VPN Config"""
    protocol: str = Field(..., description="Protocol type (openvpn, wireguard, singbox)")


class VPNConfigCreate(BaseModel):
    """Schema for creating a new VPN config"""
    user_id: int
    protocol: str = Field(..., description="Protocol type (openvpn, wireguard, singbox)")
    
    # OpenVPN specific
    server_address: Optional[str] = None
    server_port: int = 1194
    protocol_type: str = "udp"


class VPNConfigResponse(BaseModel):
    """Schema for VPN config response"""
    id: int
    user_id: int
    protocol: str
    is_active: bool
    revoked_at: Optional[datetime]
    revoked_reason: Optional[str]
    
    # OpenVPN specific
    certificate_cn: Optional[str]
    certificate_serial: Optional[str]
    certificate_issued_at: Optional[datetime]
    certificate_expires_at: Optional[datetime]
    
    # WireGuard specific
    wireguard_public_key: Optional[str]
    wireguard_allowed_ips: Optional[str]
    
    # Sing-box specific
    singbox_uuid: Optional[str]
    
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class VPNConfigFileResponse(BaseModel):
    """Schema for VPN config file response"""
    username: str
    protocol: str
    config_content: str
    qr_code: Optional[str] = None
    created_at: datetime


class VPNConfigRevokeRequest(BaseModel):
    """Schema for revoking a VPN config"""
    reason: Optional[str] = Field(None, description="Reason for revocation")


# ============================================================================
# Password Management
# ============================================================================

class PasswordChangeRequest(BaseModel):
    """Schema for changing user password"""
    new_password: str = Field(..., min_length=8, description="New password")


class PasswordResetRequest(BaseModel):
    """Schema for resetting user password (generates new random password)"""
    pass


class PasswordResetResponse(BaseModel):
    """Schema for password reset response"""
    username: str
    new_password: str
    message: str = "Password has been reset. Save it securely."


# Update forward references
VPNUserDetailResponse.model_rebuild()
