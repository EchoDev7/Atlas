# Atlas — VPN User and Config Pydantic schemas
# Phase 2 Enhancements: Multi-protocol architecture

from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime


# ============================================================================
# VPN User Schemas
# ============================================================================

class VPNUserBase(BaseModel):
    """Base schema for VPN User"""
    username: str = Field(..., min_length=3, max_length=100, description="Username for VPN authentication")
    description: Optional[str] = Field(None, description="Optional description")
    data_limit_gb: Optional[float] = Field(None, ge=0, description="Data limit in GB (null = unlimited)")
    expiry_date: Optional[datetime] = Field(None, description="Expiration date (null = no expiry)")
    max_devices: int = Field(1, ge=1, le=100, description="Maximum concurrent devices")


class VPNUserCreate(BaseModel):
    """Schema for creating a new VPN user"""
    username: Optional[str] = Field(None, min_length=3, max_length=100, description="Username (auto-generated if not provided)")
    password: Optional[str] = Field(None, min_length=8, description="Password (auto-generated if not provided)")
    description: Optional[str] = Field(None, description="Optional description")
    data_limit_gb: Optional[float] = Field(None, ge=0, description="Data limit in GB (null = unlimited)")
    expiry_date: Optional[datetime] = Field(None, description="Expiration date (null = no expiry)")
    max_devices: int = Field(1, ge=1, le=100, description="Maximum concurrent devices")
    
    # OpenVPN config creation
    create_openvpn: bool = Field(True, description="Create OpenVPN config for this user")
    server_address: Optional[str] = Field(None, description="OpenVPN server address")
    server_port: int = Field(1194, description="OpenVPN server port")
    protocol_type: str = Field("udp", description="OpenVPN protocol (udp/tcp)")


class VPNUserUpdate(BaseModel):
    """Schema for updating VPN user"""
    description: Optional[str] = None
    notes: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=8)
    data_limit_gb: Optional[float] = Field(None, ge=0)
    add_data_gb: Optional[float] = Field(None, ge=0)
    expiry_date: Optional[datetime] = None
    extend_days: Optional[int] = Field(None, ge=1, le=3650)
    max_devices: Optional[int] = Field(None, ge=1, le=100)
    is_enabled: Optional[bool] = None


class VPNUserResponse(BaseModel):
    """Schema for VPN user response"""
    id: int
    username: str
    max_devices: int
    data_limit_gb: Optional[float]
    expiry_date: Optional[datetime]
    total_bytes_sent: int
    total_bytes_received: int
    total_gb_used: float
    data_usage_percentage: float
    last_connected_at: Optional[datetime]
    is_enabled: bool
    is_expired: bool
    is_data_limit_exceeded: bool
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
