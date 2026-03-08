# Atlas — Pydantic schemas for VPN client
# Phase 2: OpenVPN client management

from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime
from typing import Optional
from backend.models.vpn_client import VPNProtocol, VPNClientStatus


class VPNClientBase(BaseModel):
    """Base schema for VPN client"""
    name: str = Field(..., min_length=3, max_length=100, description="Unique client name")
    email: Optional[EmailStr] = Field(None, description="Client email address")
    description: Optional[str] = Field(None, max_length=500, description="Client description")
    protocol: VPNProtocol = Field(default=VPNProtocol.OPENVPN, description="VPN protocol")
    max_connections: int = Field(default=1, ge=1, le=10, description="Max concurrent connections")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate client name format"""
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Name must be alphanumeric (-, _ allowed)")
        return v.lower()


class VPNClientCreate(VPNClientBase):
    """Schema for creating new VPN client"""
    server_address: Optional[str] = Field(None, description="Server IP/domain for config generation")
    server_port: int = Field(default=1194, ge=1, le=65535, description="OpenVPN server port")
    protocol_type: str = Field(default="udp", description="Connection protocol (udp/tcp)")
    
    @validator('protocol_type')
    def validate_protocol_type(cls, v):
        if v not in ['udp', 'tcp']:
            raise ValueError("Protocol type must be 'udp' or 'tcp'")
        return v


class VPNClientUpdate(BaseModel):
    """Schema for updating VPN client"""
    email: Optional[EmailStr] = None
    description: Optional[str] = Field(None, max_length=500)
    is_enabled: Optional[bool] = None
    max_connections: Optional[int] = Field(None, ge=1, le=10)


class VPNClientResponse(VPNClientBase):
    """Schema for VPN client response"""
    id: int
    status: VPNClientStatus
    certificate_cn: Optional[str] = None
    certificate_issued_at: Optional[datetime] = None
    certificate_expires_at: Optional[datetime] = None
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    last_connected_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    revoked_at: Optional[datetime] = None
    is_enabled: bool
    
    class Config:
        from_attributes = True


class VPNClientDetailResponse(VPNClientResponse):
    """Detailed schema with additional information"""
    revoked_reason: Optional[str] = None
    created_by: Optional[int] = None
    
    @property
    def is_active(self) -> bool:
        return self.status == VPNClientStatus.ACTIVE and self.is_enabled
    
    @property
    def total_bytes(self) -> int:
        return self.total_bytes_sent + self.total_bytes_received


class VPNClientConfigResponse(BaseModel):
    """Schema for client configuration response"""
    client_name: str
    config_content: str
    qr_code: Optional[str] = Field(None, description="Base64 encoded QR code image")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class VPNClientRevokeRequest(BaseModel):
    """Schema for revoking client certificate"""
    reason: Optional[str] = Field(None, max_length=500, description="Reason for revocation")


class VPNServiceStatusResponse(BaseModel):
    """Schema for OpenVPN service status"""
    service_name: str
    is_active: bool
    is_enabled: bool
    is_mock: bool = Field(default=False, description="Whether running in mock/dev mode")
    status_output: Optional[str] = None


class VPNServiceControlRequest(BaseModel):
    """Schema for service control actions"""
    action: str = Field(..., description="Service action: start, stop, restart, enable, disable")
    
    @validator('action')
    def validate_action(cls, v):
        allowed = ['start', 'stop', 'restart', 'enable', 'disable']
        if v not in allowed:
            raise ValueError(f"Action must be one of: {', '.join(allowed)}")
        return v


class VPNClientListResponse(BaseModel):
    """Schema for paginated client list"""
    total: int
    clients: list[VPNClientResponse]
    page: int = 1
    page_size: int = 50
