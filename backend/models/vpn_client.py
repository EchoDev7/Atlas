# Atlas — VPN client/peer ORM model
# Phase 2: OpenVPN client management

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Enum as SQLEnum
from datetime import datetime
from backend.database import Base
import enum


class VPNProtocol(str, enum.Enum):
    """VPN protocol types"""
    OPENVPN = "openvpn"
    WIREGUARD = "wireguard"
    SINGBOX = "singbox"


class VPNClientStatus(str, enum.Enum):
    """VPN client status"""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class VPNClient(Base):
    """
    VPN Client model for managing VPN connections across multiple protocols.
    Each client represents a unique user/device that can connect to the VPN.
    """
    __tablename__ = "vpn_clients"
    
    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=True)
    
    # Protocol and status
    protocol = Column(SQLEnum(VPNProtocol), nullable=False, default=VPNProtocol.OPENVPN)
    status = Column(SQLEnum(VPNClientStatus), nullable=False, default=VPNClientStatus.ACTIVE)
    
    # Certificate information (for OpenVPN)
    certificate_cn = Column(String(255), nullable=True)  # Common Name
    certificate_serial = Column(String(100), nullable=True)  # Serial number
    certificate_issued_at = Column(DateTime, nullable=True)
    certificate_expires_at = Column(DateTime, nullable=True)
    
    # WireGuard specific (for future Phase 3)
    wireguard_public_key = Column(String(255), nullable=True)
    wireguard_private_key = Column(Text, nullable=True)  # Encrypted
    wireguard_preshared_key = Column(Text, nullable=True)  # Encrypted
    wireguard_allowed_ips = Column(String(255), nullable=True)
    
    # Sing-box specific (for future Phase 4)
    singbox_uuid = Column(String(100), nullable=True)
    singbox_config = Column(Text, nullable=True)  # JSON config
    
    # Traffic and usage statistics
    total_bytes_sent = Column(Integer, default=0)
    total_bytes_received = Column(Integer, default=0)
    last_connected_at = Column(DateTime, nullable=True)
    last_disconnected_at = Column(DateTime, nullable=True)
    
    # Metadata
    description = Column(Text, nullable=True)
    created_by = Column(Integer, nullable=True)  # Admin user ID
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(Text, nullable=True)
    
    # Configuration
    is_enabled = Column(Boolean, default=True)
    max_connections = Column(Integer, default=1)  # Concurrent connections allowed
    
    def __repr__(self):
        return f"<VPNClient(name={self.name}, protocol={self.protocol}, status={self.status})>"
    
    @property
    def is_active(self) -> bool:
        """Check if client is active and can connect"""
        return self.status == VPNClientStatus.ACTIVE and self.is_enabled
    
    @property
    def total_bytes(self) -> int:
        """Total bytes transferred"""
        return self.total_bytes_sent + self.total_bytes_received
