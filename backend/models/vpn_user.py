# Atlas — VPN User and Config ORM models
# Phase 2 Enhancements: Multi-protocol architecture

from sqlalchemy import Column, Integer, BigInteger, String, DateTime, Boolean, Text, Float, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base
import secrets
import string


class VPNUser(Base):
    """
    VPN User model - represents a single user who can have multiple protocol configs.
    This is the parent entity for all VPN configurations (OpenVPN, WireGuard, Sing-box).
    """
    __tablename__ = "vpn_users"
    
    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)  # Hashed password for auth-user-pass
    wg_private_key = Column(String(128), nullable=True)
    wg_public_key = Column(String(128), nullable=True)
    wg_allocated_ip = Column(String(64), nullable=True)
    enable_openvpn = Column(Boolean, nullable=True, default=True)
    
    # Limits and restrictions
    data_limit_gb = Column(Float, nullable=True)  # Data limit in GB (None = unlimited)
    expiry_date = Column(DateTime, nullable=True)  # Expiration date (None = no expiry)
    max_devices = Column(Integer, nullable=False, default=1)  # Concurrent device limit
    traffic_limit_bytes = Column(BigInteger, nullable=True)  # Explicit traffic cap in bytes
    traffic_used_bytes = Column(BigInteger, nullable=False, default=0)  # Explicit consumed traffic in bytes
    access_start_at = Column(DateTime, nullable=True)  # Access validity start time (None = immediate)
    access_expires_at = Column(DateTime, nullable=True)  # Access validity end time (None = no expiry)
    max_concurrent_connections = Column(Integer, nullable=False, default=1)
    current_connections = Column(Integer, nullable=False, default=0)
    
    # Usage tracking
    total_bytes_sent = Column(Integer, default=0)
    total_bytes_received = Column(Integer, default=0)
    last_connected_at = Column(DateTime, nullable=True)
    last_disconnected_at = Column(DateTime, nullable=True)
    
    # Status
    is_enabled = Column(Boolean, default=True)
    is_expired = Column(Boolean, default=False)
    is_data_limit_exceeded = Column(Boolean, default=False)
    is_connection_limit_exceeded = Column(Boolean, default=False)
    
    # Metadata
    description = Column(Text, nullable=True)
    created_by = Column(Integer, nullable=True)  # Admin user ID
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    disabled_at = Column(DateTime, nullable=True)
    disabled_reason = Column(Text, nullable=True)
    
    # Relationships
    configs = relationship("VPNConfig", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<VPNUser(username={self.username}, enabled={self.is_enabled})>"
    
    @property
    def is_active(self) -> bool:
        """Check if user is active and can connect"""
        if self.access_start_at and datetime.utcnow() < self.access_start_at:
            return False
        return (
            self.is_enabled and 
            not self.is_expired and 
            not self.is_data_limit_exceeded and
            not self.is_connection_limit_exceeded
        )

    @property
    def effective_max_concurrent_connections(self) -> int:
        """Canonical concurrent connection limit with legacy fallback."""
        return max(1, int(self.max_concurrent_connections or self.max_devices or 1))

    @property
    def effective_access_expires_at(self):
        """Canonical access expiry with legacy fallback."""
        return self.access_expires_at or self.expiry_date

    @property
    def effective_traffic_limit_bytes(self):
        """Canonical traffic limit in bytes with legacy fallback from GB."""
        if self.traffic_limit_bytes is not None:
            return int(self.traffic_limit_bytes)
        if self.data_limit_gb is None:
            return None
        return int(self.data_limit_gb * (1024 ** 3))
    
    @property
    def total_bytes(self) -> int:
        """Total bytes transferred"""
        transport_bytes = int(self.total_bytes_sent or 0) + int(self.total_bytes_received or 0)
        accounting_bytes = int(self.traffic_used_bytes or 0)
        return max(transport_bytes, accounting_bytes)
    
    @property
    def total_gb_used(self) -> float:
        """Total GB used"""
        return self.total_bytes / (1024 ** 3) if self.total_bytes > 0 else 0.0
    
    @property
    def data_usage_percentage(self) -> float:
        """Percentage of data limit used (0-100)"""
        limit_bytes = self.effective_traffic_limit_bytes
        if limit_bytes in {None, 0}:
            return 0.0
        return min(100.0, (self.total_bytes / limit_bytes) * 100)

    def refresh_limit_flags(self, now: datetime) -> None:
        """Recompute all limit flags from current counters and timestamps."""
        expiry_point = self.effective_access_expires_at
        if expiry_point and now:
            # Ensure both are timezone-naive for comparison
            now_naive = now.replace(tzinfo=None) if now.tzinfo else now
            expiry_naive = expiry_point.replace(tzinfo=None) if expiry_point.tzinfo else expiry_point
            self.is_expired = now_naive > expiry_naive
        else:
            self.is_expired = False

        limit_bytes = self.effective_traffic_limit_bytes
        self.is_data_limit_exceeded = bool(limit_bytes is not None and self.total_bytes >= limit_bytes)

        self.is_connection_limit_exceeded = bool(
            int(self.current_connections or 0) > self.effective_max_concurrent_connections
        )

    @property
    def notes(self) -> str:
        """Alias for enterprise Notes field (backed by description)."""
        return self.description

    @notes.setter
    def notes(self, value: str) -> None:
        self.description = value
    
    @property
    def has_openvpn(self) -> bool:
        """Check if user should be treated as OpenVPN-enabled (flag or actual config rows)."""
        if getattr(self, "enable_openvpn", None) is True:
            return True

        return any(
            c.protocol == "openvpn"
            and (
                c.is_active
                or (
                    c.revoked_at is None
                    and (bool(c.certificate_cn) or bool(c.certificate_serial))
                )
            )
            for c in self.configs
        )
    
    @property
    def has_wireguard(self) -> bool:
        """Check if user has WireGuard config"""
        has_user_keys = bool((self.wg_public_key or "").strip() and (self.wg_allocated_ip or "").strip())
        return has_user_keys or any(c.protocol == "wireguard" and c.is_active for c in self.configs)
    
    @property
    def has_singbox(self) -> bool:
        """Check if user has Sing-box config"""
        return any(c.protocol == "singbox" and c.is_active for c in self.configs)
    
    @staticmethod
    def generate_random_username(prefix: str = "user") -> str:
        """Generate a random username like user_8f2a"""
        random_suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(4))
        return f"{prefix}_{random_suffix}"
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))


class VPNConfig(Base):
    """
    VPN Configuration model - represents a specific protocol config for a user.
    A user can have multiple configs (OpenVPN, WireGuard, Sing-box).
    """
    __tablename__ = "vpn_configs"
    
    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("vpn_users.id", ondelete="CASCADE"), nullable=False)
    protocol = Column(String(20), nullable=False)  # openvpn, wireguard, singbox
    
    # Status
    is_active = Column(Boolean, default=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(Text, nullable=True)
    
    # OpenVPN specific
    certificate_cn = Column(String(255), nullable=True)
    certificate_serial = Column(String(100), nullable=True)
    certificate_issued_at = Column(DateTime, nullable=True)
    certificate_expires_at = Column(DateTime, nullable=True)
    
    # WireGuard specific
    wireguard_public_key = Column(String(255), nullable=True)
    wireguard_private_key = Column(Text, nullable=True)
    wireguard_preshared_key = Column(Text, nullable=True)
    wireguard_allowed_ips = Column(String(255), nullable=True)
    
    # Sing-box specific
    singbox_uuid = Column(String(100), nullable=True)
    singbox_config = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("VPNUser", back_populates="configs")
    
    def __repr__(self):
        return f"<VPNConfig(user_id={self.user_id}, protocol={self.protocol}, active={self.is_active})>"
