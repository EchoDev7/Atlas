from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from backend.database import Base


class WireGuardSettings(Base):
    """Singleton table for WireGuard server settings."""

    __tablename__ = "wireguard_settings"

    id = Column(Integer, primary_key=True, index=True)
    interface_name = Column(String(32), nullable=False, default="wg0")
    listen_port = Column(Integer, nullable=False, default=51820)
    address_range = Column(String(64), nullable=False, default="10.9.0.0/24")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
