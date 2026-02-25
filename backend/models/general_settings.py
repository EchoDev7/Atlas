from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from backend.database import Base


class GeneralSettings(Base):
    """Singleton table for server-wide settings shared across protocols."""

    __tablename__ = "general_settings"

    id = Column(Integer, primary_key=True, index=True)
    public_ipv4_address = Column(String(64), nullable=True)
    public_ipv6_address = Column(String(64), nullable=True)
    global_ipv6_support = Column(Boolean, nullable=False, default=True)
    wan_interface = Column(String(32), nullable=False, default="eth0")

    admin_allowed_ips = Column(Text, nullable=False, default="0.0.0.0/0")

    panel_domain = Column(String(255), nullable=False, default="")
    panel_https_port = Column(Integer, nullable=False, default=2053)
    subscription_domain = Column(String(255), nullable=False, default="")
    subscription_https_port = Column(Integer, nullable=False, default=2083)
    ssl_mode = Column(String(32), nullable=False, default="none")
    letsencrypt_email = Column(String(255), nullable=True)
    force_https = Column(Boolean, nullable=False, default=False)
    auto_renew_ssl = Column(Boolean, nullable=False, default=True)
    custom_ssl_certificate = Column(Text, nullable=True)
    custom_ssl_private_key = Column(Text, nullable=True)

    system_timezone = Column(String(64), nullable=False, default="UTC")
    ntp_server = Column(String(255), nullable=False, default="pool.ntp.org")

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
