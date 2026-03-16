from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from backend.database import Base


class HysteriaInbound(Base):
    __tablename__ = "hysteria_inbounds"

    id = Column(Integer, primary_key=True, index=True)
    remark = Column(String(255), nullable=False, unique=True, index=True)
    port = Column(String(64), nullable=False, index=True)
    up_mbps = Column(Integer, nullable=True)
    down_mbps = Column(Integer, nullable=True)
    obfs_password = Column(String(255), nullable=True)
    masquerade = Column(String(512), nullable=False, default="https://www.bing.com")
    cert_mode = Column(String(32), nullable=False, default="self_signed")
    sni = Column(String(255), nullable=True)
    cert_pem = Column(Text, nullable=True)
    key_pem = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
