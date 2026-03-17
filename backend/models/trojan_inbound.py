from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Text

from backend.database import Base


class TrojanInbound(Base):
    __tablename__ = "trojan_inbounds"

    id = Column(Integer, primary_key=True, index=True)
    remark = Column(String(255), nullable=False, unique=True, index=True)
    port = Column(Integer, nullable=False, unique=True, index=True)
    network = Column(String(32), nullable=False, default="tcp")
    password = Column(String(255), nullable=False)
    cert_mode = Column(String(32), nullable=False, default="self_signed")
    sni = Column(String(255), nullable=False, default="www.microsoft.com")
    alpn = Column(String(64), nullable=False, default="h2,http/1.1")
    fingerprint = Column(String(32), nullable=False, default="chrome")
    transport_settings = Column(JSON, nullable=True)
    cert_pem = Column(Text, nullable=True)
    key_pem = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
