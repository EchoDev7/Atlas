from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String

from backend.database import Base


class VlessInbound(Base):
    __tablename__ = "vless_inbounds"

    id = Column(Integer, primary_key=True, index=True)
    remark = Column(String(255), nullable=False, unique=True, index=True)
    port = Column(Integer, nullable=False, unique=True, index=True)
    network = Column(String(32), nullable=False, default="tcp")
    security = Column(String(32), nullable=False, default="reality")
    flow = Column(String(64), nullable=True, default="xtls-rprx-vision")
    sni = Column(String(255), nullable=True, default="www.microsoft.com")
    fingerprint = Column(String(32), nullable=False, default="chrome")
    spider_x = Column(String(255), nullable=False, default="/")
    transport_settings = Column(JSON, nullable=True)
    tls_settings = Column(JSON, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
