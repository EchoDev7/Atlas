from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from backend.database import Base


class TuicInbound(Base):
    __tablename__ = "tuic_inbounds"

    id = Column(Integer, primary_key=True, index=True)
    remark = Column(String(255), nullable=False, unique=True, index=True)
    port = Column(Integer, nullable=False, unique=True, index=True)
    congestion_control = Column(String(32), nullable=False, default="bbr")
    udp_relay_mode = Column(String(32), nullable=False, default="native")
    zero_rtt_handshake = Column(Boolean, nullable=False, default=True)
    alpn = Column(String(64), nullable=False, default="h3")
    cert_mode = Column(String(32), nullable=False, default="self_signed")
    sni = Column(String(255), nullable=True)
    cert_pem = Column(Text, nullable=True)
    key_pem = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
