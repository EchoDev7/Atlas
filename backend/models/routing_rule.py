from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from backend.database import Base


class RoutingRule(Base):
    __tablename__ = "routing_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_name = Column(String(64), nullable=False, unique=True, index=True)
    ingress_iface = Column(String(32), nullable=False)
    fwmark = Column(Integer, nullable=False, index=True)
    proxy_port = Column(Integer, nullable=False)
    protocol = Column(String(8), nullable=False, default="tcp")
    table_id = Column(Integer, nullable=False)
    table_name = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False, default="active", index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
