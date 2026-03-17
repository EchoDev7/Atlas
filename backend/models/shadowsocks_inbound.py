from sqlalchemy import Boolean, CheckConstraint, Column, Integer, String

from backend.database import Base


class ShadowsocksInbound(Base):
    __tablename__ = "shadowsocks_inbounds"
    __table_args__ = (
        CheckConstraint(
            "method IN ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305')",
            name="ck_shadowsocks_inbounds_method",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    remark = Column(String(255), nullable=False, unique=True, index=True)
    port = Column(Integer, nullable=False, unique=True, index=True)
    method = Column(String(64), nullable=False, default="2022-blake3-aes-128-gcm")
    password = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
