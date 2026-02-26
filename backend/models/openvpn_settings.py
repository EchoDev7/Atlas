from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from backend.database import Base


class OpenVPNSettings(Base):
    """Singleton table for OpenVPN server settings."""

    __tablename__ = "openvpn_settings"

    id = Column(Integer, primary_key=True, index=True)
    port = Column(Integer, nullable=False, default=1194)
    protocol = Column(String(8), nullable=False, default="udp")
    device_type = Column(String(8), nullable=False, default="tun")
    topology = Column(String(16), nullable=False, default="subnet")
    ipv4_network = Column(String(32), nullable=False, default="10.8.0.0")
    ipv4_netmask = Column(String(32), nullable=False, default="255.255.255.0")
    ipv6_network = Column(String(64), nullable=True)
    ipv6_prefix = Column(Integer, nullable=True)
    ipv4_pool = Column(String(64), nullable=False, default="10.8.0.0 255.255.255.0")
    ipv6_pool = Column(String(64), nullable=True)
    max_clients = Column(Integer, nullable=False, default=100)
    client_to_client = Column(Boolean, nullable=False, default=False)

    redirect_gateway = Column(Boolean, nullable=False, default=True)
    primary_dns = Column(String(64), nullable=False, default="8.8.8.8")
    secondary_dns = Column(String(64), nullable=False, default="1.1.1.1")
    block_outside_dns = Column(Boolean, nullable=False, default=False)
    push_custom_routes = Column(Text, nullable=True)

    data_ciphers = Column(String(160), nullable=False, default="AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
    tls_version_min = Column(String(8), nullable=False, default="1.2")
    tls_mode = Column(String(16), nullable=False, default="tls-crypt")
    auth_digest = Column(String(16), nullable=False, default="SHA256")
    reneg_sec = Column(Integer, nullable=False, default=3600)

    tun_mtu = Column(Integer, nullable=False, default=1500)
    mssfix = Column(Integer, nullable=False, default=1450)
    sndbuf = Column(Integer, nullable=False, default=393216)
    rcvbuf = Column(Integer, nullable=False, default=393216)
    fast_io = Column(Boolean, nullable=False, default=False)
    tcp_nodelay = Column(Boolean, nullable=False, default=False)
    explicit_exit_notify = Column(Integer, nullable=False, default=1)

    keepalive_ping = Column(Integer, nullable=False, default=10)
    keepalive_timeout = Column(Integer, nullable=False, default=120)
    inactive_timeout = Column(Integer, nullable=False, default=300)
    management_port = Column(Integer, nullable=False, default=5555)
    verbosity = Column(Integer, nullable=False, default=3)
    enable_auth_nocache = Column(Boolean, nullable=False, default=True)

    custom_directives = Column(Text, nullable=True)
    advanced_client_push = Column(Text, nullable=True)

    # OS-Specific Custom Directives
    custom_ios = Column(Text, nullable=True)
    custom_android = Column(Text, nullable=True)
    custom_windows = Column(Text, nullable=True)
    custom_mac = Column(Text, nullable=True)

    obfuscation_mode = Column(String(32), nullable=False, default="standard")
    proxy_server = Column(String(255), nullable=True)
    proxy_address = Column(String(255), nullable=True)
    proxy_port = Column(Integer, nullable=False, default=8080)
    spoofed_host = Column(String(255), nullable=True, default="speedtest.net")
    socks_server = Column(String(255), nullable=True)
    socks_port = Column(Integer, nullable=True)
    stunnel_port = Column(Integer, nullable=False, default=443)
    sni_domain = Column(String(255), nullable=True)
    cdn_domain = Column(String(255), nullable=True)
    ws_path = Column(String(255), nullable=False, default="/stream")
    ws_port = Column(Integer, nullable=False, default=8080)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
