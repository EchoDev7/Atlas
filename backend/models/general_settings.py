from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Text

from backend.database import Base


class GeneralSettings(Base):
    """Singleton table for server-wide settings shared across protocols."""

    __tablename__ = "general_settings"

    id = Column(Integer, primary_key=True, index=True)
    server_address = Column(String(255), nullable=True)
    public_ipv4_address = Column(String(64), nullable=True)
    public_ipv6_address = Column(String(64), nullable=True)
    global_ipv6_support = Column(Boolean, nullable=False, default=True)
    wan_interface = Column(String(32), nullable=False, default="eth0")
    server_system_dns_primary = Column(String(64), nullable=False, default="1.1.1.1")
    server_system_dns_secondary = Column(String(64), nullable=False, default="8.8.8.8")

    admin_allowed_ips = Column(Text, nullable=False, default="0.0.0.0/0")
    login_max_failed_attempts = Column(Integer, nullable=False, default=5)
    login_block_duration_minutes = Column(Integer, nullable=False, default=15)

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

    is_tunnel_enabled = Column(Boolean, nullable=False, default=False)
    tunnel_mode = Column(String(32), nullable=False, default="direct")
    foreign_server_ip = Column(String(255), nullable=True)
    foreign_server_port = Column(Integer, nullable=False, default=22)
    foreign_ssh_user = Column(String(64), nullable=False, default="root")
    foreign_ssh_password = Column(String(255), nullable=True)
    tunnel_architecture = Column(String(32), nullable=False, default="standalone")
    dnstt_domain = Column(String(1024), nullable=True)
    dnstt_active_domain = Column(String(255), nullable=True)
    dnstt_dns_resolver = Column(String(1024), nullable=False, default="8.8.8.8")
    dnstt_resolver_strategy = Column(String(32), nullable=False, default="failover")
    dnstt_duplication_mode = Column(Integer, nullable=False, default=1)
    dnstt_mtu_mode = Column(String(32), nullable=False, default="preset")
    dnstt_mtu = Column(Integer, nullable=False, default=1232)
    dnstt_mtu_upload_min = Column(Integer, nullable=False, default=472)
    dnstt_mtu_upload_max = Column(Integer, nullable=False, default=1204)
    dnstt_mtu_download_min = Column(Integer, nullable=False, default=472)
    dnstt_mtu_download_max = Column(Integer, nullable=False, default=1204)
    dnstt_adaptive_per_resolver = Column(Boolean, nullable=False, default=True)
    dnstt_transport_probe_workers = Column(Integer, nullable=False, default=2)
    dnstt_transport_retry_count = Column(Integer, nullable=False, default=2)
    dnstt_transport_probe_timeout_ms = Column(Integer, nullable=False, default=2000)
    dnstt_transport_switch_threshold_percent = Column(Integer, nullable=False, default=20)
    dnstt_telemetry = Column(JSON, nullable=True)
    dnstt_telemetry_history = Column(JSON, nullable=True)
    dnstt_pubkey = Column(Text, nullable=True)
    dnstt_privkey = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
