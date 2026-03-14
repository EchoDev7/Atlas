import ipaddress
from urllib.request import urlopen

from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from backend.config import settings

settings.DATA_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def _detect_public_ipv4() -> str | None:
    endpoints = (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
    )
    for endpoint in endpoints:
        try:
            with urlopen(endpoint, timeout=3) as response:  # nosec B310
                candidate = response.read().decode("utf-8", errors="ignore").strip()
            parsed = ipaddress.ip_address(candidate)
            if parsed.version == 4:
                return candidate
        except Exception:
            continue
    return None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    # Lightweight SQLite migration for existing deployments
    with engine.begin() as connection:
        table_exists = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='vpn_users'")
        ).fetchone()
        if not table_exists:
            return

        columns = connection.execute(text("PRAGMA table_info(vpn_users)")).fetchall()
        column_names = {col[1] for col in columns}
        if "max_devices" not in column_names:
            connection.execute(
                text("ALTER TABLE vpn_users ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 1")
            )
        vpn_user_column_migrations = {
            "traffic_limit_bytes": "ALTER TABLE vpn_users ADD COLUMN traffic_limit_bytes BIGINT",
            "traffic_used_bytes": "ALTER TABLE vpn_users ADD COLUMN traffic_used_bytes BIGINT NOT NULL DEFAULT 0",
            "access_start_at": "ALTER TABLE vpn_users ADD COLUMN access_start_at DATETIME",
            "access_expires_at": "ALTER TABLE vpn_users ADD COLUMN access_expires_at DATETIME",
            "max_concurrent_connections": "ALTER TABLE vpn_users ADD COLUMN max_concurrent_connections INTEGER NOT NULL DEFAULT 1",
            "current_connections": "ALTER TABLE vpn_users ADD COLUMN current_connections INTEGER NOT NULL DEFAULT 0",
            "is_connection_limit_exceeded": "ALTER TABLE vpn_users ADD COLUMN is_connection_limit_exceeded BOOLEAN NOT NULL DEFAULT 0",
            "wg_private_key": "ALTER TABLE vpn_users ADD COLUMN wg_private_key VARCHAR(128)",
            "wg_public_key": "ALTER TABLE vpn_users ADD COLUMN wg_public_key VARCHAR(128)",
            "wg_allocated_ip": "ALTER TABLE vpn_users ADD COLUMN wg_allocated_ip VARCHAR(64)",
            "enable_openvpn": "ALTER TABLE vpn_users ADD COLUMN enable_openvpn BOOLEAN NOT NULL DEFAULT 1",
            "enable_l2tp": "ALTER TABLE vpn_users ADD COLUMN enable_l2tp BOOLEAN NOT NULL DEFAULT 0",
            "ppp_password": "ALTER TABLE vpn_users ADD COLUMN ppp_password VARCHAR(255)",
        }
        for column_name, migration_sql in vpn_user_column_migrations.items():
            if column_name not in column_names:
                connection.execute(text(migration_sql))

        columns = connection.execute(text("PRAGMA table_info(vpn_users)")).fetchall()
        column_names = {col[1] for col in columns}

        if {"traffic_limit_bytes", "data_limit_gb"}.issubset(column_names):
            connection.execute(
                text(
                    """
                    UPDATE vpn_users
                    SET traffic_limit_bytes = CAST(data_limit_gb * 1073741824 AS INTEGER)
                    WHERE traffic_limit_bytes IS NULL
                      AND data_limit_gb IS NOT NULL
                    """
                )
            )

        if "enable_openvpn" in column_names:
            connection.execute(
                text(
                    """
                    UPDATE vpn_users
                    SET enable_openvpn = 1
                    WHERE enable_openvpn IS NULL
                    """
                )
            )
        if "enable_l2tp" in column_names:
            connection.execute(
                text(
                    """
                    UPDATE vpn_users
                    SET enable_l2tp = 0
                    WHERE enable_l2tp IS NULL
                    """
                )
            )

        if {"traffic_used_bytes", "total_bytes_sent", "total_bytes_received"}.issubset(column_names):
            connection.execute(
                text(
                    """
                    UPDATE vpn_users
                    SET traffic_used_bytes = COALESCE(
                        MAX(COALESCE(traffic_used_bytes, 0), COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)),
                        0
                    )
                    """
                )
            )

        if {"access_expires_at", "expiry_date"}.issubset(column_names):
            connection.execute(
                text(
                    """
                    UPDATE vpn_users
                    SET access_expires_at = expiry_date
                    WHERE access_expires_at IS NULL
                      AND expiry_date IS NOT NULL
                    """
                )
            )

        if {"max_concurrent_connections", "max_devices"}.issubset(column_names):
            connection.execute(
                text(
                    """
                    UPDATE vpn_users
                    SET max_concurrent_connections = COALESCE(NULLIF(max_concurrent_connections, 0), max_devices, 1)
                    """
                )
            )

        openvpn_settings_table_exists = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='openvpn_settings'")
        ).fetchone()
        if openvpn_settings_table_exists:
            openvpn_columns = connection.execute(text("PRAGMA table_info(openvpn_settings)")).fetchall()
            openvpn_column_names = {col[1] for col in openvpn_columns}

            openvpn_column_migrations = {
                "ipv4_network": "ALTER TABLE openvpn_settings ADD COLUMN ipv4_network VARCHAR(32) NOT NULL DEFAULT '10.8.0.0'",
                "ipv4_netmask": "ALTER TABLE openvpn_settings ADD COLUMN ipv4_netmask VARCHAR(32) NOT NULL DEFAULT '255.255.255.0'",
                "ipv6_network": "ALTER TABLE openvpn_settings ADD COLUMN ipv6_network VARCHAR(64)",
                "ipv6_prefix": "ALTER TABLE openvpn_settings ADD COLUMN ipv6_prefix INTEGER",
                "ipv6_pool": "ALTER TABLE openvpn_settings ADD COLUMN ipv6_pool VARCHAR(64)",
                "max_clients": "ALTER TABLE openvpn_settings ADD COLUMN max_clients INTEGER NOT NULL DEFAULT 100",
                "client_to_client": "ALTER TABLE openvpn_settings ADD COLUMN client_to_client BOOLEAN NOT NULL DEFAULT 0",
                "primary_dns": "ALTER TABLE openvpn_settings ADD COLUMN primary_dns VARCHAR(64) NOT NULL DEFAULT '8.8.8.8'",
                "secondary_dns": "ALTER TABLE openvpn_settings ADD COLUMN secondary_dns VARCHAR(64) NOT NULL DEFAULT '1.1.1.1'",
                "block_outside_dns": "ALTER TABLE openvpn_settings ADD COLUMN block_outside_dns BOOLEAN NOT NULL DEFAULT 0",
                "push_custom_routes": "ALTER TABLE openvpn_settings ADD COLUMN push_custom_routes TEXT",
                "tls_mode": "ALTER TABLE openvpn_settings ADD COLUMN tls_mode VARCHAR(16) NOT NULL DEFAULT 'tls-crypt'",
                "reneg_sec": "ALTER TABLE openvpn_settings ADD COLUMN reneg_sec INTEGER NOT NULL DEFAULT 3600",
                "tun_mtu": "ALTER TABLE openvpn_settings ADD COLUMN tun_mtu INTEGER NOT NULL DEFAULT 1500",
                "mssfix": "ALTER TABLE openvpn_settings ADD COLUMN mssfix INTEGER NOT NULL DEFAULT 1450",
                "sndbuf": "ALTER TABLE openvpn_settings ADD COLUMN sndbuf INTEGER NOT NULL DEFAULT 393216",
                "rcvbuf": "ALTER TABLE openvpn_settings ADD COLUMN rcvbuf INTEGER NOT NULL DEFAULT 393216",
                "explicit_exit_notify": "ALTER TABLE openvpn_settings ADD COLUMN explicit_exit_notify INTEGER NOT NULL DEFAULT 1",
                "tcp_nodelay": "ALTER TABLE openvpn_settings ADD COLUMN tcp_nodelay BOOLEAN NOT NULL DEFAULT 0",
                "keepalive_ping": "ALTER TABLE openvpn_settings ADD COLUMN keepalive_ping INTEGER NOT NULL DEFAULT 10",
                "keepalive_timeout": "ALTER TABLE openvpn_settings ADD COLUMN keepalive_timeout INTEGER NOT NULL DEFAULT 120",
                "inactive_timeout": "ALTER TABLE openvpn_settings ADD COLUMN inactive_timeout INTEGER NOT NULL DEFAULT 300",
                "management_port": "ALTER TABLE openvpn_settings ADD COLUMN management_port INTEGER NOT NULL DEFAULT 5555",
                "verbosity": "ALTER TABLE openvpn_settings ADD COLUMN verbosity INTEGER NOT NULL DEFAULT 3",
                "advanced_client_push": "ALTER TABLE openvpn_settings ADD COLUMN advanced_client_push TEXT",
                "obfuscation_mode": "ALTER TABLE openvpn_settings ADD COLUMN obfuscation_mode VARCHAR(32) NOT NULL DEFAULT 'standard'",
                "proxy_server": "ALTER TABLE openvpn_settings ADD COLUMN proxy_server VARCHAR(255)",
                "proxy_address": "ALTER TABLE openvpn_settings ADD COLUMN proxy_address VARCHAR(255)",
                "proxy_port": "ALTER TABLE openvpn_settings ADD COLUMN proxy_port INTEGER NOT NULL DEFAULT 8080",
                "spoofed_host": "ALTER TABLE openvpn_settings ADD COLUMN spoofed_host VARCHAR(255)",
                "socks_server": "ALTER TABLE openvpn_settings ADD COLUMN socks_server VARCHAR(255)",
                "socks_port": "ALTER TABLE openvpn_settings ADD COLUMN socks_port INTEGER",
                "stunnel_port": "ALTER TABLE openvpn_settings ADD COLUMN stunnel_port INTEGER NOT NULL DEFAULT 443",
                "sni_domain": "ALTER TABLE openvpn_settings ADD COLUMN sni_domain VARCHAR(255)",
                "cdn_domain": "ALTER TABLE openvpn_settings ADD COLUMN cdn_domain VARCHAR(255)",
                "ws_path": "ALTER TABLE openvpn_settings ADD COLUMN ws_path VARCHAR(255) NOT NULL DEFAULT '/stream'",
                "ws_port": "ALTER TABLE openvpn_settings ADD COLUMN ws_port INTEGER NOT NULL DEFAULT 8080",
                "custom_ios": "ALTER TABLE openvpn_settings ADD COLUMN custom_ios TEXT",
                "custom_android": "ALTER TABLE openvpn_settings ADD COLUMN custom_android TEXT",
                "custom_windows": "ALTER TABLE openvpn_settings ADD COLUMN custom_windows TEXT",
                "custom_mac": "ALTER TABLE openvpn_settings ADD COLUMN custom_mac TEXT",
                "enable_auth_nocache": "ALTER TABLE openvpn_settings ADD COLUMN enable_auth_nocache BOOLEAN NOT NULL DEFAULT 1",
                "resolv_retry_mode": "ALTER TABLE openvpn_settings ADD COLUMN resolv_retry_mode VARCHAR(16) NOT NULL DEFAULT 'infinite'",
                "persist_key": "ALTER TABLE openvpn_settings ADD COLUMN persist_key BOOLEAN NOT NULL DEFAULT 1",
                "persist_tun": "ALTER TABLE openvpn_settings ADD COLUMN persist_tun BOOLEAN NOT NULL DEFAULT 1",
                "enable_dns_leak_protection": "ALTER TABLE openvpn_settings ADD COLUMN enable_dns_leak_protection BOOLEAN NOT NULL DEFAULT 1",
            }

            for column_name, migration_sql in openvpn_column_migrations.items():
                if column_name not in openvpn_column_names:
                    connection.execute(text(migration_sql))

            openvpn_columns = connection.execute(text("PRAGMA table_info(openvpn_settings)")).fetchall()
            openvpn_column_names = {col[1] for col in openvpn_columns}

            if "obfuscation_mode" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET obfuscation_mode = CASE LOWER(TRIM(COALESCE(obfuscation_mode, 'standard')))
                            WHEN 'native_stealth' THEN 'stealth'
                            WHEN 'tls_tunnel' THEN 'standard'
                            WHEN 'websocket_cdn' THEN 'standard'
                            ELSE LOWER(TRIM(COALESCE(obfuscation_mode, 'standard')))
                        END
                        """
                    )
                )

            if "resolv_retry_mode" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET resolv_retry_mode = 'infinite'
                        WHERE resolv_retry_mode IS NULL OR TRIM(resolv_retry_mode) = ''
                        """
                    )
                )

            if "persist_key" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET persist_key = 1
                        WHERE persist_key IS NULL
                        """
                    )
                )

            if "persist_tun" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET persist_tun = 1
                        WHERE persist_tun IS NULL
                        """
                    )
                )

            if "mtu" in openvpn_column_names and "tun_mtu" in openvpn_column_names:
                connection.execute(
                    text("UPDATE openvpn_settings SET tun_mtu = COALESCE(tun_mtu, mtu)")
                )

            if {"proxy_server", "proxy_address"}.issubset(openvpn_column_names):
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET proxy_server = COALESCE(NULLIF(TRIM(proxy_server), ''), NULLIF(TRIM(proxy_address), ''), proxy_server)
                        WHERE proxy_server IS NULL OR TRIM(proxy_server) = ''
                        """
                    )
                )

            if "ws_path" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET ws_path = '/stream'
                        WHERE ws_path IS NULL OR TRIM(ws_path) = '' OR ws_path = '/vpn-ws'
                        """
                    )
                )
            
            # Update default values for improved settings
            if "tls_version_min" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET tls_version_min = '1.3'
                        WHERE tls_version_min = '1.2'
                        """
                    )
                )
            
            if "sndbuf" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET sndbuf = 0
                        WHERE sndbuf = 393216
                        """
                    )
                )
            
            if "rcvbuf" in openvpn_column_names:
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET rcvbuf = 0
                        WHERE rcvbuf = 393216
                        """
                    )
                )

            if {"ipv4_pool", "ipv4_network", "ipv4_netmask"}.issubset(openvpn_column_names):
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET ipv4_network = COALESCE(NULLIF(TRIM(substr(ipv4_pool, 1, instr(ipv4_pool || ' ', ' ') - 1)), ''), ipv4_network, '10.8.0.0'),
                            ipv4_netmask = COALESCE(NULLIF(TRIM(substr(ipv4_pool || ' ', instr(ipv4_pool || ' ', ' ') + 1)), ''), ipv4_netmask, '255.255.255.0')
                        WHERE ipv4_pool IS NOT NULL
                        """
                    )
                )

            if {"ipv6_pool", "ipv6_network"}.issubset(openvpn_column_names):
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET ipv6_network = COALESCE(NULLIF(TRIM(substr(ipv6_pool, 1, instr(ipv6_pool || '/', '/') - 1)), ''), ipv6_network)
                        WHERE ipv6_pool IS NOT NULL
                          AND instr(ipv6_pool, '/') > 0
                        """
                    )
                )

            if {"ipv6_pool", "ipv6_prefix"}.issubset(openvpn_column_names):
                connection.execute(
                    text(
                        """
                        UPDATE openvpn_settings
                        SET ipv6_prefix = COALESCE(CAST(NULLIF(TRIM(substr(ipv6_pool || '/', instr(ipv6_pool || '/', '/') + 1)), '') AS INTEGER), ipv6_prefix)
                        WHERE ipv6_pool IS NOT NULL
                          AND instr(ipv6_pool, '/') > 0
                        """
                    )
                )

            settings_row_count = connection.execute(
                text("SELECT COUNT(*) FROM openvpn_settings")
            ).scalar_one()
            if settings_row_count == 0:
                connection.execute(
                    text(
                        """
                        INSERT INTO openvpn_settings (
                            id, port, protocol, device_type, topology,
                            ipv4_network, ipv4_netmask, ipv6_network, ipv6_prefix, ipv4_pool, ipv6_pool,
                            max_clients, client_to_client,
                            redirect_gateway, primary_dns, secondary_dns, block_outside_dns, push_custom_routes,
                            data_ciphers, tls_version_min, tls_mode, auth_digest, reneg_sec,
                            tun_mtu, mssfix, sndbuf, rcvbuf, fast_io, explicit_exit_notify, tcp_nodelay,
                            keepalive_ping, keepalive_timeout, inactive_timeout, management_port, verbosity,
                            enable_auth_nocache, resolv_retry_mode, persist_key, persist_tun, enable_dns_leak_protection,
                            custom_directives, advanced_client_push,
                            obfuscation_mode, proxy_server, proxy_address, proxy_port, spoofed_host, socks_server, socks_port, stunnel_port, sni_domain, cdn_domain, ws_path, ws_port,
                            created_at, updated_at
                        ) VALUES (
                            1, 1194, 'udp', 'tun', 'subnet',
                            '10.8.0.0', '255.255.255.0', NULL, NULL, '10.8.0.0 255.255.255.0', NULL,
                            100, 0,
                            1, '8.8.8.8', '1.1.1.1', 0, NULL,
                            'AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305', '1.2', 'tls-crypt', 'SHA256', 3600,
                            1500, 1450, 393216, 393216, 0, 1, 0,
                            10, 120, 300, 5555, 3,
                            1, 'infinite', 1, 1, 1,
                            NULL, NULL,
                            'standard', NULL, NULL, 8080, 'speedtest.net', NULL, NULL, 443, NULL, NULL, '/stream', 8080,
                            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                        )
                        """
                    )
                )

        wireguard_settings_table_exists = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='wireguard_settings'")
        ).fetchone()
        if wireguard_settings_table_exists:
            wireguard_columns = connection.execute(text("PRAGMA table_info(wireguard_settings)")).fetchall()
            wireguard_column_names = {col[1] for col in wireguard_columns}

            wireguard_column_migrations = {
                "interface_name": "ALTER TABLE wireguard_settings ADD COLUMN interface_name VARCHAR(32) NOT NULL DEFAULT 'wg0'",
                "listen_port": "ALTER TABLE wireguard_settings ADD COLUMN listen_port INTEGER NOT NULL DEFAULT 51820",
                "address_range": "ALTER TABLE wireguard_settings ADD COLUMN address_range VARCHAR(64) NOT NULL DEFAULT '10.9.0.0/24'",
                "endpoint_address": "ALTER TABLE wireguard_settings ADD COLUMN endpoint_address VARCHAR(255)",
                "server_private_key": "ALTER TABLE wireguard_settings ADD COLUMN server_private_key VARCHAR(128)",
                "server_public_key": "ALTER TABLE wireguard_settings ADD COLUMN server_public_key VARCHAR(128)",
                "created_at": "ALTER TABLE wireguard_settings ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
                "updated_at": "ALTER TABLE wireguard_settings ADD COLUMN updated_at DATETIME",
            }

            for column_name, migration_sql in wireguard_column_migrations.items():
                if column_name not in wireguard_column_names:
                    connection.execute(text(migration_sql))

            wireguard_row_count = connection.execute(
                text("SELECT COUNT(*) FROM wireguard_settings")
            ).scalar_one()
            if wireguard_row_count == 0:
                connection.execute(
                    text(
                        """
                        INSERT INTO wireguard_settings (
                            id,
                            interface_name,
                            listen_port,
                            address_range,
                            created_at,
                            updated_at
                        ) VALUES (
                            1,
                            'wg0',
                            51820,
                            '10.9.0.0/24',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                        """
                    )
                )

        general_settings_table_exists = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='general_settings'")
        ).fetchone()
        if general_settings_table_exists:
            detected_public_ipv4 = _detect_public_ipv4()
            general_columns = connection.execute(text("PRAGMA table_info(general_settings)")).fetchall()
            general_column_names = {col[1] for col in general_columns}

            general_column_migrations = {
                "server_address": "ALTER TABLE general_settings ADD COLUMN server_address VARCHAR(255)",
                "public_ipv4_address": "ALTER TABLE general_settings ADD COLUMN public_ipv4_address VARCHAR(64)",
                "public_ipv6_address": "ALTER TABLE general_settings ADD COLUMN public_ipv6_address VARCHAR(64)",
                "global_ipv6_support": "ALTER TABLE general_settings ADD COLUMN global_ipv6_support BOOLEAN NOT NULL DEFAULT 1",
                "wan_interface": "ALTER TABLE general_settings ADD COLUMN wan_interface VARCHAR(32) NOT NULL DEFAULT 'eth0'",
                "server_system_dns_primary": "ALTER TABLE general_settings ADD COLUMN server_system_dns_primary VARCHAR(64) NOT NULL DEFAULT '1.1.1.1'",
                "server_system_dns_secondary": "ALTER TABLE general_settings ADD COLUMN server_system_dns_secondary VARCHAR(64) NOT NULL DEFAULT '8.8.8.8'",
                "is_tunnel_enabled": "ALTER TABLE general_settings ADD COLUMN is_tunnel_enabled BOOLEAN NOT NULL DEFAULT 0",
                "foreign_server_ip": "ALTER TABLE general_settings ADD COLUMN foreign_server_ip VARCHAR(64)",
                "foreign_server_port": "ALTER TABLE general_settings ADD COLUMN foreign_server_port INTEGER NOT NULL DEFAULT 22",
                "foreign_ssh_user": "ALTER TABLE general_settings ADD COLUMN foreign_ssh_user VARCHAR(64) NOT NULL DEFAULT 'root'",
                "foreign_ssh_password": "ALTER TABLE general_settings ADD COLUMN foreign_ssh_password VARCHAR(255)",
                "admin_allowed_ips": "ALTER TABLE general_settings ADD COLUMN admin_allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0'",
                "login_max_failed_attempts": "ALTER TABLE general_settings ADD COLUMN login_max_failed_attempts INTEGER NOT NULL DEFAULT 5",
                "login_block_duration_minutes": "ALTER TABLE general_settings ADD COLUMN login_block_duration_minutes INTEGER NOT NULL DEFAULT 15",
                "panel_domain": "ALTER TABLE general_settings ADD COLUMN panel_domain VARCHAR(255) NOT NULL DEFAULT ''",
                "panel_https_port": "ALTER TABLE general_settings ADD COLUMN panel_https_port INTEGER NOT NULL DEFAULT 2053",
                "subscription_domain": "ALTER TABLE general_settings ADD COLUMN subscription_domain VARCHAR(255) NOT NULL DEFAULT ''",
                "subscription_https_port": "ALTER TABLE general_settings ADD COLUMN subscription_https_port INTEGER NOT NULL DEFAULT 2083",
                "ssl_mode": "ALTER TABLE general_settings ADD COLUMN ssl_mode VARCHAR(32) NOT NULL DEFAULT 'none'",
                "letsencrypt_email": "ALTER TABLE general_settings ADD COLUMN letsencrypt_email VARCHAR(255)",
                "force_https": "ALTER TABLE general_settings ADD COLUMN force_https BOOLEAN NOT NULL DEFAULT 0",
                "auto_renew_ssl": "ALTER TABLE general_settings ADD COLUMN auto_renew_ssl BOOLEAN NOT NULL DEFAULT 1",
                "custom_ssl_certificate": "ALTER TABLE general_settings ADD COLUMN custom_ssl_certificate TEXT",
                "custom_ssl_private_key": "ALTER TABLE general_settings ADD COLUMN custom_ssl_private_key TEXT",
                "system_timezone": "ALTER TABLE general_settings ADD COLUMN system_timezone VARCHAR(64) NOT NULL DEFAULT 'UTC'",
                "ntp_server": "ALTER TABLE general_settings ADD COLUMN ntp_server VARCHAR(255) NOT NULL DEFAULT 'pool.ntp.org'",
                "created_at": "ALTER TABLE general_settings ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
                "updated_at": "ALTER TABLE general_settings ADD COLUMN updated_at DATETIME",
            }

            for column_name, migration_sql in general_column_migrations.items():
                if column_name not in general_column_names:
                    connection.execute(text(migration_sql))

            general_columns = connection.execute(text("PRAGMA table_info(general_settings)")).fetchall()
            general_column_names = {col[1] for col in general_columns}

            if {"server_address", "public_ipv4_address"}.issubset(general_column_names):
                connection.execute(
                    text(
                        """
                        UPDATE general_settings
                        SET server_address = TRIM(public_ipv4_address)
                        WHERE (server_address IS NULL OR TRIM(server_address) = '')
                          AND public_ipv4_address IS NOT NULL
                          AND TRIM(public_ipv4_address) != ''
                        """
                    )
                )

                if detected_public_ipv4:
                    connection.execute(
                        text(
                            """
                            UPDATE general_settings
                            SET public_ipv4_address = :detected_public_ipv4,
                                server_address = :detected_public_ipv4,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE (public_ipv4_address IS NULL OR TRIM(public_ipv4_address) = '')
                               OR (server_address IS NULL OR TRIM(server_address) = '')
                            """
                        ),
                        {"detected_public_ipv4": detected_public_ipv4},
                    )

            if {"panel_https_port", "subscription_https_port"}.issubset(general_column_names):
                connection.execute(
                    text(
                        """
                        UPDATE general_settings
                        SET panel_https_port = CASE
                                WHEN panel_https_port IN (2053, 2083, 2087, 2096, 8443) THEN panel_https_port
                                ELSE 2053
                            END,
                            subscription_https_port = CASE
                                WHEN subscription_https_port IN (2053, 2083, 2087, 2096, 8443) THEN subscription_https_port
                                ELSE 2083
                            END
                        """
                    )
                )

            if {"login_max_failed_attempts", "login_block_duration_minutes"}.issubset(general_column_names):
                connection.execute(
                    text(
                        """
                        UPDATE general_settings
                        SET login_max_failed_attempts = CASE
                                WHEN login_max_failed_attempts BETWEEN 1 AND 20 THEN login_max_failed_attempts
                                ELSE 5
                            END,
                            login_block_duration_minutes = CASE
                                WHEN login_block_duration_minutes BETWEEN 1 AND 1440 THEN login_block_duration_minutes
                                ELSE 15
                            END
                        """
                    )
                )

            general_settings_row_count = connection.execute(
                text("SELECT COUNT(*) FROM general_settings")
            ).scalar_one()
            if general_settings_row_count == 0:
                connection.execute(
                    text(
                        """
                        INSERT INTO general_settings (
                            id,
                            server_address,
                            public_ipv4_address,
                            public_ipv6_address,
                            global_ipv6_support,
                            wan_interface,
                            server_system_dns_primary,
                            server_system_dns_secondary,
                            is_tunnel_enabled,
                            foreign_server_ip,
                            foreign_server_port,
                            foreign_ssh_user,
                            foreign_ssh_password,
                            admin_allowed_ips,
                            login_max_failed_attempts,
                            login_block_duration_minutes,
                            panel_domain,
                            panel_https_port,
                            subscription_domain,
                            subscription_https_port,
                            ssl_mode,
                            letsencrypt_email,
                            force_https,
                            auto_renew_ssl,
                            custom_ssl_certificate,
                            custom_ssl_private_key,
                            system_timezone,
                            ntp_server,
                            created_at,
                            updated_at
                        ) VALUES (
                            1,
                            :detected_public_ipv4,
                            :detected_public_ipv4,
                            NULL,
                            1,
                            'eth0',
                            '1.1.1.1',
                            '8.8.8.8',
                            0,
                            NULL,
                            22,
                            'root',
                            NULL,
                            '0.0.0.0/0',
                            5,
                            15,
                            '',
                            2053,
                            '',
                            2083,
                            'none',
                            NULL,
                            0,
                            1,
                            NULL,
                            NULL,
                            'UTC',
                            'pool.ntp.org',
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP
                        )
                        """
                    ),
                    {"detected_public_ipv4": detected_public_ipv4},
                )

        audit_logs_table_exists = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
        ).fetchone()
        routing_rules_table_exists = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='routing_rules'")
        ).fetchone()
        if not routing_rules_table_exists:
            connection.execute(
                text(
                    """
                    CREATE TABLE routing_rules (
                        id INTEGER PRIMARY KEY,
                        rule_name VARCHAR(64) NOT NULL UNIQUE,
                        ingress_iface VARCHAR(32) NOT NULL,
                        fwmark INTEGER NOT NULL,
                        proxy_port INTEGER NOT NULL,
                        protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
                        dest_cidr VARCHAR(64) NOT NULL DEFAULT '0.0.0.0/0',
                        description VARCHAR(255),
                        table_id INTEGER NOT NULL,
                        table_name VARCHAR(64) NOT NULL,
                        status VARCHAR(16) NOT NULL DEFAULT 'active',
                        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_routing_rules_rule_name ON routing_rules (rule_name)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_routing_rules_fwmark ON routing_rules (fwmark)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_routing_rules_status ON routing_rules (status)"))
        else:
            routing_columns = connection.execute(text("PRAGMA table_info(routing_rules)")).fetchall()
            routing_column_names = {col[1] for col in routing_columns}
            routing_column_migrations = {
                "protocol": "ALTER TABLE routing_rules ADD COLUMN protocol VARCHAR(8) NOT NULL DEFAULT 'tcp'",
                "dest_cidr": "ALTER TABLE routing_rules ADD COLUMN dest_cidr VARCHAR(64) NOT NULL DEFAULT '0.0.0.0/0'",
                "description": "ALTER TABLE routing_rules ADD COLUMN description VARCHAR(255)",
                "table_id": "ALTER TABLE routing_rules ADD COLUMN table_id INTEGER NOT NULL DEFAULT 0",
                "table_name": "ALTER TABLE routing_rules ADD COLUMN table_name VARCHAR(64) NOT NULL DEFAULT ''",
                "status": "ALTER TABLE routing_rules ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'active'",
                "created_at": "ALTER TABLE routing_rules ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
                "updated_at": "ALTER TABLE routing_rules ADD COLUMN updated_at DATETIME",
            }
            for column_name, migration_sql in routing_column_migrations.items():
                if column_name not in routing_column_names:
                    connection.execute(text(migration_sql))

            connection.execute(
                text(
                    """
                    UPDATE routing_rules
                    SET protocol = 'tcp'
                    WHERE protocol IS NULL OR TRIM(protocol) = ''
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE routing_rules
                    SET dest_cidr = '0.0.0.0/0'
                    WHERE dest_cidr IS NULL OR TRIM(dest_cidr) = ''
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE routing_rules
                    SET status = 'active'
                    WHERE status IS NULL OR TRIM(status) = ''
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE routing_rules
                    SET table_id = fwmark
                    WHERE table_id IS NULL OR table_id <= 0
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE routing_rules
                    SET table_name = ('atlas_pbr_' || lower(replace(replace(replace(rule_name, ' ', '_'), '-', '_'), '.', '_')))
                    WHERE table_name IS NULL OR TRIM(table_name) = ''
                    """
                )
            )
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_routing_rules_rule_name ON routing_rules (rule_name)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_routing_rules_fwmark ON routing_rules (fwmark)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_routing_rules_status ON routing_rules (status)"))

        if not audit_logs_table_exists:
            connection.execute(
                text(
                    """
                    CREATE TABLE audit_logs (
                        id INTEGER PRIMARY KEY,
                        admin_username VARCHAR(64),
                        action VARCHAR(128) NOT NULL,
                        resource_type VARCHAR(64),
                        resource_id VARCHAR(128),
                        ip_address VARCHAR(64),
                        success BOOLEAN NOT NULL DEFAULT 1,
                        details TEXT,
                        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_admin_username ON audit_logs (admin_username)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_resource_type ON audit_logs (resource_type)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs (created_at)"))
