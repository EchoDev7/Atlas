# Atlas — OpenVPN Core Logic
# Phase 2: OpenVPN management with mock support for development

import subprocess
import os
import platform
import logging
import time
import shutil
import asyncio
import threading
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterator
from fastapi import HTTPException
from datetime import datetime
import qrcode
import io
import base64
from urllib.parse import urlparse
from sqlalchemy import text

from backend.core.pki import PKIManager
from backend.services.protocols.base_vpn_service import BaseVPNService

logger = logging.getLogger(__name__)

# Detect if running on Linux (production) or Mac/Windows (development)
IS_LINUX = platform.system() == "Linux"


class OpenVPNConfig:
    """
    OpenVPN configuration paths following Ubuntu standard locations.
    Based on official OpenVPN documentation.
    """
    # Standard Ubuntu/Debian paths for openvpn-server@server service.
    OPENVPN_DIR = Path("/etc/openvpn")
    OPENVPN_SERVER_DIR = OPENVPN_DIR / "server"
    EASYRSA_DIR = OPENVPN_SERVER_DIR
    PKI_DIR = OPENVPN_SERVER_DIR / "pki"
    
    # Server configuration
    SERVER_CONF = OPENVPN_SERVER_DIR / "server.conf"
    LEGACY_SERVER_CONF = OPENVPN_DIR / "server.conf"
    ENFORCEMENT_HOOK = OPENVPN_SERVER_DIR / "atlas_enforcement_hook.py"
    AUTH_USER_PASS_SCRIPT = OPENVPN_SERVER_DIR / "atlas_auth_user_pass.py"
    STATUS_LOG = Path("/run/openvpn-server/status-server.log")
    
    # PKI paths (Easy-RSA 3 standard structure)
    CA_CERT = PKI_DIR / "ca.crt"
    SERVER_CERT = PKI_DIR / "issued" / "server.crt"
    SERVER_KEY = PKI_DIR / "private" / "server.key"
    DH_PARAMS = PKI_DIR / "dh.pem"
    TA_KEY = OPENVPN_SERVER_DIR / "ta.key"
    PKI_CRL = PKI_DIR / "crl.pem"
    CRL_FILE = OPENVPN_SERVER_DIR / "crl.pem"
    
    # Client certificates directory
    CLIENT_CERTS_DIR = PKI_DIR / "issued"
    CLIENT_KEYS_DIR = PKI_DIR / "private"
    
    # Client configs output directory
    CLIENT_CONFIGS_DIR = Path("/etc/openvpn/client-configs")
    
    # Service name
    SERVICE_NAME = "openvpn-server@server"
    SERVICE_CANDIDATES = ("openvpn-server@server", "openvpn@server")


class MockOpenVPNResponse:
    """Mock responses for development environment"""
    
    @staticmethod
    def easyrsa_build_client(client_name: str) -> str:
        return f"""
Note: using Easy-RSA configuration from: /etc/openvpn/easy-rsa/vars
Using SSL: openssl OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

Notice
------
Keypair and certificate request completed. Your files are:
req: /etc/openvpn/easy-rsa/pki/reqs/{client_name}.req
key: /etc/openvpn/easy-rsa/pki/private/{client_name}.key

Notice
------
Certificate created at: /etc/openvpn/easy-rsa/pki/issued/{client_name}.crt
"""
    
    @staticmethod
    def easyrsa_revoke(client_name: str) -> str:
        return f"""
Note: using Easy-RSA configuration from: /etc/openvpn/easy-rsa/vars
Using SSL: openssl OpenSSL 3.0.2 15 Mar 2022

Please confirm you wish to revoke the certificate with the following subject:

subject=
    commonName                = {client_name}

Type the word 'yes' to continue, or any other input to abort.
  Continue with revocation: yes

Revoking Certificate {client_name}.
Data Base Updated

IMPORTANT!!!

Revocation was successful. You must run gen-crl and upload a CRL to your
infrastructure in order to prevent the revoked cert from being accepted.
"""
    
    @staticmethod
    def systemctl_status() -> str:
        return """
● openvpn-server@server.service - OpenVPN service for server
     Loaded: loaded (/lib/systemd/system/openvpn-server@.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2026-02-25 14:00:00 UTC; 1h ago
       Docs: man:openvpn(8)
             https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
   Main PID: 1234 (openvpn)
     Status: "Initialization Sequence Completed"
      Tasks: 1 (limit: 1137)
     Memory: 2.5M
        CPU: 123ms
     CGroup: /system.slice/system-openvpn\\x2dserver.slice/openvpn-server@server.service
             └─1234 /usr/sbin/openvpn --status /run/openvpn-server/status-server.log --status-version 2 --suppress-timestamps --config server.conf

Feb 25 14:00:00 atlas systemd[1]: Starting OpenVPN service for server...
Feb 25 14:00:00 atlas systemd[1]: Started OpenVPN service for server.
"""


def validate_openvpn_readiness(general_settings, openvpn_settings) -> List[str]:
    """
    Stage 1: The Gatekeeper - Granular validation of required fields.
    Returns list of human-readable missing field names.
    """
    missing = []
    
    # Absolute Requirements
    if not general_settings.server_address or not general_settings.server_address.strip():
        missing.append("Server IP/Domain")
    if not openvpn_settings.port:
        missing.append("Port")
    if not openvpn_settings.protocol or not openvpn_settings.protocol.strip():
        missing.append("Protocol")
    
    # Conditional Requirements
    if openvpn_settings.obfuscation_mode and openvpn_settings.obfuscation_mode != "standard":
        if not openvpn_settings.proxy_port:
            missing.append("Proxy Port (Required for HTTP Proxy)")
        if openvpn_settings.obfuscation_mode in ["http_proxy_basic", "http_proxy_advanced"] and (
            not openvpn_settings.proxy_address or not openvpn_settings.proxy_address.strip()
        ):
            missing.append("Proxy Address (Required for HTTP Proxy)")
    
    if openvpn_settings.tls_mode and openvpn_settings.tls_mode != "none":
        # TLS keys should exist - this is a logical check since actual file existence
        # would be checked during config generation
        pass
    
    return missing


def _safe_int(value, default=None):
    """Stage 2: The Safe Builder - Convert to int safely."""
    try:
        if value is None or (isinstance(value, str) and not value.strip()):
            return default
        return int(value)
    except (ValueError, TypeError):
        return default


class OpenVPNManager(BaseVPNService):
    """
    Core OpenVPN management logic.
    Follows official OpenVPN and Easy-RSA 3 documentation.
    Includes mock support for development on non-Linux systems.
    """
    
    def __init__(self):
        self.config = OpenVPNConfig()
        self.is_production = IS_LINUX
        self.protocol_name = "openvpn"
        self.service_name = self.config.SERVICE_NAME
        self.pki_manager = PKIManager(
            easyrsa_dir=self.config.EASYRSA_DIR,
            pki_dir=self.config.PKI_DIR,
            ca_cert_path=self.config.CA_CERT,
            ta_key_path=self.config.TA_KEY,
            pki_crl_path=self.config.PKI_CRL,
            openvpn_crl_path=self.config.CRL_FILE,
            client_certs_dir=self.config.CLIENT_CERTS_DIR,
            client_keys_dir=self.config.CLIENT_KEYS_DIR,
            is_production=self.is_production,
        )

        if self.is_production:
            self.service_name = self._resolve_service_name()
        
        if not self.is_production:
            logger.warning("Running in DEVELOPMENT mode - subprocess calls will be mocked")

    def _resolve_service_name(self) -> str:
        """Detect installed OpenVPN systemd unit name across distro variants."""
        # Prefer the actively running service first.
        for candidate in self.config.SERVICE_CANDIDATES:
            success, _, _ = self._run_command(["systemctl", "is-active", "--quiet", candidate], check=False)
            if success:
                return candidate

        # Then prefer enabled units.
        for candidate in self.config.SERVICE_CANDIDATES:
            success, _, _ = self._run_command(["systemctl", "is-enabled", "--quiet", candidate], check=False)
            if success:
                return candidate

        # Finally, fall back to whichever unit exists on disk.
        for candidate in self.config.SERVICE_CANDIDATES:
            success, _, _ = self._run_command(["systemctl", "cat", candidate], check=False)
            if success:
                return candidate
        logger.warning(
            "OpenVPN service unit auto-detection failed; using default %s",
            self.config.SERVICE_NAME,
        )
        return self.config.SERVICE_NAME

    def _get_server_conf_paths(self) -> Tuple[Path, Path]:
        """Return (primary, compatibility_copy) server.conf paths."""
        if self.service_name == "openvpn@server":
            return self.config.LEGACY_SERVER_CONF, self.config.SERVER_CONF
        return self.config.SERVER_CONF, self.config.LEGACY_SERVER_CONF

    def _get_management_socket_target(self) -> Tuple[str, int]:
        """Resolve OpenVPN management interface host/port from runtime settings."""
        host = "127.0.0.1"
        # Operational constraint: production OpenVPN management interface is pinned to 5555.
        return host, 5555

    def _send_management_command(self, command: str, timeout: float = 3.0) -> Tuple[bool, str]:
        """Send a command to OpenVPN management interface and return raw response."""
        host, port = self._get_management_socket_target()
        command = (command or "").strip()
        if not command:
            return False, "Missing management command"

        def _is_completion_marker(payload: str) -> bool:
            return (
                "\nEND" in payload
                or "END\n" in payload
                or payload.endswith("END")
                or "SUCCESS:" in payload
                or "ERROR:" in payload
                or "OpenVPN Version" in payload
            )

        async def _send_with_asyncio() -> Tuple[bool, str]:
            started_at = time.monotonic()
            logger.info(
                "OpenVPN management command start command=%s target=%s:%s timeout=%.2fs",
                command,
                host,
                port,
                timeout,
            )

            writer: Optional[asyncio.StreamWriter] = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )

                writer.write(f"{command}\n".encode())
                await asyncio.wait_for(writer.drain(), timeout=timeout)

                response_chunks: List[str] = []
                response_termination = "loop_exhausted"
                while True:
                    try:
                        data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
                    except asyncio.TimeoutError:
                        response_termination = "socket_timeout"
                        break

                    if not data:
                        response_termination = "socket_closed"
                        break

                    text = data.decode(errors="ignore")
                    response_chunks.append(text)
                    merged = "".join(response_chunks)
                    if _is_completion_marker(merged):
                        response_termination = "completion_marker"
                        break

                response_text = "".join(response_chunks).strip()
                duration_ms = int((time.monotonic() - started_at) * 1000)
                logger.info(
                    (
                        "OpenVPN management command done command=%s target=%s:%s duration_ms=%s "
                        "response_chunks=%s response_termination=%s response_len=%s"
                    ),
                    command,
                    host,
                    port,
                    duration_ms,
                    len(response_chunks),
                    response_termination,
                    len(response_text),
                )
                return True, response_text

            except asyncio.TimeoutError:
                duration_ms = int((time.monotonic() - started_at) * 1000)
                logger.warning(
                    "OpenVPN management command timeout command=%s target=%s:%s duration_ms=%s",
                    command,
                    host,
                    port,
                    duration_ms,
                )
                return False, f"Management interface timeout on {host}:{port}"
            except OSError as exc:
                duration_ms = int((time.monotonic() - started_at) * 1000)
                logger.warning(
                    "OpenVPN management command os_error command=%s target=%s:%s duration_ms=%s error=%s",
                    command,
                    host,
                    port,
                    duration_ms,
                    exc,
                )
                return False, f"Management interface unavailable on {host}:{port}: {exc}"
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                    except Exception:
                        pass

        def _run_in_thread() -> Tuple[bool, str]:
            result: Dict[str, Tuple[bool, str]] = {}
            error: Dict[str, Exception] = {}

            def _thread_runner() -> None:
                try:
                    result["value"] = asyncio.run(_send_with_asyncio())
                except Exception as exc:  # pragma: no cover - defensive thread boundary
                    error["value"] = exc

            worker = threading.Thread(target=_thread_runner, daemon=True, name="atlas-openvpn-mgmt")
            worker.start()
            worker.join(timeout + 1.5)
            if worker.is_alive():
                logger.warning(
                    "OpenVPN management command thread_timeout command=%s target=%s:%s timeout=%.2fs",
                    command,
                    host,
                    port,
                    timeout,
                )
                return False, f"Management interface timeout on {host}:{port}"
            if "value" in error:
                logger.warning(
                    "OpenVPN management command thread_error command=%s target=%s:%s error=%s",
                    command,
                    host,
                    port,
                    error["value"],
                )
                return False, f"Management interface unavailable on {host}:{port}: {error['value']}"
            return result.get("value", (False, f"Management interface timeout on {host}:{port}"))

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop and running_loop.is_running():
            return _run_in_thread()
        return asyncio.run(_send_with_asyncio())

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Return active OpenVPN sessions from management interface (status 3)."""
        def _split_status_fields(line: str) -> List[str]:
            return [segment.strip() for segment in re.split(r"[\t,]", line)]

        def _is_header_client_list(parts: List[str]) -> bool:
            return len(parts) >= 2 and parts[0] == "HEADER" and parts[1] == "CLIENT_LIST"

        def _is_client_list(parts: List[str]) -> bool:
            return len(parts) >= 1 and parts[0] == "CLIENT_LIST"

        def _normalize_header_name(value: str) -> str:
            return "".join(ch.lower() if ch.isalnum() else "_" for ch in str(value or "").strip()).strip("_")

        def _extract_client_metrics(parts: List[str], header_map: Optional[Dict[str, int]] = None) -> Tuple[str, int, int, Optional[str], Optional[str]]:
            common_name = parts[1] if len(parts) > 1 else ""
            real_address = parts[2] if len(parts) > 2 else None
            virtual_address = parts[3] if len(parts) > 3 else None

            bytes_received: int
            bytes_sent: int
            connected_since: Optional[str]

            if header_map:
                recv_idx = header_map.get("bytes_received")
                sent_idx = header_map.get("bytes_sent")
                connected_idx = header_map.get("connected_since")
                bytes_received = _safe_int(parts[recv_idx], 0) if recv_idx is not None and recv_idx < len(parts) else 0
                bytes_sent = _safe_int(parts[sent_idx], 0) if sent_idx is not None and sent_idx < len(parts) else 0
                connected_since = parts[connected_idx] if connected_idx is not None and connected_idx < len(parts) else None
                return common_name, bytes_received, bytes_sent, connected_since, real_address, virtual_address

            # Fallback for status formats without a header:
            # - status v2 CLIENT_LIST: bytes at indexes 4,5
            # - status v3 CLIENT_LIST: bytes at indexes 5,6 (index 4 = virtual IPv6)
            recv_idx, sent_idx = 4, 5
            if len(parts) > 6 and not str(parts[4]).isdigit() and str(parts[5]).isdigit():
                recv_idx, sent_idx = 5, 6

            bytes_received = _safe_int(parts[recv_idx], 0) if recv_idx < len(parts) else 0
            bytes_sent = _safe_int(parts[sent_idx], 0) if sent_idx < len(parts) else 0
            connected_since = parts[7] if len(parts) > 7 else None
            return common_name, bytes_received, bytes_sent, connected_since, real_address, virtual_address

        def _parse_status_log_sessions() -> List[Dict[str, Any]]:
            sessions: List[Dict[str, Any]] = []
            status_path = self.config.STATUS_LOG
            if not status_path.exists():
                logger.info("OpenVPN status log fallback path missing status_path=%s", status_path)
                return sessions

            try:
                logger.info("OpenVPN status log fallback parse start status_path=%s", status_path)
                client_header_map: Dict[str, int] = {}
                for raw_line in status_path.read_text(errors="ignore").splitlines():
                    line = raw_line.strip()
                    parts = _split_status_fields(line)
                    if _is_header_client_list(parts):
                        header_columns = parts[2:]
                        client_header_map = {
                            _normalize_header_name(name): index + 1
                            for index, name in enumerate(header_columns)
                        }
                        continue

                    if not _is_client_list(parts):
                        continue

                    if len(parts) < 6:
                        continue

                    common_name, bytes_received, bytes_sent, connected_since, real_address, virtual_address = _extract_client_metrics(
                        parts,
                        client_header_map or None,
                    )
                    if not common_name or common_name.upper() == "UNDEF":
                        continue

                    sessions.append(
                        {
                            "username": common_name,
                            "real_address": real_address,
                            "virtual_address": virtual_address,
                            "bytes_received": bytes_received,
                            "bytes_sent": bytes_sent,
                            "connected_since": connected_since,
                            "raw": line,
                        }
                    )
            except Exception as exc:
                logger.warning("Failed to parse OpenVPN status log sessions: %s", exc)

            logger.info(
                "OpenVPN status log fallback parse done status_path=%s sessions=%s",
                status_path,
                len(sessions),
            )

            return sessions

        success, response = self._send_management_command("status 3")
        if not success:
            logger.warning("OpenVPN management status query failed: %s", response)
            logger.info("OpenVPN active sessions source=status_log reason=management_query_failed")
            return _parse_status_log_sessions()

        sessions: List[Dict[str, Any]] = []
        client_header_map: Dict[str, int] = {}
        for raw_line in response.splitlines():
            line = raw_line.strip()
            parts = _split_status_fields(line)
            if _is_header_client_list(parts):
                header_columns = parts[2:]
                client_header_map = {
                    _normalize_header_name(name): index + 1
                    for index, name in enumerate(header_columns)
                }
                continue

            if not _is_client_list(parts):
                continue

            if len(parts) < 6:
                continue

            common_name, bytes_received, bytes_sent, connected_since, real_address, virtual_address = _extract_client_metrics(
                parts,
                client_header_map or None,
            )
            if not common_name or common_name.upper() == "UNDEF":
                continue

            sessions.append(
                {
                    "username": common_name,
                    "real_address": real_address,
                    "virtual_address": virtual_address,
                    "bytes_received": bytes_received,
                    "bytes_sent": bytes_sent,
                    "connected_since": connected_since,
                    "raw": line,
                }
            )

        if sessions:
            logger.info(
                "OpenVPN active sessions source=management status_format=status_3 sessions=%s",
                len(sessions),
            )
            return sessions

        logger.info("OpenVPN active sessions source=status_log reason=management_empty_or_unparsed")
        return _parse_status_log_sessions()

    def kill_user(self, username: str) -> Dict[str, Any]:
        """Disconnect a user immediately via management `kill <common_name>` command."""
        username = (username or "").strip()
        if not username:
            return {"success": False, "message": "Missing username", "protocol": self.protocol_name}

        success, response = self._send_management_command(f"kill {username}")
        if not success:
            return {"success": False, "message": response, "protocol": self.protocol_name}

        is_ok = "ERROR:" not in response
        return {
            "success": is_ok,
            "message": response or f"Kill command executed for {username}",
            "protocol": self.protocol_name,
            "username": username,
        }

    def get_traffic_usage(self, username: Optional[str] = None) -> Dict[str, Any]:
        """Aggregate traffic usage from live management sessions."""
        sessions = self.get_active_sessions()
        usage_by_user: Dict[str, Dict[str, int]] = {}

        for session in sessions:
            key = session.get("username")
            if not key:
                continue
            usage = usage_by_user.setdefault(key, {"bytes_received": 0, "bytes_sent": 0, "total_bytes": 0})
            usage["bytes_received"] += _safe_int(session.get("bytes_received"), 0)
            usage["bytes_sent"] += _safe_int(session.get("bytes_sent"), 0)
            usage["total_bytes"] = usage["bytes_received"] + usage["bytes_sent"]

        if username:
            scoped = usage_by_user.get(username, {"bytes_received": 0, "bytes_sent": 0, "total_bytes": 0})
            return {"protocol": self.protocol_name, "username": username, "usage": scoped}

        return {"protocol": self.protocol_name, "users": usage_by_user, "session_count": len(sessions)}

    def _load_runtime_settings(self) -> Tuple[Dict[str, any], Dict[str, any]]:
        """Load persisted OpenVPN and General settings from SQLite."""
        openvpn_defaults: Dict[str, any] = {
            "port": 1194,
            "protocol": "udp",
            "data_ciphers": "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "auth_digest": "SHA256",
            "tls_version_min": "1.2",
            "obfuscation_mode": "standard",
            "proxy_server": None,
            "proxy_address": None,
            "proxy_port": 8080,
            "spoofed_host": "speedtest.net",
            "socks_server": None,
            "socks_port": None,
            "stunnel_port": 443,
            "sni_domain": None,
            "cdn_domain": None,
            "ws_path": "/stream",
            "ws_port": 8080,
            "device_type": "tun",
            "topology": "subnet",
            "ipv4_network": "10.8.0.0",
            "ipv4_netmask": "255.255.255.0",
            "ipv4_pool": "10.8.0.0 255.255.255.0",
            "ipv6_network": None,
            "ipv6_prefix": None,
            "ipv6_pool": None,
            "max_clients": 100,
            "client_to_client": False,
            "redirect_gateway": True,
            "primary_dns": "8.8.8.8",
            "secondary_dns": "1.1.1.1",
            "block_outside_dns": False,
            "push_custom_routes": None,
            "tls_mode": "tls-crypt",
            "reneg_sec": 3600,
            "tun_mtu": 1500,
            "mssfix": 1450,
            "sndbuf": 393216,
            "rcvbuf": 393216,
            "fast_io": False,
            "tcp_nodelay": False,
            "explicit_exit_notify": 1,
            "keepalive_ping": 10,
            "keepalive_timeout": 120,
            "inactive_timeout": 300,
            "management_port": 5555,
            "verbosity": 3,
            "enable_auth_nocache": True,
            "enable_dns_leak_protection": True,
            "custom_directives": None,
            "advanced_client_push": None,
            "custom_ios": None,
            "custom_android": None,
            "custom_windows": None,
            "custom_mac": None,
        }
        general_defaults: Dict[str, any] = {
            "server_address": "",
            "public_ipv4_address": None,
            "public_ipv6_address": None,
            "global_ipv6_support": False,
        }

        try:
            from backend.database import SessionLocal

            def _load_first_row_values(db, table_name: str, candidate_columns: List[str]) -> Dict[str, Any]:
                table_exists = db.execute(
                    text(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name=:table_name"
                    ),
                    {"table_name": table_name},
                ).fetchone()
                if not table_exists:
                    return {}

                table_info = db.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
                existing_columns = {row[1] for row in table_info}
                selected_columns = [column for column in candidate_columns if column in existing_columns]
                if not selected_columns:
                    return {}

                select_sql = (
                    f"SELECT {', '.join(selected_columns)} "
                    f"FROM {table_name} ORDER BY id ASC LIMIT 1"
                )
                row = db.execute(text(select_sql)).mappings().first()
                return dict(row) if row else {}

            db = SessionLocal()
            try:
                openvpn_values = _load_first_row_values(
                    db,
                    "openvpn_settings",
                    list(openvpn_defaults.keys()),
                )
                for key, value in openvpn_values.items():
                    if key in openvpn_defaults and value is not None:
                        openvpn_defaults[key] = value

                general_values = _load_first_row_values(
                    db,
                    "general_settings",
                    ["server_address", "public_ipv4_address", "public_ipv6_address", "global_ipv6_support"],
                )
                if general_values:
                    persisted_server_address = str(general_values.get("server_address") or "").strip()
                    persisted_ipv4 = str(general_values.get("public_ipv4_address") or "").strip()
                    persisted_ipv6 = str(general_values.get("public_ipv6_address") or "").strip()
                    general_defaults["server_address"] = (
                        persisted_server_address
                        or persisted_ipv4
                        or general_defaults["server_address"]
                    )
                    general_defaults["public_ipv4_address"] = persisted_ipv4 or None
                    general_defaults["public_ipv6_address"] = persisted_ipv6 or None
                    general_defaults["global_ipv6_support"] = bool(general_values.get("global_ipv6_support", False))
            finally:
                db.close()
        except Exception as exc:
            logger.warning("Failed to load runtime settings from database: %s", exc)

        return openvpn_defaults, general_defaults

    def _resolve_sqlite_db_path(self) -> str:
        """
        Resolve SQLite database file path for OpenVPN hook scripts.
        Returns path accessible to OpenVPN subprocess (not under /root due to ProtectHome=true).
        """
        openvpn_accessible_db = self.config.OPENVPN_SERVER_DIR / "atlas.db"
        
        if not self.is_production:
            return str(openvpn_accessible_db)
        
        try:
            from backend.config import settings
            
            source_db_candidates = [
                Path("/root/Atlas/data/atlas.db"),
                Path("/root/Atlas/backend/atlas.db"),
            ]
            
            db_url = str(getattr(settings, "DATABASE_URL", "") or "")
            if db_url.startswith("sqlite:///"):
                source_db_candidates.insert(0, Path(db_url.replace("sqlite:///", "", 1)))
            
            source_db_path = None
            for candidate in source_db_candidates:
                if candidate.exists():
                    source_db_path = candidate
                    break
            
            if source_db_path:
                import shutil
                openvpn_accessible_db.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_db_path, openvpn_accessible_db)
                openvpn_accessible_db.chmod(0o640)
                logger.info(f"Synced DB from {source_db_path} to {openvpn_accessible_db}")
            else:
                logger.warning("No source DB found to sync to OpenVPN-accessible location")
            
            return str(openvpn_accessible_db)
        except Exception as exc:
            logger.warning("Failed to sync DB to OpenVPN-accessible location: %s", exc)
            return str(openvpn_accessible_db)

    def sync_auth_database_snapshot(self) -> Dict[str, Any]:
        """Synchronize auth assets (DB snapshot + scripts) used by OpenVPN hooks."""
        auth_script_path: Optional[Path] = None
        enforcement_hook_path: Optional[Path] = None

        if self.is_production:
            try:
                auth_script_path = self._ensure_auth_user_pass_script()
            except Exception as exc:
                logger.warning("Failed to refresh OpenVPN auth script: %s", exc)

            try:
                enforcement_hook_path = self._ensure_realtime_enforcement_hook()
            except Exception as exc:
                logger.warning("Failed to refresh OpenVPN enforcement hook: %s", exc)

        target_path = Path(self._resolve_sqlite_db_path())
        exists = target_path.exists()
        if not exists:
            return {
                "success": False,
                "message": f"OpenVPN auth DB snapshot not found at {target_path}",
                "path": str(target_path),
                "auth_script": str(auth_script_path) if auth_script_path else None,
                "enforcement_hook": str(enforcement_hook_path) if enforcement_hook_path else None,
                "protocol": self.protocol_name,
            }

        return {
            "success": True,
            "message": "OpenVPN auth assets synchronized",
            "path": str(target_path),
            "auth_script": str(auth_script_path) if auth_script_path else None,
            "enforcement_hook": str(enforcement_hook_path) if enforcement_hook_path else None,
            "protocol": self.protocol_name,
        }

    def _ensure_auth_user_pass_script(self) -> Path:
        """Ensure OpenVPN auth-user-pass verifier script exists in server config dir."""
        auth_script_path = self.config.AUTH_USER_PASS_SCRIPT
        if not self.is_production:
            return auth_script_path

        script_candidates = [
            Path("/root/Atlas/scripts/openvpn_auth_user_pass.py"),
            Path(__file__).resolve().parents[2] / "scripts" / "openvpn_auth_user_pass.py",
        ]

        auth_script_content: Optional[str] = None
        for script_source in script_candidates:
            try:
                if script_source.exists():
                    auth_script_content = script_source.read_text()
                    break
            except Exception as exc:
                logger.warning("Failed to read auth verifier source %s: %s", script_source, exc)

        if not auth_script_content:
            auth_script_content = self._build_auth_user_pass_script_content()

        auth_script_path.parent.mkdir(parents=True, exist_ok=True)
        auth_script_path.write_text(auth_script_content)
        try:
            os.chmod(auth_script_path, 0o750)
        except Exception as exc:
            logger.warning("Failed to chmod auth verifier script %s: %s", auth_script_path, exc)

        return auth_script_path

    @staticmethod
    def _build_auth_user_pass_script_content() -> str:
        """Build fallback auth-user-pass-verify script if repository script is unavailable."""
        return '''#!/usr/bin/env python3
import base64
import hashlib
import hmac
import os
import sqlite3
import sys
from datetime import datetime

try:
    import bcrypt
except Exception:
    bcrypt = None


ATLAS_DB_PATH = (os.environ.get("ATLAS_DB_PATH") or "/etc/openvpn/server/atlas.db").strip()
AUTH_LOG_PATH = "/var/log/atlas_auth.log"
PBKDF2_SCHEME = "pbkdf2_sha256"
BYTES_PER_GB = 1024 ** 3


def _safe_int(value, default=0):
    try:
        if value in (None, ""):
            return default
        return int(float(str(value)))
    except Exception:
        return default


def _safe_float(value, default=None):
    try:
        if value in (None, ""):
            return default
        return float(str(value))
    except Exception:
        return default


def _effective_traffic_limit_bytes(user_row):
    explicit_limit = user_row["traffic_limit_bytes"]
    if explicit_limit not in (None, ""):
        return max(0, _safe_int(explicit_limit, 0))
    data_limit_gb = _safe_float(user_row["data_limit_gb"], None)
    if data_limit_gb is None:
        return None
    return max(0, int(data_limit_gb * BYTES_PER_GB))


def _effective_usage_bytes(user_row):
    traffic_used = max(0, _safe_int(user_row["traffic_used_bytes"], 0))
    transport_total = max(0, _safe_int(user_row["total_bytes_sent"], 0)) + max(0, _safe_int(user_row["total_bytes_received"], 0))
    return max(traffic_used, transport_total)


def _effective_max_connections(user_row):
    canonical = _safe_int(user_row["max_concurrent_connections"], 0)
    legacy = _safe_int(user_row["max_devices"], 1)
    return max(1, canonical or legacy or 1)


def _parse_db_datetime(value):
    if value in (None, ""):
        return None

    text = str(value).strip()
    if not text:
        return None

    normalized = text.replace("Z", "+00:00").replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(normalized)
        return parsed.replace(tzinfo=None)
    except ValueError:
        return None


def _is_user_active(user_row):
    now = datetime.utcnow()
    access_start_at = _parse_db_datetime(user_row["access_start_at"])
    access_expires_at = _parse_db_datetime(user_row["access_expires_at"])
    expiry_date = _parse_db_datetime(user_row["expiry_date"])
    effective_expiry = access_expires_at or expiry_date

    if access_start_at and now < access_start_at:
        return False

    if not bool(user_row["is_enabled"]):
        return False

    if effective_expiry and now >= effective_expiry:
        return False

    limit_bytes = _effective_traffic_limit_bytes(user_row)
    if limit_bytes is not None and _effective_usage_bytes(user_row) >= limit_bytes:
        return False

    current_connections = max(0, _safe_int(user_row["current_connections"], 0))
    if current_connections >= _effective_max_connections(user_row):
        return False

    return True


def _verify_password(plain_password, hashed_password):
    if not hashed_password:
        return False

    if hashed_password.startswith(f"{PBKDF2_SCHEME}$"):
        try:
            _, iterations_raw, salt_b64, expected_b64 = hashed_password.split("$", 3)
            iterations = int(iterations_raw)
            salt = base64.b64decode(salt_b64.encode("ascii"))
            digest = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
            calculated_b64 = base64.b64encode(digest).decode("ascii")
            return hmac.compare_digest(calculated_b64, expected_b64)
        except Exception:
            return False

    if hashed_password.startswith("$2"):
        if bcrypt is None:
            return False
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception:
            return False

    return False


def _log_auth_failure(username, reason):
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    safe_username = (username or "").strip() or "<unknown>"
    message = f"{timestamp} auth_failed user={safe_username} reason={reason}\\n"
    try:
        with open(AUTH_LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(message)
    except Exception as exc:
        print(f"Failed to write auth debug log: {exc}", file=sys.stderr)


def _verify_credentials(username, password):
    conn = None
    try:
        conn = sqlite3.connect(ATLAS_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")

        user = conn.execute(
            (
                "SELECT username, password, is_enabled, "
                "access_start_at, access_expires_at, expiry_date, "
                "data_limit_gb, traffic_limit_bytes, traffic_used_bytes, "
                "total_bytes_sent, total_bytes_received, "
                "current_connections, max_concurrent_connections, max_devices "
                "FROM vpn_users WHERE username = ?"
            ),
            (username,),
        ).fetchone()

        if not user:
            return False, "user_not_found"

        if not _is_user_active(user):
            return False, "user_not_active"

        if not _verify_password(password, str(user["password"] or "")):
            return False, "password_mismatch"

        return True, "ok"
    except Exception as exc:
        return False, f"exception:{exc}"
    finally:
        if conn is not None:
            conn.close()


def main():
    if len(sys.argv) < 2:
        _log_auth_failure("", "missing_credentials_file_argument")
        raise SystemExit(1)

    credentials_file = sys.argv[1]
    try:
        with open(credentials_file, "r", encoding="utf-8") as file_handle:
            lines = file_handle.readlines()
            if len(lines) < 2:
                _log_auth_failure("", "invalid_credentials_file_format")
                raise SystemExit(1)
            username = lines[0].strip()
            password = lines[1].strip()

        is_valid, reason = _verify_credentials(username, password)
        if is_valid:
            raise SystemExit(0)

        _log_auth_failure(username, reason)
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as exc:
        _log_auth_failure("", f"main_exception:{exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
'''

    def _build_realtime_enforcement_hook_content(self) -> str:
        """Build Python hook script used by OpenVPN client-connect/client-disconnect."""
        return '''#!/usr/bin/env python3
import os
import sqlite3
import sys
from datetime import datetime

BYTES_PER_GB = 1024 ** 3


def _safe_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value, default=None):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _get_effective_limit_bytes(row):
    if row["traffic_limit_bytes"] is not None:
        return _safe_int(row["traffic_limit_bytes"], None)
    data_limit_gb = _safe_float(row["data_limit_gb"], None)
    if data_limit_gb is None:
        return None
    return int(data_limit_gb * BYTES_PER_GB)


def _get_effective_expiry(row):
    return _parse_dt(row["access_expires_at"]) or _parse_dt(row["expiry_date"])


def _get_effective_max_connections(row):
    canonical = _safe_int(row["max_concurrent_connections"], 0)
    legacy = _safe_int(row["max_devices"], 1)
    return max(1, canonical or legacy or 1)


def _get_current_usage_bytes(row):
    traffic_used = _safe_int(row["traffic_used_bytes"], 0)
    transport = _safe_int(row["total_bytes_sent"], 0) + _safe_int(row["total_bytes_received"], 0)
    return max(traffic_used, transport)


def _connect_db(path):
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def _reject(message):
    print(f"[ATLAS ENFORCEMENT] {message}", file=sys.stderr)
    return 1


def _handle_connect(conn, common_name):
    now = datetime.utcnow()
    conn.execute("BEGIN IMMEDIATE")

    row = conn.execute(
        (
            "SELECT id, is_enabled, data_limit_gb, traffic_limit_bytes, traffic_used_bytes, "
            "expiry_date, access_start_at, access_expires_at, "
            "max_devices, max_concurrent_connections, current_connections, "
            "total_bytes_sent, total_bytes_received "
            "FROM vpn_users "
            "WHERE username = ?"
        ),
        (common_name,),
    ).fetchone()

    if row is None:
        conn.execute("ROLLBACK")
        return _reject(f"Connection denied for unknown user '{common_name}'")

    if not bool(row["is_enabled"]):
        conn.execute("ROLLBACK")
        return _reject(f"Connection denied for disabled user '{common_name}'")

    access_start_at = _parse_dt(row["access_start_at"])
    if access_start_at and now < access_start_at:
        conn.execute("ROLLBACK")
        return _reject(f"Connection denied: account '{common_name}' is not active yet")

    access_expires_at = _get_effective_expiry(row)
    if access_expires_at and now >= access_expires_at:
        conn.execute("ROLLBACK")
        return _reject(f"Connection denied: account '{common_name}' has expired")

    limit_bytes = _get_effective_limit_bytes(row)
    used_bytes = _get_current_usage_bytes(row)
    if limit_bytes is not None and used_bytes >= limit_bytes:
        conn.execute("ROLLBACK")
        return _reject(
            f"Connection denied: traffic limit exceeded for '{common_name}' ({used_bytes} / {limit_bytes})"
        )

    current_connections = max(0, _safe_int(row["current_connections"], 0))
    max_connections = _get_effective_max_connections(row)
    if current_connections >= max_connections:
        conn.execute(
            "UPDATE vpn_users SET is_connection_limit_exceeded = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (row["id"],),
        )
        conn.execute("COMMIT")
        return _reject(
            f"Connection denied: concurrent connection limit reached for '{common_name}' ({current_connections} / {max_connections})"
        )

    conn.execute(
        (
            "UPDATE vpn_users "
            "SET current_connections = ?, "
            "is_connection_limit_exceeded = 0, "
            "updated_at = CURRENT_TIMESTAMP, "
            "last_connected_at = CURRENT_TIMESTAMP "
            "WHERE id = ?"
        ),
        (current_connections + 1, row["id"]),
    )
    conn.execute("COMMIT")
    return 0


def _handle_disconnect(conn, common_name):
    bytes_sent = max(0, _safe_int(os.environ.get("bytes_sent"), 0))
    bytes_received = max(0, _safe_int(os.environ.get("bytes_received"), 0))
    now_iso = datetime.utcnow().isoformat()
    session_total = bytes_sent + bytes_received

    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute(
        (
            "SELECT id, current_connections, traffic_used_bytes, total_bytes_sent, total_bytes_received, "
            "data_limit_gb, traffic_limit_bytes, max_concurrent_connections, max_devices "
            "FROM vpn_users "
            "WHERE username = ?"
        ),
        (common_name,),
    ).fetchone()

    if row is None:
        conn.execute("ROLLBACK")
        return 0

    current_connections = max(0, _safe_int(row["current_connections"], 0) - 1)
    total_sent = max(0, _safe_int(row["total_bytes_sent"], 0) + bytes_sent)
    total_received = max(0, _safe_int(row["total_bytes_received"], 0) + bytes_received)
    traffic_used = max(0, _safe_int(row["traffic_used_bytes"], 0) + session_total)

    fake_row = {
        "traffic_limit_bytes": row["traffic_limit_bytes"],
        "data_limit_gb": row["data_limit_gb"],
    }
    limit_bytes = _get_effective_limit_bytes(fake_row)
    effective_usage = max(traffic_used, total_sent + total_received)
    is_data_limit_exceeded = bool(limit_bytes is not None and effective_usage >= limit_bytes)

    max_connections = max(1, _safe_int(row["max_concurrent_connections"], 0) or _safe_int(row["max_devices"], 1))
    is_connection_limit_exceeded = current_connections > max_connections

    conn.execute(
        (
            "UPDATE vpn_users "
            "SET current_connections = ?, "
            "traffic_used_bytes = ?, "
            "total_bytes_sent = ?, "
            "total_bytes_received = ?, "
            "is_data_limit_exceeded = ?, "
            "is_connection_limit_exceeded = ?, "
            "last_disconnected_at = ?, "
            "updated_at = CURRENT_TIMESTAMP "
            "WHERE id = ?"
        ),
        (
            current_connections,
            traffic_used,
            total_sent,
            total_received,
            int(is_data_limit_exceeded),
            int(is_connection_limit_exceeded),
            now_iso,
            row["id"],
        ),
    )
    conn.execute("COMMIT")
    return 0


def main():
    mode = (sys.argv[1] if len(sys.argv) > 1 else "").strip().lower()
    common_name = (os.environ.get("common_name") or "").strip()
    db_path = (os.environ.get("ATLAS_DB_PATH") or "").strip()

    if mode not in {"connect", "disconnect"}:
        return _reject("Invalid hook mode")

    if not common_name:
        return _reject("Missing common_name") if mode == "connect" else 0

    if not db_path:
        return _reject("Missing ATLAS_DB_PATH") if mode == "connect" else 0

    try:
        conn = _connect_db(db_path)
    except Exception as exc:
        return _reject(f"Failed to open database: {exc}") if mode == "connect" else 0

    try:
        if mode == "connect":
            return _handle_connect(conn, common_name)
        return _handle_disconnect(conn, common_name)
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return _reject(f"Hook execution failed: {exc}") if mode == "connect" else 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
'''

    def _ensure_realtime_enforcement_hook(self) -> Path:
        """Ensure OpenVPN real-time enforcement hook script exists on disk."""
        hook_path = self.config.ENFORCEMENT_HOOK
        hook_content = self._build_realtime_enforcement_hook_content()

        if self.is_production:
            hook_path.parent.mkdir(parents=True, exist_ok=True)
            hook_path.write_text(hook_content)
            try:
                os.chmod(hook_path, 0o750)
            except Exception as exc:
                logger.warning("Failed to chmod enforcement hook script: %s", exc)

        return hook_path

    def _harden_sensitive_file_permissions(self) -> None:
        """Harden sensitive key material file permissions in production."""
        if not self.is_production:
            return

        sensitive_paths = [
            self.config.SERVER_KEY,
            self.config.TA_KEY,
        ]
        for path in sensitive_paths:
            try:
                if path.exists():
                    os.chmod(path, 0o600)
            except Exception as exc:
                logger.warning("Failed to chmod %s to 600: %s", path, exc)
    
    def _run_command(self, cmd: List[str], check: bool = True) -> Tuple[bool, str, str]:
        """
        Execute system command with mock support for development.
        
        Args:
            cmd: Command and arguments as list
            check: Raise exception on non-zero exit code
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            if not cmd:
                return False, "", "No command provided"

            if not self.is_production:
                # Mock responses for development
                logger.info(f"[MOCK] Would execute: {' '.join(cmd)}")
                
                if "easyrsa" in cmd[0]:
                    if "build-client-full" in cmd:
                        client_name = cmd[2] if len(cmd) > 2 else "client"
                        return True, MockOpenVPNResponse.easyrsa_build_client(client_name), ""
                    elif "revoke" in cmd:
                        client_name = cmd[2] if len(cmd) > 2 else "client"
                        return True, MockOpenVPNResponse.easyrsa_revoke(client_name), ""
                    elif "gen-crl" in cmd:
                        return True, "CRL generated successfully", ""
                
                elif "systemctl" in cmd[0]:
                    if "status" in cmd:
                        return True, MockOpenVPNResponse.systemctl_status(), ""
                    else:
                        action = cmd[1] if len(cmd) > 1 else "unknown"
                        return True, f"Service {action} completed successfully", ""
                
                return True, f"Mock command executed: {' '.join(cmd)}", ""
            
            if not self._command_exists(cmd[0]):
                warning_message = f"System command not found: {cmd[0]}"
                logger.warning(warning_message)
                return False, "", warning_message

            # Production: execute real command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return result.returncode == 0, result.stdout, result.stderr
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}\nError: {e.stderr}")
            return False, e.stdout, e.stderr
        except FileNotFoundError as e:
            logger.warning(f"Command not found: {cmd[0]}")
            return False, "", str(e)
        except Exception as e:
            logger.error(f"Unexpected error running command: {e}")
            return False, "", str(e)

    def _command_exists(self, command: str) -> bool:
        if not self.is_production:
            return True
        return shutil.which(command) is not None

    @staticmethod
    def _normalize_transport_protocol(protocol: str) -> str:
        normalized = (protocol or "udp").lower().strip()
        if normalized.startswith("tcp"):
            return "tcp"
        return "udp"

    def sync_firewall_for_transport_change(
        self,
        old_port: int,
        old_protocol: str,
        new_port: int,
        new_protocol: str,
    ) -> Dict[str, any]:
        """Apply UFW rule updates when OpenVPN transport changes."""
        old_proto = self._normalize_transport_protocol(old_protocol)
        new_proto = self._normalize_transport_protocol(new_protocol)

        if old_port == new_port and old_proto == new_proto:
            return {
                "success": True,
                "message": "Firewall rules unchanged",
                "is_mock": not self.is_production,
                "commands": [],
            }

        if self.is_production and not self._command_exists("ufw"):
            logger.warning("ufw is not installed. Skipping OpenVPN transport firewall sync.")
            return {
                "success": True,
                "message": "ufw not installed; skipped firewall sync",
                "is_mock": False,
                "commands": [],
            }

        commands: List[List[str]] = []
        allow_rule = ["ufw", "allow", f"{new_port}/{new_proto}"]
        commands.append(allow_rule)

        if old_port != new_port or old_proto != new_proto:
            commands.append(["ufw", "delete", "allow", f"{old_port}/{old_proto}"])

        if not self.is_production:
            for cmd in commands:
                logger.info(f"[MOCK] Would execute firewall command: {' '.join(cmd)}")
            return {
                "success": True,
                "message": "Firewall rules updated (mock)",
                "is_mock": True,
                "commands": [" ".join(cmd) for cmd in commands],
            }

        allow_success, _, allow_error = self._run_command(allow_rule, check=False)
        if not allow_success:
            return {
                "success": False,
                "message": f"Failed to allow new firewall rule: {allow_error}",
                "is_mock": False,
                "commands": [" ".join(allow_rule)],
            }

        old_rule_results: List[str] = []
        if len(commands) > 1:
            delete_cmd = commands[1]
            delete_success, _, delete_error = self._run_command(delete_cmd, check=False)
            if not delete_success:
                deny_cmd = ["ufw", "deny", f"{old_port}/{old_proto}"]
                deny_success, _, deny_error = self._run_command(deny_cmd, check=False)
                old_rule_results.append(" ".join(delete_cmd))
                old_rule_results.append(" ".join(deny_cmd))
                if not deny_success:
                    return {
                        "success": False,
                        "message": f"Failed to remove old firewall rule: {delete_error or deny_error}",
                        "is_mock": False,
                        "commands": [" ".join(allow_rule), *old_rule_results],
                    }
            else:
                old_rule_results.append(" ".join(delete_cmd))

        return {
            "success": True,
            "message": "Firewall rules updated",
            "is_mock": False,
            "commands": [" ".join(allow_rule), *old_rule_results],
        }

    def sync_system_general_settings(
        self,
        old_global_ipv6_support: bool,
        new_global_ipv6_support: bool,
        old_timezone: str,
        new_timezone: str,
        old_panel_https_port: Optional[int] = None,
        new_panel_https_port: Optional[int] = None,
        old_subscription_https_port: Optional[int] = None,
        new_subscription_https_port: Optional[int] = None,
    ) -> Dict[str, any]:
        """Apply OS-level sync for General settings changes."""
        commands: List[List[str]] = []

        normalized_old_timezone = (old_timezone or "").strip()
        normalized_new_timezone = (new_timezone or "").strip()
        if normalized_new_timezone and normalized_new_timezone != normalized_old_timezone:
            if self._command_exists("timedatectl"):
                commands.append(["timedatectl", "set-timezone", normalized_new_timezone])
            else:
                logger.warning("timedatectl is not installed. Skipping timezone sync.")

        port_sync_result = self.sync_https_firewall_ports(
            old_panel_port=old_panel_https_port,
            new_panel_port=new_panel_https_port,
            old_subscription_port=old_subscription_https_port,
            new_subscription_port=new_subscription_https_port,
        )
        if not port_sync_result.get("success"):
            return port_sync_result

        if not commands:
            return {
                "success": True,
                "message": "General system settings unchanged",
                "is_mock": not self.is_production,
                "commands": port_sync_result.get("commands", []),
            }

        if not self.is_production:
            for cmd in commands:
                logger.info(f"[MOCK] Would execute general system command: {' '.join(cmd)}")
            return {
                "success": True,
                "message": "General system settings updated (mock)",
                "is_mock": True,
                "commands": [*port_sync_result.get("commands", []), *[" ".join(cmd) for cmd in commands]],
            }

        executed_commands: List[str] = []
        for cmd in commands:
            success, _, stderr = self._run_command(cmd, check=False)
            executed_commands.append(" ".join(cmd))
            if not success:
                return {
                    "success": False,
                    "message": f"Failed to apply general system command: {' '.join(cmd)}. {stderr}".strip(),
                    "is_mock": False,
                    "commands": executed_commands,
                }

        return {
            "success": True,
            "message": "General system settings updated",
            "is_mock": False,
            "commands": [*port_sync_result.get("commands", []), *executed_commands],
        }

    def sync_https_firewall_ports(
        self,
        old_panel_port: Optional[int],
        new_panel_port: Optional[int],
        old_subscription_port: Optional[int],
        new_subscription_port: Optional[int],
    ) -> Dict[str, any]:
        """Sync UFW rules for panel/subscription HTTPS ports."""

        old_ports = {int(port) for port in [old_panel_port, old_subscription_port] if port is not None}
        new_ports = {int(port) for port in [new_panel_port, new_subscription_port] if port is not None}

        allow_ports = sorted(new_ports - old_ports)
        remove_ports = sorted(old_ports - new_ports)

        if not allow_ports and not remove_ports:
            return {
                "success": True,
                "message": "HTTPS firewall rules unchanged",
                "is_mock": not self.is_production,
                "commands": [],
            }

        if self.is_production and not self._command_exists("ufw"):
            logger.warning("ufw is not installed. Skipping HTTPS firewall port sync.")
            return {
                "success": True,
                "message": "ufw not installed; skipped HTTPS firewall sync",
                "is_mock": False,
                "commands": [],
            }

        commands: List[List[str]] = []
        for port in allow_ports:
            commands.append(["ufw", "allow", f"{port}/tcp"])

        for port in remove_ports:
            commands.append(["ufw", "delete", "allow", f"{port}/tcp"])

        if not self.is_production:
            for cmd in commands:
                logger.info(f"[MOCK] Would execute HTTPS firewall command: {' '.join(cmd)}")
            return {
                "success": True,
                "message": "HTTPS firewall rules updated (mock)",
                "is_mock": True,
                "commands": [" ".join(cmd) for cmd in commands],
            }

        executed_commands: List[str] = []
        for cmd in commands:
            success, _, stderr = self._run_command(cmd, check=False)
            executed_commands.append(" ".join(cmd))
            if not success:
                if cmd[:3] == ["ufw", "delete", "allow"]:
                    deny_cmd = ["ufw", "deny", cmd[-1]]
                    deny_success, _, deny_error = self._run_command(deny_cmd, check=False)
                    executed_commands.append(" ".join(deny_cmd))
                    if deny_success:
                        continue
                    stderr = deny_error or stderr

                return {
                    "success": False,
                    "message": f"Failed to update HTTPS firewall rules: {stderr}".strip(),
                    "is_mock": False,
                    "commands": executed_commands,
                }

        return {
            "success": True,
            "message": "HTTPS firewall rules updated",
            "is_mock": False,
            "commands": executed_commands,
        }

    @staticmethod
    def _normalize_cert_domain(value: str) -> str:
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError("Domain is required")

        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        domain = (parsed.hostname or "").strip().lower()
        if not domain:
            domain = candidate.split("/")[0].split(":")[0].strip().lower()
        if not domain:
            raise ValueError("Domain is invalid")
        return domain

    def _build_ssl_targets(
        self,
        panel_domain: Optional[str],
        subscription_domain: Optional[str],
    ) -> List[Tuple[str, str]]:
        targets: List[Tuple[str, str]] = []

        panel_raw = (panel_domain or "").strip()
        if panel_raw:
            targets.append(("Panel Domain", self._normalize_cert_domain(panel_raw)))

        subscription_raw = (subscription_domain or "").strip()
        if subscription_raw:
            targets.append(("Subscription Domain", self._normalize_cert_domain(subscription_raw)))

        if not targets:
            raise ValueError("At least one domain is required for SSL issuance")

        return targets

    @staticmethod
    def _build_certbot_command(domain: str, email: str) -> List[str]:
        return [
            "certbot",
            "certonly",
            "--standalone",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "-m",
            email,
        ]

    def _stream_mock_ssl_issue_logs(self, targets: List[Tuple[str, str]], email: str) -> Iterator[str]:
        for label, domain in targets:
            command = self._build_certbot_command(domain, email)
            yield f">>> Starting SSL issuance for {label}..."
            time.sleep(0.25)
            yield f"$ {' '.join(command)}"
            time.sleep(0.25)
            yield f"Saving debug log to /var/log/letsencrypt/letsencrypt-{domain}.log"
            time.sleep(0.25)
            yield f"Requesting a certificate for {domain}"
            time.sleep(0.4)
            yield "Successfully received certificate"
            time.sleep(0.2)
            yield f"Certificate is saved at: /etc/letsencrypt/live/{domain}/fullchain.pem"
            time.sleep(0.2)
            yield f"Key is saved at: /etc/letsencrypt/live/{domain}/privkey.pem"
            time.sleep(0.2)
            yield ">>> Success!"
            time.sleep(0.2)

        yield ">>> SSL issuance completed for all requested domains."

    def _stream_production_ssl_issue_logs(self, targets: List[Tuple[str, str]], email: str) -> Iterator[str]:
        for label, domain in targets:
            command = self._build_certbot_command(domain, email)
            yield f">>> Starting SSL issuance for {label}..."
            yield f"$ {' '.join(command)}"

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            try:
                if process.stdout is not None:
                    for line in process.stdout:
                        rendered = line.rstrip("\n")
                        if rendered:
                            yield rendered
            finally:
                if process.stdout is not None:
                    process.stdout.close()

            return_code = process.wait()
            if return_code != 0:
                yield f">>> Error: SSL issuance failed for {label} with exit code {return_code}."
                return

            yield ">>> Success!"

        yield ">>> SSL issuance completed for all requested domains."

    def stream_ssl_issue_logs(
        self,
        panel_domain: Optional[str],
        subscription_domain: Optional[str],
        email: str,
    ) -> Iterator[str]:
        normalized_email = (email or "").strip()
        if not normalized_email:
            raise ValueError("Let's Encrypt email is required")

        targets = self._build_ssl_targets(panel_domain, subscription_domain)

        if not self.is_production:
            yield ">>> Running in development mode with mock SSL logs."
            yield from self._stream_mock_ssl_issue_logs(targets, normalized_email)
            return

        yield from self._stream_production_ssl_issue_logs(targets, normalized_email)
    
    def check_easyrsa_installed(self) -> bool:
        """Check if Easy-RSA is installed"""
        return self.pki_manager.is_easyrsa_available()
    
    def initialize_pki(self) -> Dict[str, any]:
        """
        Initialize PKI infrastructure using Easy-RSA 3.
        This should be run once during initial setup.
        """
        result = self.pki_manager.ensure_ready()
        if not result.get("success") and result.get("degraded"):
            logger.warning("PKI initialize skipped with graceful degradation: %s", result.get("message"))
        return result
    
    def create_client_certificate(self, client_name: str) -> Dict[str, any]:
        """
        Create client certificate using Easy-RSA 3.
        
        Args:
            client_name: Unique client identifier (alphanumeric, no spaces)
            
        Returns:
            Dict with success status and file paths
        """
        if not client_name.replace("-", "").replace("_", "").isalnum():
            return {
                "success": False,
                "message": "Client name must be alphanumeric (-, _ allowed)"
            }

        result = self.pki_manager.build_client(client_name)
        if not result.get("success"):
            logger.warning("Client certificate creation failed for %s: %s", client_name, result.get("message"))
        return result
    
    def revoke_client_certificate(self, client_name: str) -> Dict[str, any]:
        """
        Revoke client certificate using Easy-RSA 3.
        
        Args:
            client_name: Client identifier to revoke
            
        Returns:
            Dict with success status
        """
        result = self.pki_manager.revoke_client(client_name)
        if result.get("success"):
            result["revoked_at"] = datetime.utcnow().isoformat()
        else:
            logger.warning("Client certificate revoke failed for %s: %s", client_name, result.get("message"))
        return result
    
    def _get_client_materials(self, client_name: str) -> Tuple[str, str, str, str]:
        """Return CA cert, client cert, client key, and TLS auth/crypt key content."""
        cert_path = self.config.CLIENT_CERTS_DIR / f"{client_name}.crt"
        key_path = self.config.CLIENT_KEYS_DIR / f"{client_name}.key"
        missing = [
            str(path)
            for path in [self.config.CA_CERT, cert_path, key_path, self.config.TA_KEY]
            if not path.exists()
        ]
        if missing:
            raise FileNotFoundError(
                "Missing OpenVPN PKI material(s): " + ", ".join(missing)
            )
        with open(self.config.CA_CERT, 'r') as f:
            ca_cert = f.read()
        with open(cert_path, 'r') as f:
            client_cert = f.read()
        with open(key_path, 'r') as f:
            client_key = f.read()
        with open(self.config.TA_KEY, 'r') as f:
            ta_key = f.read()
        return ca_cert, client_cert, client_key, ta_key

    def _get_base_config(
        self,
        *,
        os_label: str,
        client_name: str,
        device_type: str,
        client_protocol: str,
        client_remote_line: str,
        client_data_ciphers: str,
        data_cipher_fallback: str,
        auth_digest: str,
        tls_version_min: str,
        tls_mode: str,
        tun_mtu: Optional[int],
        mssfix: Optional[int],
        keepalive_ping: Optional[int],
        keepalive_timeout: Optional[int],
        redirect_gateway: bool,
        ipv6_enabled: bool,
        primary_dns: str,
        secondary_dns: str,
        push_custom_routes: str,
        persist_key: bool,
        persist_tun: bool,
        verbosity: int = 3,
    ) -> List[str]:
        lines: List[str] = [
            "# Atlas VPN - OpenVPN Client Configuration",
            f"# OS: {os_label}",
            f"# Client: {client_name}",
            f"# Generated: {datetime.utcnow().isoformat()}",
            "",
            "client",
            f"dev {device_type}",
            f"proto {client_protocol}",
            client_remote_line,
            "resolv-retry infinite",
            "nobind",
        ]

        if persist_key:
            lines.append("persist-key")
        if persist_tun:
            lines.append("persist-tun")

        lines.extend([
            "remote-cert-tls server",
            f"verb {int(verbosity)}",
        ])

        if client_data_ciphers:
            lines.append(f"data-ciphers {client_data_ciphers}")
        if data_cipher_fallback:
            lines.append(f"data-ciphers-fallback {data_cipher_fallback}")
        if auth_digest:
            lines.append(f"auth {auth_digest}")
        if tls_version_min:
            lines.append(f"tls-version-min {tls_version_min}")
        if tls_mode == "tls-auth":
            lines.append("key-direction 1")

        if tun_mtu:
            lines.append(f"tun-mtu {int(tun_mtu)}")
        if mssfix:
            lines.append(f"mssfix {int(mssfix)}")
        if keepalive_ping and keepalive_timeout:
            lines.append(f"keepalive {int(keepalive_ping)} {int(keepalive_timeout)}")

        if push_custom_routes:
            for route_line in push_custom_routes.splitlines():
                route_clean = route_line.strip()
                if route_clean:
                    lines.append(f"route {route_clean}")

        return lines

    @staticmethod
    def _resolve_client_ipv6_context(general_settings: Dict[str, any]) -> Tuple[bool, str]:
        ipv6_enabled = bool(general_settings.get("global_ipv6_support", False))
        server_ipv6 = (general_settings.get("public_ipv6_address") or "").strip()
        if not ipv6_enabled or not server_ipv6:
            return False, ""
        return True, server_ipv6

    @staticmethod
    def _inject_ipv6_client_directives(
        lines: List[str],
        *,
        server_ipv6: str,
        server_port: int,
        redirect_gateway: bool,
    ) -> None:
        ipv6_remote = f"remote {server_ipv6} {int(server_port)}"
        if ipv6_remote not in lines:
            insert_index = 0
            for idx, line in enumerate(lines):
                if line.strip().startswith("remote "):
                    insert_index = idx + 1
                    break
            lines.insert(insert_index, ipv6_remote)

        if redirect_gateway and "route-ipv6 2000::/3" not in lines:
            lines.append("route-ipv6 2000::/3")

    def _append_certificate_blocks(
        self,
        lines: List[str],
        *,
        ca_cert: str,
        client_cert: str,
        client_key: str,
        ta_key: str,
        tls_mode: str,
    ) -> None:
        lines.extend([
            "",
            "<ca>",
            ca_cert,
            "</ca>",
            "",
            "<cert>",
            client_cert,
            "</cert>",
            "",
            "<key>",
            client_key,
            "</key>",
        ])

        if tls_mode == "tls-crypt":
            lines.extend(["", "<tls-crypt>", ta_key, "</tls-crypt>"])
        elif tls_mode == "tls-auth":
            lines.extend(["", "<tls-auth>", ta_key, "</tls-auth>"])

    def _apply_obfuscation(
        self,
        lines: List[str],
        *,
        obfuscation_mode: str,
        resolved_server: str,
        openvpn_settings: Dict[str, any],
        prebuilt_directives: Optional[List[str]] = None,
    ) -> None:
        """Apply obfuscation directives in a reusable way for all client builders."""
        if prebuilt_directives is not None:
            for directive in prebuilt_directives:
                normalized = (directive or "").strip().lower()
                if normalized and "comp-lzo" not in normalized and "compress" not in normalized:
                    lines.append((directive or "").strip())
            return

        proxy_server = (openvpn_settings.get("proxy_server") or "").strip()
        proxy_address = (openvpn_settings.get("proxy_address") or "").strip()
        proxy_target = proxy_server or proxy_address or resolved_server
        proxy_port = _safe_int(openvpn_settings.get("proxy_port")) or 8080
        spoofed_host = (openvpn_settings.get("spoofed_host") or "").strip()
        socks_server = (openvpn_settings.get("socks_server") or "").strip()
        socks_port = _safe_int(openvpn_settings.get("socks_port")) or 1080
        sni_domain = (openvpn_settings.get("sni_domain") or "").strip()
        ws_path = (openvpn_settings.get("ws_path") or "/stream").strip() or "/stream"
        ws_port = _safe_int(openvpn_settings.get("ws_port")) or 8080

        if obfuscation_mode == "stealth":
            lines.append(f"http-proxy {proxy_target} {proxy_port}")
            lines.append("http-proxy-retry")
            if spoofed_host:
                lines.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
        elif obfuscation_mode == "http_proxy_basic":
            lines.append(f"http-proxy {proxy_target} {proxy_port}")
            lines.append("http-proxy-retry")
        elif obfuscation_mode == "http_proxy_advanced":
            lines.append(f"http-proxy {proxy_target} {proxy_port}")
            lines.append("http-proxy-retry")
            if spoofed_host:
                lines.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
        elif obfuscation_mode == "socks5_proxy_injection":
            socks_target = socks_server or proxy_target
            lines.append(f"socks-proxy {socks_target} {socks_port}")
            lines.append("socks-proxy-retry")
        elif obfuscation_mode == "tls_tunnel":
            lines.append("# TLS tunnel mode: run local Stunnel client before connecting.")
            if sni_domain:
                lines.append(f"# TLS SNI domain hint: {sni_domain}")
        elif obfuscation_mode == "websocket_cdn":
            lines.append(f"# WebSocket path hint: {ws_path}")
            lines.append(f"# Local WebSocket port hint: {ws_port}")

    def _apply_android_optimizations(
        self,
        lines: List[str],
        *,
        sndbuf: Optional[int],
        rcvbuf: Optional[int],
        fast_io: bool,
        explicit_exit_notify: Optional[int],
        is_udp: bool,
    ) -> None:
        if sndbuf is not None:
            lines.append(f"sndbuf {int(sndbuf)}")
        if rcvbuf is not None:
            lines.append(f"rcvbuf {int(rcvbuf)}")
        if fast_io and is_udp:
            lines.append("fast-io")
        if explicit_exit_notify and is_udp:
            lines.append(f"explicit-exit-notify {int(explicit_exit_notify)}")

    def _apply_windows_optimizations(
        self,
        lines: List[str],
        *,
        sndbuf: Optional[int],
        rcvbuf: Optional[int],
        is_tcp: bool,
    ) -> None:
        # Group Windows-only anti-leak and performance directives together.
        lines.append("block-outside-dns")
        lines.append("register-dns")

        if sndbuf is not None:
            lines.append(f"sndbuf {int(sndbuf)}")
        if rcvbuf is not None:
            lines.append(f"rcvbuf {int(rcvbuf)}")

        if is_tcp:
            lines.append("socket-flags TCP_NODELAY")

    def _apply_apple_restrictions(self, lines: List[str], ensure_persistence: bool = True) -> List[str]:
        blocked_directives = (
            "sndbuf",
            "rcvbuf",
            "comp-lzo",
            "compress",
            "explicit-exit-notify",
            "block-outside-dns",
        )

        sanitized_lines: List[str] = []
        for line in lines:
            stripped = line.strip()
            lowered = stripped.lower()
            if stripped and not stripped.startswith("#"):
                if any(lowered == directive or lowered.startswith(f"{directive} ") for directive in blocked_directives):
                    continue
            sanitized_lines.append(line)

        if ensure_persistence:
            # Ensure Apple persistence directives are present.
            if "persist-key" not in sanitized_lines:
                sanitized_lines.insert(10, "persist-key")
            if "persist-tun" not in sanitized_lines:
                sanitized_lines.insert(11, "persist-tun")

        return sanitized_lines

    def _generate_apple_config(
        self,
        client_name: str,
        openvpn_settings: dict,
        general_settings: dict,
        server_address: str,
        server_port: int,
        protocol: str,
        os_type: str = "ios",
    ) -> str:
        """
        Standalone Apple (iOS/macOS) config generator with strict whitelist.
        NO sndbuf, NO rcvbuf, NO block-outside-dns, NO comp-lzo/compress.
        """
        device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
        resolved_protocol = str(protocol or openvpn_settings.get("protocol", "udp")).strip().lower()
        obfuscation_mode = str(openvpn_settings.get("obfuscation_mode") or "standard").strip().lower()
        effective_protocol = "tcp" if obfuscation_mode != "standard" else resolved_protocol
        is_tcp = "tcp" in effective_protocol.lower()

        resolved_server = (
            (server_address or "").strip()
            or (general_settings.get("server_address") or "").strip()
            or (general_settings.get("public_ipv4_address") or "").strip()
        )
        resolved_port = int(server_port if server_port is not None else openvpn_settings.get("port", 1194))

        obfuscation_settings = {
            "obfuscation_mode": openvpn_settings.get("obfuscation_mode"),
            "proxy_server": openvpn_settings.get("proxy_server"),
            "proxy_address": openvpn_settings.get("proxy_address"),
            "proxy_port": openvpn_settings.get("proxy_port"),
            "spoofed_host": openvpn_settings.get("spoofed_host"),
            "socks_server": openvpn_settings.get("socks_server"),
            "socks_port": openvpn_settings.get("socks_port"),
            "stunnel_port": openvpn_settings.get("stunnel_port"),
            "sni_domain": openvpn_settings.get("sni_domain"),
            "cdn_domain": openvpn_settings.get("cdn_domain"),
            "ws_path": openvpn_settings.get("ws_path"),
            "ws_port": openvpn_settings.get("ws_port"),
        }

        (
            client_protocol,
            client_remote_line,
            obfuscation_directives,
        ) = self._build_client_transport_directives(
            server_address=resolved_server,
            default_port=resolved_port,
            default_protocol=effective_protocol,
            obfuscation_settings=obfuscation_settings,
        )

        raw_data_ciphers = openvpn_settings.get("data_ciphers") or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
        if isinstance(raw_data_ciphers, list):
            client_data_ciphers = ":".join([c.strip() for c in raw_data_ciphers if c and c.strip()])
        else:
            client_data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

        fallback = client_data_ciphers.split(":")[0].strip() if ":" in client_data_ciphers else client_data_ciphers
        auth_digest = str(openvpn_settings.get("auth_digest") or "SHA256").strip().upper()
        tls_version_min = str(openvpn_settings.get("tls_version_min") or "1.2").strip()
        tls_mode = str(openvpn_settings.get("tls_mode") or "tls-crypt").strip().lower()

        verbosity = _safe_int(openvpn_settings.get("verbosity"))
        tun_mtu = _safe_int(openvpn_settings.get("tun_mtu"))
        mssfix = _safe_int(openvpn_settings.get("mssfix"))
        apple_mssfix = mssfix if mssfix and mssfix > 0 else None
        keepalive_ping = _safe_int(openvpn_settings.get("keepalive_ping"))
        keepalive_timeout = _safe_int(openvpn_settings.get("keepalive_timeout"))
        tcp_nodelay = bool(openvpn_settings.get("tcp_nodelay", False))
        redirect_gateway = bool(openvpn_settings.get("redirect_gateway", False))
        ipv6_enabled, server_ipv6 = self._resolve_client_ipv6_context(general_settings)
        primary_dns = (openvpn_settings.get("primary_dns") or "").strip()
        secondary_dns = (openvpn_settings.get("secondary_dns") or "").strip()
        push_custom_routes = (openvpn_settings.get("push_custom_routes") or "").strip()

        os_name = (os_type or "").strip().lower()
        is_macos = os_name in {"mac", "macos"}

        lines = self._get_base_config(
            os_label="macOS" if is_macos else "iOS",
            client_name=client_name,
            device_type=device_type,
            client_protocol=client_protocol,
            client_remote_line=client_remote_line,
            client_data_ciphers=client_data_ciphers,
            data_cipher_fallback=fallback,
            auth_digest=auth_digest,
            tls_version_min=tls_version_min,
            tls_mode=tls_mode,
            tun_mtu=tun_mtu,
            mssfix=apple_mssfix,
            keepalive_ping=keepalive_ping,
            keepalive_timeout=keepalive_timeout,
            redirect_gateway=redirect_gateway,
            ipv6_enabled=ipv6_enabled,
            primary_dns=primary_dns,
            secondary_dns=secondary_dns,
            push_custom_routes=push_custom_routes,
            persist_key=is_macos,
            persist_tun=is_macos,
            verbosity=verbosity if verbosity is not None else 3,
        )

        if tcp_nodelay and is_tcp:
            lines.append("tcp-nodelay")

        if ipv6_enabled:
            self._inject_ipv6_client_directives(
                lines,
                server_ipv6=server_ipv6,
                server_port=resolved_port,
                redirect_gateway=redirect_gateway,
            )

        self._apply_obfuscation(
            lines,
            obfuscation_mode=obfuscation_mode,
            resolved_server=resolved_server,
            openvpn_settings=openvpn_settings,
            prebuilt_directives=obfuscation_directives,
        )
        
        # CONDITIONAL: Custom Apple-specific directives from DB
        custom_apple = (openvpn_settings.get("custom_mac") if os_name in {"mac", "macos"} else openvpn_settings.get("custom_ios"))
        custom_apple = (custom_apple or "").strip()
        blocked_directives = (
            "sndbuf",
            "rcvbuf",
            "comp-lzo",
            "compress",
            "explicit-exit-notify",
            "block-outside-dns",
        )
        if custom_apple:
            lines.append("")
            lines.append("# Custom Apple Directives")
            for custom_line in custom_apple.splitlines():
                custom_clean = custom_line.strip()
                if custom_clean and not custom_clean.startswith("#"):
                    custom_lower = custom_clean.lower()
                    if any(custom_lower == directive or custom_lower.startswith(f"{directive} ") for directive in blocked_directives):
                        continue
                    lines.append(custom_clean)
        
        # AUTHENTICATION: auth-user-pass and conditional auth-nocache (BEFORE certificates)
        lines.append("")
        lines.append("auth-user-pass")
        enable_auth_nocache = str(openvpn_settings.get("enable_auth_nocache", True)).strip().lower() not in {"0", "false", "no", "off"}
        if enable_auth_nocache:
            lines.append("auth-nocache")
        
        ca_cert, client_cert, client_key, ta_key = self._get_client_materials(client_name)
        self._append_certificate_blocks(
            lines,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            ta_key=ta_key,
            tls_mode=tls_mode,
        )

        sanitized_lines = self._apply_apple_restrictions(lines, ensure_persistence=is_macos)
        sanitized_lines = [
            line
            for line in sanitized_lines
            if not line.strip().lower().startswith("tun-mtu ")
            and not line.strip().lower().startswith("mssfix ")
            and not line.strip().lower().startswith("keepalive ")
        ]
        if not is_macos:
            sanitized_lines = [
                line
                for line in sanitized_lines
                if line.strip().lower() not in {"persist-key", "persist-tun", "resolv-retry infinite"}
            ]
        sanitized_lines.append("")
        return "\n".join(sanitized_lines)

    def _generate_android_config(
        self,
        client_name: str,
        openvpn_settings: dict,
        general_settings: dict,
        server_address: str,
        server_port: int,
        protocol: str,
    ) -> str:
        """Generate Android config using global settings with Android-specific smart filtering."""
        device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
        resolved_protocol = str(protocol or openvpn_settings.get("protocol", "udp")).strip().lower()
        obfuscation_mode = str(openvpn_settings.get("obfuscation_mode") or "standard").strip().lower()
        effective_protocol = "tcp" if obfuscation_mode != "standard" else resolved_protocol

        resolved_server = (
            (server_address or "").strip()
            or (general_settings.get("server_address") or "").strip()
            or (general_settings.get("public_ipv4_address") or "").strip()
        )
        resolved_port = int(server_port if server_port is not None else openvpn_settings.get("port", 1194))

        obfuscation_settings = {
            "obfuscation_mode": openvpn_settings.get("obfuscation_mode"),
            "proxy_server": openvpn_settings.get("proxy_server"),
            "proxy_address": openvpn_settings.get("proxy_address"),
            "proxy_port": openvpn_settings.get("proxy_port"),
            "spoofed_host": openvpn_settings.get("spoofed_host"),
            "socks_server": openvpn_settings.get("socks_server"),
            "socks_port": openvpn_settings.get("socks_port"),
            "stunnel_port": openvpn_settings.get("stunnel_port"),
            "sni_domain": openvpn_settings.get("sni_domain"),
            "cdn_domain": openvpn_settings.get("cdn_domain"),
            "ws_path": openvpn_settings.get("ws_path"),
            "ws_port": openvpn_settings.get("ws_port"),
        }

        (
            client_protocol,
            client_remote_line,
            obfuscation_directives,
        ) = self._build_client_transport_directives(
            server_address=resolved_server,
            default_port=resolved_port,
            default_protocol=effective_protocol,
            obfuscation_settings=obfuscation_settings,
        )

        is_udp = "udp" in client_protocol.lower()

        raw_data_ciphers = openvpn_settings.get("data_ciphers") or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
        if isinstance(raw_data_ciphers, list):
            client_data_ciphers = ":".join([c.strip() for c in raw_data_ciphers if c and c.strip()])
        else:
            client_data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

        data_cipher_fallback = client_data_ciphers.split(":")[0].strip() if ":" in client_data_ciphers else client_data_ciphers
        auth_digest = str(openvpn_settings.get("auth_digest") or "SHA256").strip().upper()
        tls_version_min = str(openvpn_settings.get("tls_version_min") or "1.2").strip()
        tls_mode = str(openvpn_settings.get("tls_mode") or "tls-crypt").strip().lower()
        redirect_gateway = bool(openvpn_settings.get("redirect_gateway", False))
        primary_dns = (openvpn_settings.get("primary_dns") or "").strip()
        secondary_dns = (openvpn_settings.get("secondary_dns") or "").strip()
        push_custom_routes = (openvpn_settings.get("push_custom_routes") or "").strip()
        tun_mtu = _safe_int(openvpn_settings.get("tun_mtu"))
        mssfix = _safe_int(openvpn_settings.get("mssfix"))
        sndbuf = _safe_int(openvpn_settings.get("sndbuf"))
        rcvbuf = _safe_int(openvpn_settings.get("rcvbuf"))
        fast_io = bool(openvpn_settings.get("fast_io", False))
        explicit_exit_notify = _safe_int(openvpn_settings.get("explicit_exit_notify"))
        keepalive_ping = _safe_int(openvpn_settings.get("keepalive_ping"))
        keepalive_timeout = _safe_int(openvpn_settings.get("keepalive_timeout"))
        tcp_nodelay = bool(openvpn_settings.get("tcp_nodelay", False))
        persist_key = bool(openvpn_settings.get("persist_key", True))
        persist_tun = bool(openvpn_settings.get("persist_tun", True))

        ipv6_enabled, server_ipv6 = self._resolve_client_ipv6_context(general_settings)

        lines = self._get_base_config(
            os_label="ANDROID",
            client_name=client_name,
            device_type=device_type,
            client_protocol=client_protocol,
            client_remote_line=client_remote_line,
            client_data_ciphers=client_data_ciphers,
            data_cipher_fallback=data_cipher_fallback,
            auth_digest=auth_digest,
            tls_version_min=tls_version_min,
            tls_mode=tls_mode,
            tun_mtu=tun_mtu,
            mssfix=mssfix,
            keepalive_ping=keepalive_ping,
            keepalive_timeout=keepalive_timeout,
            redirect_gateway=redirect_gateway,
            ipv6_enabled=ipv6_enabled,
            primary_dns=primary_dns,
            secondary_dns=secondary_dns,
            push_custom_routes=push_custom_routes,
            persist_key=persist_key,
            persist_tun=persist_tun,
            verbosity=3,
        )

        if tcp_nodelay and "tcp" in client_protocol.lower():
            lines.append("tcp-nodelay")

        if ipv6_enabled:
            self._inject_ipv6_client_directives(
                lines,
                server_ipv6=server_ipv6,
                server_port=resolved_port,
                redirect_gateway=redirect_gateway,
            )

        self._apply_android_optimizations(
            lines,
            sndbuf=sndbuf,
            rcvbuf=rcvbuf,
            fast_io=fast_io,
            explicit_exit_notify=explicit_exit_notify,
            is_udp=is_udp,
        )

        self._apply_obfuscation(
            lines,
            obfuscation_mode=obfuscation_mode,
            resolved_server=resolved_server,
            openvpn_settings=openvpn_settings,
            prebuilt_directives=obfuscation_directives,
        )

        custom_android = (openvpn_settings.get("custom_android") or "").strip()
        if custom_android:
            lines.append("")
            lines.append("# Custom ANDROID Directives")
            for custom_line in custom_android.splitlines():
                custom_clean = custom_line.strip()
                custom_lower = custom_clean.lower()
                if custom_clean and not custom_clean.startswith("#"):
                    if "comp-lzo" in custom_lower or "compress" in custom_lower:
                        continue
                    lines.append(custom_clean)

        lines = [
            line
            for line in lines
            if line.strip().lower() not in {"resolv-retry infinite", "persist-key", "persist-tun"}
            and not line.strip().lower().startswith("tun-mtu ")
            and not line.strip().lower().startswith("mssfix ")
            and not line.strip().lower().startswith("keepalive ")
            and not line.strip().lower().startswith("sndbuf ")
            and not line.strip().lower().startswith("rcvbuf ")
        ]

        lines.append("")
        lines.append("auth-user-pass")
        enable_auth_nocache = str(openvpn_settings.get("enable_auth_nocache", True)).strip().lower() not in {"0", "false", "no", "off"}
        if enable_auth_nocache:
            lines.append("auth-nocache")

        ca_cert, client_cert, client_key, ta_key = self._get_client_materials(client_name)
        self._append_certificate_blocks(
            lines,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            ta_key=ta_key,
            tls_mode=tls_mode,
        )

        lines.append("")
        return "\n".join(lines)

    def _generate_windows_config(
        self,
        client_name: str,
        openvpn_settings: dict,
        general_settings: dict,
        server_address: str,
        server_port: int,
        protocol: str,
    ) -> str:
        device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
        resolved_protocol = str(protocol or openvpn_settings.get("protocol", "udp")).strip().lower()
        obfuscation_mode = str(openvpn_settings.get("obfuscation_mode") or "standard").strip().lower()
        effective_protocol = "tcp" if obfuscation_mode != "standard" else resolved_protocol

        resolved_server = (
            (server_address or "").strip()
            or (general_settings.get("server_address") or "").strip()
            or (general_settings.get("public_ipv4_address") or "").strip()
        )
        resolved_port = int(server_port if server_port is not None else openvpn_settings.get("port", 1194))

        obfuscation_settings = {
            "obfuscation_mode": openvpn_settings.get("obfuscation_mode"),
            "proxy_server": openvpn_settings.get("proxy_server"),
            "proxy_address": openvpn_settings.get("proxy_address"),
            "proxy_port": openvpn_settings.get("proxy_port"),
            "spoofed_host": openvpn_settings.get("spoofed_host"),
            "socks_server": openvpn_settings.get("socks_server"),
            "socks_port": openvpn_settings.get("socks_port"),
            "stunnel_port": openvpn_settings.get("stunnel_port"),
            "sni_domain": openvpn_settings.get("sni_domain"),
            "cdn_domain": openvpn_settings.get("cdn_domain"),
            "ws_path": openvpn_settings.get("ws_path"),
            "ws_port": openvpn_settings.get("ws_port"),
        }

        (
            client_protocol,
            client_remote_line,
            obfuscation_directives,
        ) = self._build_client_transport_directives(
            server_address=resolved_server,
            default_port=resolved_port,
            default_protocol=effective_protocol,
            obfuscation_settings=obfuscation_settings,
        )

        is_tcp = "tcp" in client_protocol.lower()
        is_udp = "udp" in client_protocol.lower()

        raw_data_ciphers = openvpn_settings.get("data_ciphers") or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
        if isinstance(raw_data_ciphers, list):
            client_data_ciphers = ":".join([cipher.strip() for cipher in raw_data_ciphers if cipher and cipher.strip()])
        else:
            client_data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

        data_cipher_fallback = client_data_ciphers.split(":")[0].strip() if ":" in client_data_ciphers else client_data_ciphers
        auth_digest = str(openvpn_settings.get("auth_digest") or "SHA256").strip().upper()
        tls_version_min = str(openvpn_settings.get("tls_version_min") or "1.2").strip()
        tls_mode = str(openvpn_settings.get("tls_mode") or "tls-crypt").strip().lower()
        tun_mtu = _safe_int(openvpn_settings.get("tun_mtu"))
        mssfix = _safe_int(openvpn_settings.get("mssfix"))
        sndbuf = _safe_int(openvpn_settings.get("sndbuf"))
        rcvbuf = _safe_int(openvpn_settings.get("rcvbuf"))
        keepalive_ping = _safe_int(openvpn_settings.get("keepalive_ping"))
        keepalive_timeout = _safe_int(openvpn_settings.get("keepalive_timeout"))
        redirect_gateway = bool(openvpn_settings.get("redirect_gateway", False))
        primary_dns = (openvpn_settings.get("primary_dns") or "").strip()
        secondary_dns = (openvpn_settings.get("secondary_dns") or "").strip()
        push_custom_routes = (openvpn_settings.get("push_custom_routes") or "").strip()
        persist_key = bool(openvpn_settings.get("persist_key", True))
        persist_tun = bool(openvpn_settings.get("persist_tun", True))

        ipv6_enabled, server_ipv6 = self._resolve_client_ipv6_context(general_settings)

        lines = self._get_base_config(
            os_label="WINDOWS",
            client_name=client_name,
            device_type=device_type,
            client_protocol=client_protocol,
            client_remote_line=client_remote_line,
            client_data_ciphers=client_data_ciphers,
            data_cipher_fallback=data_cipher_fallback,
            auth_digest=auth_digest,
            tls_version_min=tls_version_min,
            tls_mode=tls_mode,
            tun_mtu=tun_mtu,
            mssfix=mssfix,
            keepalive_ping=keepalive_ping,
            keepalive_timeout=keepalive_timeout,
            redirect_gateway=redirect_gateway,
            ipv6_enabled=ipv6_enabled,
            primary_dns=primary_dns,
            secondary_dns=secondary_dns,
            push_custom_routes=push_custom_routes,
            persist_key=persist_key,
            persist_tun=persist_tun,
            verbosity=3,
        )

        explicit_exit_notify = _safe_int(openvpn_settings.get("explicit_exit_notify"))
        if explicit_exit_notify and is_udp:
            lines.append(f"explicit-exit-notify {int(explicit_exit_notify)}")

        if ipv6_enabled:
            self._inject_ipv6_client_directives(
                lines,
                server_ipv6=server_ipv6,
                server_port=resolved_port,
                redirect_gateway=redirect_gateway,
            )

        self._apply_windows_optimizations(
            lines,
            sndbuf=sndbuf,
            rcvbuf=rcvbuf,
            is_tcp=is_tcp,
        )

        self._apply_obfuscation(
            lines,
            obfuscation_mode=obfuscation_mode,
            resolved_server=resolved_server,
            openvpn_settings=openvpn_settings,
            prebuilt_directives=obfuscation_directives,
        )

        custom_windows = (openvpn_settings.get("custom_windows") or "").strip()
        if custom_windows:
            lines.append("")
            lines.append("# Custom WINDOWS Directives")
            for custom_line in custom_windows.splitlines():
                custom_clean = custom_line.strip()
                custom_lower = custom_clean.lower()
                if custom_clean and not custom_clean.startswith("#"):
                    if "comp-lzo" in custom_lower or "compress" in custom_lower:
                        continue
                    lines.append(custom_clean)

        lines = [
            line
            for line in lines
            if not line.strip().lower().startswith("tun-mtu ")
            and not line.strip().lower().startswith("mssfix ")
            and not line.strip().lower().startswith("keepalive ")
            and not line.strip().lower().startswith("sndbuf ")
            and not line.strip().lower().startswith("rcvbuf ")
        ]

        lines.append("")
        lines.append("auth-user-pass")
        enable_auth_nocache = str(openvpn_settings.get("enable_auth_nocache", True)).strip().lower() not in {"0", "false", "no", "off"}
        if enable_auth_nocache:
            lines.append("auth-nocache")

        ca_cert, client_cert, client_key, ta_key = self._get_client_materials(client_name)
        self._append_certificate_blocks(
            lines,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            ta_key=ta_key,
            tls_mode=tls_mode,
        )

        lines.append("")
        return "\n".join(lines)

    def _generate_default_config(
        self,
        client_name: str,
        openvpn_settings: dict,
        general_settings: dict,
        server_address: str,
        server_port: int,
        protocol: str,
        os_type: str,
    ) -> str:
        os_name = (os_type or "default").strip().lower()
        os_label = os_name.upper() if os_name else "GENERIC"

        device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
        resolved_protocol = str(protocol or openvpn_settings.get("protocol", "udp")).strip().lower()
        obfuscation_mode = str(openvpn_settings.get("obfuscation_mode") or "standard").strip().lower()
        effective_protocol = "tcp" if obfuscation_mode != "standard" else resolved_protocol

        resolved_server = (
            (server_address or "").strip()
            or (general_settings.get("server_address") or "").strip()
            or (general_settings.get("public_ipv4_address") or "").strip()
        )
        resolved_port = int(server_port if server_port is not None else openvpn_settings.get("port", 1194))

        obfuscation_settings = {
            "obfuscation_mode": openvpn_settings.get("obfuscation_mode"),
            "proxy_server": openvpn_settings.get("proxy_server"),
            "proxy_address": openvpn_settings.get("proxy_address"),
            "proxy_port": openvpn_settings.get("proxy_port"),
            "spoofed_host": openvpn_settings.get("spoofed_host"),
            "socks_server": openvpn_settings.get("socks_server"),
            "socks_port": openvpn_settings.get("socks_port"),
            "stunnel_port": openvpn_settings.get("stunnel_port"),
            "sni_domain": openvpn_settings.get("sni_domain"),
            "cdn_domain": openvpn_settings.get("cdn_domain"),
            "ws_path": openvpn_settings.get("ws_path"),
            "ws_port": openvpn_settings.get("ws_port"),
        }

        (
            client_protocol,
            client_remote_line,
            obfuscation_directives,
        ) = self._build_client_transport_directives(
            server_address=resolved_server,
            default_port=resolved_port,
            default_protocol=effective_protocol,
            obfuscation_settings=obfuscation_settings,
        )

        is_tcp = "tcp" in client_protocol.lower()
        is_udp = "udp" in client_protocol.lower()

        raw_data_ciphers = openvpn_settings.get("data_ciphers") or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
        if isinstance(raw_data_ciphers, list):
            client_data_ciphers = ":".join([cipher.strip() for cipher in raw_data_ciphers if cipher and cipher.strip()])
        else:
            client_data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

        data_cipher_fallback = client_data_ciphers.split(":")[0].strip() if ":" in client_data_ciphers else client_data_ciphers
        auth_digest = str(openvpn_settings.get("auth_digest") or "SHA256").strip().upper()
        tls_version_min = str(openvpn_settings.get("tls_version_min") or "1.2").strip()
        tls_mode = str(openvpn_settings.get("tls_mode") or "tls-crypt").strip().lower()
        tun_mtu = _safe_int(openvpn_settings.get("tun_mtu"))
        mssfix = _safe_int(openvpn_settings.get("mssfix"))
        sndbuf = _safe_int(openvpn_settings.get("sndbuf"))
        rcvbuf = _safe_int(openvpn_settings.get("rcvbuf"))
        keepalive_ping = _safe_int(openvpn_settings.get("keepalive_ping"))
        keepalive_timeout = _safe_int(openvpn_settings.get("keepalive_timeout"))
        redirect_gateway = bool(openvpn_settings.get("redirect_gateway", False))
        primary_dns = (openvpn_settings.get("primary_dns") or "").strip()
        secondary_dns = (openvpn_settings.get("secondary_dns") or "").strip()
        push_custom_routes = (openvpn_settings.get("push_custom_routes") or "").strip()
        persist_key = bool(openvpn_settings.get("persist_key", True))
        persist_tun = bool(openvpn_settings.get("persist_tun", True))

        ipv6_enabled, server_ipv6 = self._resolve_client_ipv6_context(general_settings)

        lines = self._get_base_config(
            os_label=os_label,
            client_name=client_name,
            device_type=device_type,
            client_protocol=client_protocol,
            client_remote_line=client_remote_line,
            client_data_ciphers=client_data_ciphers,
            data_cipher_fallback=data_cipher_fallback,
            auth_digest=auth_digest,
            tls_version_min=tls_version_min,
            tls_mode=tls_mode,
            tun_mtu=tun_mtu,
            mssfix=mssfix,
            keepalive_ping=keepalive_ping,
            keepalive_timeout=keepalive_timeout,
            redirect_gateway=redirect_gateway,
            ipv6_enabled=ipv6_enabled,
            primary_dns=primary_dns,
            secondary_dns=secondary_dns,
            push_custom_routes=push_custom_routes,
            persist_key=persist_key,
            persist_tun=persist_tun,
            verbosity=3,
        )

        if os_name == "linux":
            lines.extend(
                [
                    "setenv opt script-security 2",
                    "setenv opt setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "setenv opt up /etc/openvpn/update-resolv-conf",
                    "setenv opt down /etc/openvpn/update-resolv-conf",
                    "setenv opt down-pre",
                ]
            )
            lines = [
                line
                for line in lines
                if not line.strip().lower().startswith("tun-mtu ")
                and not line.strip().lower().startswith("mssfix ")
                and not line.strip().lower().startswith("keepalive ")
                and not line.strip().lower().startswith("sndbuf ")
                and not line.strip().lower().startswith("rcvbuf ")
            ]

        if os_name != "linux" and sndbuf:
            lines.append(f"sndbuf {int(sndbuf)}")
        if os_name != "linux" and rcvbuf:
            lines.append(f"rcvbuf {int(rcvbuf)}")

        tcp_nodelay = bool(openvpn_settings.get("tcp_nodelay", False))
        if tcp_nodelay and is_tcp:
            lines.append("tcp-nodelay")

        explicit_exit_notify = _safe_int(openvpn_settings.get("explicit_exit_notify"))
        if explicit_exit_notify and is_udp:
            lines.append(f"explicit-exit-notify {int(explicit_exit_notify)}")

        if ipv6_enabled:
            self._inject_ipv6_client_directives(
                lines,
                server_ipv6=server_ipv6,
                server_port=resolved_port,
                redirect_gateway=redirect_gateway,
            )

        self._apply_obfuscation(
            lines,
            obfuscation_mode=obfuscation_mode,
            resolved_server=resolved_server,
            openvpn_settings=openvpn_settings,
            prebuilt_directives=obfuscation_directives,
        )

        os_custom_map = {
            "ios": openvpn_settings.get("custom_ios"),
            "android": openvpn_settings.get("custom_android"),
            "windows": openvpn_settings.get("custom_windows"),
            "mac": openvpn_settings.get("custom_mac"),
            "macos": openvpn_settings.get("custom_mac"),
        }
        custom_directives = os_custom_map.get(os_name)
        if custom_directives and (custom_directives or "").strip():
            lines.append("")
            lines.append(f"# Custom {os_name.upper()} Directives")
            for line in (custom_directives or "").strip().splitlines():
                cleaned = line.strip().lower()
                if cleaned:
                    if "comp-lzo" in cleaned or "compress" in cleaned:
                        continue
                    lines.append(line.strip())

        lines.append("")
        lines.append("auth-user-pass")
        enable_auth_nocache = str(openvpn_settings.get("enable_auth_nocache", True)).strip().lower() not in {"0", "false", "no", "off"}
        if enable_auth_nocache:
            lines.append("auth-nocache")

        ca_cert, client_cert, client_key, ta_key = self._get_client_materials(client_name)
        self._append_certificate_blocks(
            lines,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            ta_key=ta_key,
            tls_mode=tls_mode,
        )

        lines.append("")
        return "\n".join(lines)
    
    def generate_client_config(
        self,
        client_name: str,
        server_address: Optional[str] = None,
        server_port: Optional[int] = None,
        protocol: Optional[str] = None,
        os_type: str = "default"
    ) -> Optional[str]:
        """
        Generate .ovpn configuration file for client.
        
        Args:
            client_name: Client identifier
            server_address: Server IP or domain
            server_port: OpenVPN server port
            protocol: udp or tcp
            
        Returns:
            Complete .ovpn configuration as string
        """
        normalized_os = (os_type or "default").strip().lower()

        builder_registry = {
            "ios": lambda ovpn, gen, remote, remote_port, transport_proto: self._generate_apple_config(
                client_name=client_name,
                openvpn_settings=ovpn,
                general_settings=gen,
                server_address=remote,
                server_port=remote_port,
                protocol=transport_proto,
                os_type="ios",
            ),
            "mac": lambda ovpn, gen, remote, remote_port, transport_proto: self._generate_apple_config(
                client_name=client_name,
                openvpn_settings=ovpn,
                general_settings=gen,
                server_address=remote,
                server_port=remote_port,
                protocol=transport_proto,
                os_type="mac",
            ),
            "macos": lambda ovpn, gen, remote, remote_port, transport_proto: self._generate_apple_config(
                client_name=client_name,
                openvpn_settings=ovpn,
                general_settings=gen,
                server_address=remote,
                server_port=remote_port,
                protocol=transport_proto,
                os_type="macos",
            ),
            "android": lambda ovpn, gen, remote, remote_port, transport_proto: self._generate_android_config(
                client_name=client_name,
                openvpn_settings=ovpn,
                general_settings=gen,
                server_address=remote,
                server_port=remote_port,
                protocol=transport_proto,
            ),
            "windows": lambda ovpn, gen, remote, remote_port, transport_proto: self._generate_windows_config(
                client_name=client_name,
                openvpn_settings=ovpn,
                general_settings=gen,
                server_address=remote,
                server_port=remote_port,
                protocol=transport_proto,
            ),
            "win": lambda ovpn, gen, remote, remote_port, transport_proto: self._generate_windows_config(
                client_name=client_name,
                openvpn_settings=ovpn,
                general_settings=gen,
                server_address=remote,
                server_port=remote_port,
                protocol=transport_proto,
            ),
        }

        try:
            openvpn_settings, general_settings = self._load_runtime_settings()

            explicit_server_address = (server_address or "").strip()
            db_server_address = (general_settings.get("server_address") or "").strip()
            db_public_ipv4 = (general_settings.get("public_ipv4_address") or "").strip()
            resolved_server_address = (
                explicit_server_address
                or
                db_server_address
                or db_public_ipv4
            )

            if not resolved_server_address:
                logger.error("Client config generation failed: missing server address in GeneralSettings")
                return None

            resolved_server_port = int(server_port if server_port is not None else (openvpn_settings.get("port") or 1194))
            resolved_protocol = str(protocol or openvpn_settings.get("protocol") or "udp").strip().lower()

            builder = builder_registry.get(normalized_os)
            if builder:
                return builder(
                    openvpn_settings,
                    {
                        **general_settings,
                        "server_address": resolved_server_address,
                    },
                    resolved_server_address,
                    resolved_server_port,
                    resolved_protocol,
                )

            return self._generate_default_config(
                client_name=client_name,
                openvpn_settings=openvpn_settings,
                general_settings=general_settings,
                server_address=resolved_server_address,
                server_port=resolved_server_port,
                protocol=resolved_protocol,
                os_type=normalized_os,
            )
        except Exception as e:
            logger.error(f"Config generation failed for os={normalized_os}: {e}")
            return None

    @staticmethod
    def _extract_remote_hostname(value: str) -> str:
        candidate = (value or "").strip()
        if not candidate:
            return ""

        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        hostname = (parsed.hostname or "").strip()
        if hostname:
            return hostname

        return candidate.split("/")[0].split(":")[0].strip()

    def _build_client_transport_directives(
        self,
        server_address: str,
        default_port: int,
        default_protocol: str,
        obfuscation_settings: Dict[str, any],
    ) -> Tuple[str, str, List[str]]:
        mode = str(obfuscation_settings.get("obfuscation_mode", "standard") or "standard").strip().lower()

        proxy_server = (obfuscation_settings.get("proxy_server") or "").strip()
        proxy_address = (obfuscation_settings.get("proxy_address") or "").strip()
        proxy_target = proxy_server or proxy_address or server_address
        proxy_port = int(obfuscation_settings.get("proxy_port") or 8080)
        spoofed_host = (obfuscation_settings.get("spoofed_host") or "").strip()
        socks_server = (obfuscation_settings.get("socks_server") or "").strip()
        socks_port = obfuscation_settings.get("socks_port")
        stunnel_port = int(obfuscation_settings.get("stunnel_port") or 443)
        sni_domain = (obfuscation_settings.get("sni_domain") or "").strip()
        ws_path = (obfuscation_settings.get("ws_path") or "/stream").strip() or "/stream"
        ws_port = int(obfuscation_settings.get("ws_port") or 8080)
        cdn_raw = (obfuscation_settings.get("cdn_domain") or "").strip()
        cdn_host = self._extract_remote_hostname(cdn_raw)

        if mode == "stealth":
            directives: List[str] = ["http-proxy-retry"]
            if spoofed_host:
                directives.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
            return "tcp", f"remote {server_address} 443", directives

        if mode == "http_proxy_basic":
            directives = [
                f"http-proxy {proxy_target} {proxy_port}",
                "http-proxy-retry",
            ]
            return "tcp", f"remote {server_address} 443", directives

        if mode == "http_proxy_advanced":
            directives: List[str] = [
                f"http-proxy {proxy_target} {proxy_port}",
                "http-proxy-retry",
            ]
            if spoofed_host:
                directives.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
            return "tcp", f"remote {server_address} 443", directives

        if mode == "socks5_proxy_injection":
            socks_target = socks_server or proxy_target
            socks_target_port = int(socks_port or 1080)
            directives = [
                f"socks-proxy {socks_target} {socks_target_port}",
                "socks-proxy-retry",
            ]
            return "tcp", f"remote {server_address} 443", directives

        if mode == "tls_tunnel":
            directives = [
                "# TLS tunnel mode: run local Stunnel client before connecting.",
            ]
            if sni_domain:
                directives.append(f"# TLS SNI domain hint: {sni_domain}")
            return "tcp", f"remote 127.0.0.1 {stunnel_port}", directives

        if mode == "websocket_cdn":
            remote_target = cdn_host or server_address
            directives = [
                f"# WebSocket path hint: {ws_path}",
                f"# Local WebSocket port hint: {ws_port}",
            ]
            return "tcp", f"remote {remote_target} 443", directives

        return default_protocol, f"remote {server_address} {default_port}", []

    def _resolve_client_transport_settings(
        self,
        server_port: Optional[int],
        protocol: Optional[str],
    ) -> Tuple[int, str]:
        if server_port is not None and protocol:
            return int(server_port), str(protocol).strip().lower()

        try:
            from backend.database import SessionLocal
            from backend.models.openvpn_settings import OpenVPNSettings

            db = SessionLocal()
            try:
                settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
                if settings:
                    resolved_port = int(server_port if server_port is not None else settings.port)
                    resolved_protocol = str(protocol or settings.protocol).strip().lower()
                    return resolved_port, resolved_protocol
            finally:
                db.close()
        except Exception as exc:
            logger.warning(f"Falling back to default OpenVPN transport settings: {exc}")

        resolved_port = int(server_port if server_port is not None else 1194)
        resolved_protocol = str(protocol or "udp").strip().lower()
        return resolved_port, resolved_protocol

    def _resolve_client_obfuscation_settings(self) -> Dict[str, any]:
        try:
            from backend.database import SessionLocal
            from backend.models.openvpn_settings import OpenVPNSettings

            db = SessionLocal()
            try:
                settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
                if settings:
                    return {
                        "obfuscation_mode": settings.obfuscation_mode,
                        "proxy_server": settings.proxy_server,
                        "proxy_address": settings.proxy_address,
                        "proxy_port": settings.proxy_port,
                        "spoofed_host": settings.spoofed_host,
                        "socks_server": settings.socks_server,
                        "socks_port": settings.socks_port,
                        "stunnel_port": settings.stunnel_port,
                        "sni_domain": settings.sni_domain,
                        "cdn_domain": settings.cdn_domain,
                        "ws_path": settings.ws_path,
                        "ws_port": settings.ws_port,
                    }
            finally:
                db.close()
        except Exception as exc:
            logger.warning(f"Falling back to default obfuscation settings: {exc}")

        return {
            "obfuscation_mode": "standard",
            "proxy_server": None,
            "proxy_address": None,
            "proxy_port": 8080,
            "spoofed_host": "speedtest.net",
            "socks_server": None,
            "socks_port": None,
            "stunnel_port": 443,
            "sni_domain": None,
            "cdn_domain": None,
            "ws_path": "/stream",
            "ws_port": 8080,
        }

    def _resolve_client_remote_address(
        self,
        server_address: Optional[str],
        protocol: str,
    ) -> str:
        explicit_address = (server_address or "").strip()
        if explicit_address:
            return explicit_address

        try:
            from backend.database import SessionLocal
            from backend.models.general_settings import GeneralSettings

            db = SessionLocal()
            try:
                settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
                if settings:
                    persisted_address = (settings.server_address or "").strip()
                    if persisted_address:
                        return persisted_address
            finally:
                db.close()
        except Exception as exc:
            logger.warning(f"Falling back to default client remote address: {exc}")

        return ""

    def _validate_openvpn_settings(self, settings: Dict[str, Any]) -> None:
        """Legacy validation - kept for compatibility but should not be used."""
        pass

    def generate_server_config(self, settings: Optional[Dict[str, any]] = None) -> Dict[str, any]:
        """Generate OpenVPN 2.6 server.conf content from persisted settings."""
        try:
            dco_data_ciphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

            def _is_dco_incompatible_directive(directive: str) -> bool:
                normalized = str(directive or "").strip().lower()
                if not normalized:
                    return False

                normalized = normalized.strip('"\'')
                return (
                    normalized == "comp-lzo"
                    or normalized.startswith("comp-lzo ")
                    or normalized == "compress"
                    or normalized.startswith("compress ")
                    or normalized == "disable-dco"
                    or normalized.startswith("disable-dco ")
                    or normalized == "packet-filter"
                    or normalized.startswith("packet-filter ")
                )

            runtime_openvpn_settings, _ = self._load_runtime_settings()
            effective_settings: Dict[str, any] = dict(runtime_openvpn_settings)
            if settings:
                for key, value in settings.items():
                    if value is not None:
                        effective_settings[key] = value

            settings = effective_settings
            self._validate_openvpn_settings(settings)

            port = int(settings.get("port", 1194))
            protocol = str(settings.get("protocol", "udp")).lower().strip()
            obfuscation_mode = str(settings.get("obfuscation_mode", "standard") or "standard").strip().lower()
            if obfuscation_mode != "standard":
                protocol = "tcp"
            device_type = str(settings.get("device_type", "tun")).lower().strip()
            topology = str(settings.get("topology", "subnet")).lower().strip()
            ipv4_network = str(settings.get("ipv4_network", "10.8.0.0")).strip()
            ipv4_netmask = str(settings.get("ipv4_netmask", "255.255.255.0")).strip()
            legacy_ipv4_pool = str(settings.get("ipv4_pool", "")).strip()
            if legacy_ipv4_pool and not settings.get("ipv4_network"):
                parts = [part for part in legacy_ipv4_pool.split() if part]
                if len(parts) >= 2:
                    ipv4_network, ipv4_netmask = parts[0], parts[1]

            ipv6_network = (settings.get("ipv6_network") or "").strip()
            ipv6_prefix = settings.get("ipv6_prefix")
            legacy_ipv6_pool = (settings.get("ipv6_pool") or "").strip()
            if legacy_ipv6_pool and not ipv6_network:
                if "/" in legacy_ipv6_pool:
                    pool_parts = legacy_ipv6_pool.split("/", 1)
                    ipv6_network = pool_parts[0].strip()
                    try:
                        ipv6_prefix = int(pool_parts[1].strip())
                    except ValueError:
                        ipv6_prefix = None
                else:
                    ipv6_network = legacy_ipv6_pool

            ipv4_pool = f"{ipv4_network} {ipv4_netmask}".strip()
            max_clients = int(settings.get("max_clients", 100))
            client_to_client = bool(settings.get("client_to_client", False))

            redirect_gateway = bool(settings.get("redirect_gateway", True))
            primary_dns = str(settings.get("primary_dns", "8.8.8.8")).strip()
            secondary_dns = str(settings.get("secondary_dns", "1.1.1.1")).strip()
            block_outside_dns = bool(settings.get("block_outside_dns", False))
            push_custom_routes = (settings.get("push_custom_routes") or "").strip()

            data_ciphers = dco_data_ciphers

            tls_version_min = str(settings.get("tls_version_min", "1.2")).strip()
            tls_mode = str(settings.get("tls_mode", "tls-crypt")).lower().strip()
            auth_digest = str(settings.get("auth_digest", "SHA256")).upper().strip()
            reneg_sec = int(settings.get("reneg_sec", 3600))

            def _safe_int(value, default=None):
                try:
                    if value is None or (isinstance(value, str) and not value.strip()):
                        return default
                    return int(value)
                except (ValueError, TypeError):
                    return default

            tun_mtu = _safe_int(settings.get("tun_mtu"))
            mssfix = _safe_int(settings.get("mssfix"))
            sndbuf = _safe_int(settings.get("sndbuf"))
            rcvbuf = _safe_int(settings.get("rcvbuf"))
            fast_io = bool(settings.get("fast_io", False))
            tcp_nodelay = bool(settings.get("tcp_nodelay", False))
            explicit_exit_notify = int(settings.get("explicit_exit_notify", 1))

            keepalive_ping = int(settings.get("keepalive_ping", 10))
            keepalive_timeout = int(settings.get("keepalive_timeout", 120))
            inactive_timeout = int(settings.get("inactive_timeout", 300))
            management_port = int(settings.get("management_port", 5555))
            verbosity = int(settings.get("verbosity", 3))

            custom_directives = (settings.get("custom_directives") or "").strip()

            if protocol not in {"udp", "tcp", "udp6", "tcp6"}:
                raise ValueError("Protocol must be udp, tcp, udp6, or tcp6")
            if device_type not in {"tun", "tap"}:
                raise ValueError("Device type must be tun or tap")
            if topology != "subnet":
                raise ValueError("Topology must be subnet")
            if tls_version_min not in {"1.2", "1.3"}:
                raise ValueError("TLS minimum version must be 1.2 or 1.3")
            if tls_mode not in {"tls-crypt", "tls-auth", "none"}:
                raise ValueError("TLS mode must be tls-crypt, tls-auth, or none")
            if auth_digest not in {"SHA256", "SHA384", "SHA512"}:
                raise ValueError("Auth digest must be SHA256, SHA384, or SHA512")

            push_lines: List[str] = []
            if redirect_gateway:
                ipv6_enabled = bool(ipv6_network and ipv6_prefix is not None)
                if ipv6_enabled:
                    push_lines.append('push "redirect-gateway def1 ipv6 bypass-dhcp"')
                else:
                    push_lines.append('push "redirect-gateway def1 bypass-dhcp"')
            if primary_dns:
                push_lines.append(f'push "dhcp-option DNS {primary_dns}"')
            if secondary_dns:
                push_lines.append(f'push "dhcp-option DNS {secondary_dns}"')
            if block_outside_dns:
                push_lines.append('push "block-outside-dns"')
            # Custom Routes (comma or newline separated)
            push_custom_routes = (settings.get("push_custom_routes") or "").strip()
            if push_custom_routes:
                for route in [seg.strip() for seg in push_custom_routes.replace(',', '\n').splitlines() if seg.strip()]:
                    # Normalize and prepend push route
                    sanitized = route.replace('route ', '').strip()
                    push_lines.append(f'push "route {sanitized}"')
            
            advanced_client_push = (settings.get("advanced_client_push") or "").strip()
            if advanced_client_push:
                for directive in [line.strip() for line in advanced_client_push.splitlines() if line.strip()]:
                    if directive.startswith("push "):
                        directive_body = directive[5:].strip().strip('"').strip("'")
                        if _is_dco_incompatible_directive(directive_body):
                            logger.warning("Skipping DCO-incompatible advanced push directive: %s", directive)
                            continue
                        push_lines.append(directive)
                    else:
                        if _is_dco_incompatible_directive(directive):
                            logger.warning("Skipping DCO-incompatible advanced push directive: %s", directive)
                            continue
                        push_lines.append(f'push "{directive}"')

            if tls_mode == "tls-crypt":
                tls_mode_line = f"tls-crypt {self.config.TA_KEY}"
            elif tls_mode == "tls-auth":
                tls_mode_line = f"tls-auth {self.config.TA_KEY} 0"
            else:
                tls_mode_line = None

            server_lines: List[str] = [
                "# Atlas VPN - OpenVPN Server Configuration",
                f"# Generated: {datetime.utcnow().isoformat()}",
                "# Optimized for Data Channel Offload (DCO) - OpenVPN 2.6+.",
                "",
                f"port {port}",
                f"proto {protocol}",
                f"dev {device_type}",
                f"topology {topology}",
                f"server {ipv4_pool}",
            ]

            if ipv6_network and ipv6_prefix is not None:
                server_lines.append(f"server-ipv6 {ipv6_network}/{int(ipv6_prefix)}")

            if max_clients:
                server_lines.append(f"max-clients {max_clients}")
            if client_to_client:
                server_lines.append("client-to-client")

            server_lines.extend(
                [
                    "",
                    f"ca {self.config.CA_CERT}",
                    f"cert {self.config.SERVER_CERT}",
                    f"key {self.config.SERVER_KEY}",
                    f"dh {self.config.DH_PARAMS}",
                    f"crl-verify {self.config.CRL_FILE}",
                ]
            )

            if data_ciphers:
                server_lines.append(f"data-ciphers {data_ciphers}")
                server_lines.append("data-ciphers-fallback AES-256-GCM")
            if auth_digest:
                server_lines.append(f"auth {auth_digest}")
            if tls_version_min:
                server_lines.append(f"tls-version-min {tls_version_min}")
            if tls_mode_line:
                server_lines.append(tls_mode_line)
            if reneg_sec is not None:
                server_lines.append(f"reneg-sec {int(reneg_sec)}")

            if keepalive_ping and keepalive_timeout:
                server_lines.append(f"keepalive {keepalive_ping} {keepalive_timeout}")
            if inactive_timeout and int(inactive_timeout) > 0:
                server_lines.append(f"inactive {int(inactive_timeout)}")

            server_lines.extend(["persist-key", "persist-tun"])

            if sndbuf and int(sndbuf) > 0:
                server_lines.append(f"sndbuf {int(sndbuf)}")
            if rcvbuf and int(rcvbuf) > 0:
                server_lines.append(f"rcvbuf {int(rcvbuf)}")
            if fast_io and protocol in {"udp", "udp6"}:
                server_lines.append("fast-io")
            if tcp_nodelay and protocol in {"tcp", "tcp6"}:
                server_lines.append("tcp-nodelay")
            if tun_mtu and int(tun_mtu) > 0:
                server_lines.append(f"tun-mtu {int(tun_mtu)}")
            if mssfix and int(mssfix) > 0:
                server_lines.append(f"mssfix {int(mssfix)}")
            if protocol in {"udp", "udp6"} and explicit_exit_notify and int(explicit_exit_notify) > 0:
                server_lines.append(f"explicit-exit-notify {int(explicit_exit_notify)}")
            if management_port and int(management_port) > 0:
                server_lines.append(f"management 127.0.0.1 {int(management_port)}")
            server_lines.append(f"status {self.config.STATUS_LOG}")
            server_lines.append("status-version 2")
            server_lines.append("suppress-timestamps")

            enforcement_hook_path = self._ensure_realtime_enforcement_hook()
            auth_user_pass_script = self._ensure_auth_user_pass_script()
            db_path = self._resolve_sqlite_db_path()
            server_lines.extend(
                [
                    "script-security 2",
                    f"setenv ATLAS_DB_PATH {db_path}" if db_path else "# setenv ATLAS_DB_PATH <path_to_atlas.db>",
                    f'auth-user-pass-verify "{auth_user_pass_script}" via-file',
                    "username-as-common-name",
                    f'client-connect "{enforcement_hook_path} connect"',
                    f'client-disconnect "{enforcement_hook_path} disconnect"',
                ]
            )

            if push_lines:
                server_lines.append("")
                server_lines.extend(push_lines)

            # Keep OpenVPN running as root for Atlas auth/enforcement scripts.
            # Dropping to nobody/nogroup has caused repeated AUTH_FAILED regressions
            # in production due to systemd sandboxing and sqlite file access constraints.
            server_lines.append("")
            if verbosity is not None:
                server_lines.append(f"verb {int(verbosity)}")

            if custom_directives:
                server_lines.append("")
                for directive in [line.strip() for line in custom_directives.splitlines() if line.strip()]:
                    if _is_dco_incompatible_directive(directive):
                        logger.warning("Skipping DCO-incompatible server custom directive: %s", directive)
                        continue
                    server_lines.append(directive)

            server_lines.append("")
            server_conf = "\n".join(server_lines)

            primary_conf_path, compatibility_conf_path = self._get_server_conf_paths()

            if self.is_production:
                primary_conf_path.parent.mkdir(parents=True, exist_ok=True)
                primary_conf_path.write_text(server_conf)

                try:
                    compatibility_conf_path.parent.mkdir(parents=True, exist_ok=True)
                    compatibility_conf_path.write_text(server_conf)
                except Exception as compat_exc:
                    logger.warning(
                        "Failed to write compatibility OpenVPN server config at %s: %s",
                        compatibility_conf_path,
                        compat_exc,
                    )

                self._harden_sensitive_file_permissions()
                logger.info(
                    "OpenVPN server configuration written to %s (compatibility copy: %s)",
                    primary_conf_path,
                    compatibility_conf_path,
                )
            else:
                logger.info("[MOCK] OpenVPN server configuration generated (not written in development mode)")

            return {
                "success": True,
                "message": "OpenVPN server configuration generated successfully",
                "config_path": str(primary_conf_path),
                "compatibility_config_path": str(compatibility_conf_path),
                "content": server_conf,
                "is_mock": not self.is_production,
            }

        except Exception as e:
            logger.error(f"OpenVPN server configuration generation failed: {e}")
            return {
                "success": False,
                "message": f"Failed to generate OpenVPN server configuration: {str(e)}",
                "error": str(e),
            }

    def _get_os_specific_directives(self, os_type: str) -> str:
        """Return additional directives optimized for target client OS."""
        directives_by_os = {
            "windows": "setenv opt block-outside-dns\nregister-dns",
            "mac": "resolv-retry 30\nroute-delay 2",
            "macos": "resolv-retry 30\nroute-delay 2",
            "ios": "resolv-retry 30\nexplicit-exit-notify",
            "mac_ios": "resolv-retry 30\nexplicit-exit-notify",
            "android": "explicit-exit-notify\nremote-cert-tls server",
            "linux": "resolv-retry infinite\nscript-security 2"
        }
        return directives_by_os.get(os_type, "")
    
    def generate_qr_code(self, config_content: str) -> Optional[str]:
        """
        Generate QR code for mobile clients.
        
        Args:
            config_content: .ovpn configuration content
            
        Returns:
            Base64 encoded PNG image
        """
        try:
            qr = qrcode.QRCode(
                version=None,  # Auto-determine size
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(config_content)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
            
        except Exception as e:
            logger.error(f"QR code generation failed: {e}")
            return None
    
    def get_service_status(self) -> Dict[str, any]:
        """
        Get OpenVPN service status using systemctl.
        
        Returns:
            Dict with service status information
        """
        try:
            success, stdout, stderr = self._run_command([
                "systemctl",
                "status",
                self.service_name
            ], check=False)
            
            # Parse systemctl output
            is_active = "active (running)" in stdout
            is_enabled = "enabled" in stdout
            
            return {
                "success": True,
                "service_name": self.service_name,
                "is_active": is_active,
                "is_enabled": is_enabled,
                "status_output": stdout,
                "is_mock": not self.is_production
            }
            
        except Exception as e:
            logger.error(f"Service status check failed: {e}")
            return {
                "success": False,
                "message": f"Status check failed: {str(e)}",
                "error": str(e)
            }
    
    def control_service(self, action: str) -> Dict[str, any]:
        """
        Control OpenVPN service (start/stop/restart).
        
        Args:
            action: start, stop, restart, or enable
            
        Returns:
            Dict with operation result
        """
        if action not in ["start", "stop", "restart", "enable", "disable"]:
            return {
                "success": False,
                "message": f"Invalid action: {action}"
            }
        
        try:
            success, stdout, stderr = self._run_command([
                "systemctl",
                action,
                self.service_name
            ])
            
            return {
                "success": success,
                "action": action,
                "service_name": self.service_name,
                "message": f"Service {action} completed",
                "is_mock": not self.is_production
            }
            
        except Exception as e:
            logger.error(f"Service control failed: {e}")
            return {
                "success": False,
                "message": f"Service {action} failed: {str(e)}",
                "error": str(e)
            }
