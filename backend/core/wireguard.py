import base64
import ipaddress
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class WireGuardConfig:
    """WireGuard runtime paths and service naming."""

    BASE_DIR = Path("/etc/wireguard")
    DEFAULT_INTERFACE = "wg0"
    SERVICE_TEMPLATE = "wg-quick@{interface}"


class WireGuardManager:
    """Core WireGuard manager for key generation, config rendering, and service control."""

    def __init__(self) -> None:
        self.config = WireGuardConfig()
        self.protocol_name = "wireguard"

    @staticmethod
    def _run_command(command: list[str], input_text: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            check=check,
        )

    @staticmethod
    def _validate_key_material(key: str) -> None:
        normalized = (key or "").strip()
        if not normalized:
            raise ValueError("WireGuard key cannot be empty")

        try:
            decoded = base64.b64decode(normalized, validate=True)
        except Exception as exc:
            raise ValueError("WireGuard key is not valid base64") from exc

        if len(decoded) != 32:
            raise ValueError("WireGuard key must decode to 32 bytes")

    @staticmethod
    def _validate_interface_name(interface_name: str) -> str:
        normalized = (interface_name or "").strip()
        if not normalized:
            raise ValueError("WireGuard interface name cannot be empty")
        if len(normalized) > 15:
            raise ValueError("WireGuard interface name must be 15 characters or fewer")
        if not re.fullmatch(r"[a-zA-Z0-9_=+.-]+", normalized):
            raise ValueError("WireGuard interface name contains invalid characters")
        return normalized

    def generate_server_keypair(self) -> Tuple[str, str]:
        """Generate WireGuard private/public key pair using wg(8)."""
        try:
            private_result = self._run_command(["wg", "genkey"])
            private_key = private_result.stdout.strip()
            self._validate_key_material(private_key)

            public_result = self._run_command(["wg", "pubkey"], input_text=f"{private_key}\n")
            public_key = public_result.stdout.strip()
            self._validate_key_material(public_key)
            return private_key, public_key
        except FileNotFoundError as exc:
            raise RuntimeError("wg command is not available. Install wireguard-tools first.") from exc
        except subprocess.CalledProcessError as exc:
            error_message = (exc.stderr or exc.stdout or str(exc)).strip()
            raise RuntimeError(f"Failed to generate WireGuard key pair: {error_message}") from exc

    @staticmethod
    def _detect_wan_interface() -> str:
        try:
            route_result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in route_result.stdout.splitlines():
                parts = line.strip().split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]
        except Exception:
            pass
        return "eth0"

    @staticmethod
    def _compute_interface_address(address_range: str) -> str:
        network = ipaddress.ip_network((address_range or "").strip(), strict=False)
        first_host = next(network.hosts(), network.network_address)
        return f"{first_host}/{network.prefixlen}"

    def build_server_config(
        self,
        interface_name: str,
        listen_port: int,
        address_range: str,
        private_key: str,
        wan_interface: Optional[str] = None,
    ) -> str:
        """Render wg-quick config with NAT PostUp/PostDown rules."""
        self._validate_interface_name(interface_name or self.config.DEFAULT_INTERFACE)
        clean_private_key = (private_key or "").strip()
        self._validate_key_material(clean_private_key)

        network = ipaddress.ip_network((address_range or "").strip(), strict=False)
        interface_address = self._compute_interface_address(address_range)
        external_interface = self._validate_interface_name(wan_interface or self._detect_wan_interface())

        post_up = (
            f"iptables -C FORWARD -i %i -j ACCEPT || iptables -A FORWARD -i %i -j ACCEPT; "
            f"iptables -C FORWARD -o %i -j ACCEPT || iptables -A FORWARD -o %i -j ACCEPT; "
            f"iptables -t nat -C POSTROUTING -s {network.with_prefixlen} -o {external_interface} -j MASQUERADE || "
            f"iptables -t nat -A POSTROUTING -s {network.with_prefixlen} -o {external_interface} -j MASQUERADE"
        )
        post_down = (
            f"iptables -D FORWARD -i %i -j ACCEPT; "
            f"iptables -D FORWARD -o %i -j ACCEPT; "
            f"iptables -t nat -D POSTROUTING -s {network.with_prefixlen} -o {external_interface} -j MASQUERADE"
        )

        return (
            "[Interface]\n"
            f"Address = {interface_address}\n"
            f"ListenPort = {int(listen_port)}\n"
            f"PrivateKey = {clean_private_key}\n"
            f"PostUp = {post_up}\n"
            f"PostDown = {post_down}\n"
            "SaveConfig = false\n"
        )

    def write_server_config(
        self,
        interface_name: str,
        listen_port: int,
        address_range: str,
        private_key: str,
        wan_interface: Optional[str] = None,
    ) -> Path:
        """Write /etc/wireguard/<interface>.conf with strict permissions."""
        clean_interface = self._validate_interface_name(interface_name or self.config.DEFAULT_INTERFACE)
        self.config.BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

        config_body = self.build_server_config(
            interface_name=clean_interface,
            listen_port=listen_port,
            address_range=address_range,
            private_key=private_key,
            wan_interface=wan_interface,
        )

        config_path = self.config.BASE_DIR / f"{clean_interface}.conf"
        config_path.write_text(config_body, encoding="utf-8")
        config_path.chmod(0o600)
        return config_path

    def apply_interface(self, interface_name: str) -> Dict[str, Any]:
        """Enable and start/restart wg-quick@interface via systemd."""
        clean_interface = self._validate_interface_name(interface_name or self.config.DEFAULT_INTERFACE)
        unit_name = self.config.SERVICE_TEMPLATE.format(interface=clean_interface)

        try:
            enable_result = self._run_command(["systemctl", "enable", unit_name], check=False)
            if enable_result.returncode != 0:
                return {
                    "success": False,
                    "message": (enable_result.stderr or enable_result.stdout or "failed to enable service").strip(),
                }

            active_probe = self._run_command(["systemctl", "is-active", "--quiet", unit_name], check=False)
            action = "restart" if active_probe.returncode == 0 else "start"
            action_result = self._run_command(["systemctl", action, unit_name], check=False)
            if action_result.returncode != 0:
                return {
                    "success": False,
                    "message": (action_result.stderr or action_result.stdout or f"failed to {action} {unit_name}").strip(),
                }

            final_probe = self._run_command(["systemctl", "is-active", "--quiet", unit_name], check=False)
            if final_probe.returncode != 0:
                return {
                    "success": False,
                    "message": f"{unit_name} is not active after {action}",
                }

            return {
                "success": True,
                "message": f"{unit_name} {action}ed successfully",
                "service": unit_name,
            }
        except FileNotFoundError as exc:
            return {"success": False, "message": f"systemctl command is not available: {exc}"}
        except Exception as exc:
            logger.exception("Failed to apply WireGuard interface %s", clean_interface)
            return {"success": False, "message": str(exc)}

    def allocate_next_client_ip(self, address_range: str, existing_allocated_ips: list[str]) -> str:
        """Allocate the next available client IP from the WireGuard subnet."""
        network = ipaddress.ip_network((address_range or "").strip(), strict=False)
        if network.version != 4:
            raise ValueError("WireGuard client allocation currently supports IPv4 CIDR ranges only")

        reserved_server_ip = ipaddress.ip_interface(self._compute_interface_address(address_range)).ip
        used_ips: set[ipaddress.IPv4Address] = set()
        for raw_ip in existing_allocated_ips:
            candidate = (raw_ip or "").strip()
            if not candidate:
                continue
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if parsed.version == 4 and parsed in network:
                used_ips.add(parsed)

        for host in network.hosts():
            if host == reserved_server_ip:
                continue
            if host not in used_ips:
                return str(host)

        raise ValueError(f"No available IPs left in WireGuard subnet {network.with_prefixlen}")

    def generate_user_identity(self, address_range: str, existing_allocated_ips: list[str]) -> Tuple[str, str, str]:
        """Generate WireGuard keypair and allocate a unique client IP for a unified user."""
        private_key, public_key = self.generate_server_keypair()
        allocated_ip = self.allocate_next_client_ip(address_range, existing_allocated_ips)
        return private_key, public_key, allocated_ip

    @staticmethod
    def _user_has_active_wireguard_config(user: Any) -> bool:
        for config in list(getattr(user, "configs", []) or []):
            if getattr(config, "protocol", "") == "wireguard" and bool(getattr(config, "is_active", False)):
                return True
        return False

    def _build_peer_sections(self, peers: list[dict[str, str]]) -> str:
        blocks: list[str] = []
        for peer in peers:
            public_key = (peer.get("public_key") or "").strip()
            allocated_ip = (peer.get("allocated_ip") or "").strip()
            if not public_key or not allocated_ip:
                continue
            self._validate_key_material(public_key)
            blocks.append(
                "\n".join(
                    [
                        "[Peer]",
                        f"PublicKey = {public_key}",
                        f"AllowedIPs = {allocated_ip}/32",
                    ]
                )
            )
        return "\n\n".join(blocks)

    def _reload_interface_smoothly(self, interface_name: str) -> Dict[str, Any]:
        """Try wg syncconf for smooth reload; fall back to systemd restart/start path."""
        clean_interface = self._validate_interface_name(interface_name or self.config.DEFAULT_INTERFACE)
        unit_name = self.config.SERVICE_TEMPLATE.format(interface=clean_interface)

        is_active = self._run_command(["systemctl", "is-active", "--quiet", unit_name], check=False).returncode == 0
        if not is_active:
            return self.apply_interface(clean_interface)

        strip_result = self._run_command(["wg-quick", "strip", clean_interface], check=False)
        if strip_result.returncode == 0 and (strip_result.stdout or "").strip():
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as temp_file:
                    temp_file.write(strip_result.stdout)
                    temp_path = temp_file.name

                sync_result = self._run_command(["wg", "syncconf", clean_interface, temp_path], check=False)
                if sync_result.returncode == 0:
                    return {
                        "success": True,
                        "message": f"wg syncconf applied successfully for {clean_interface}",
                        "service": unit_name,
                        "method": "syncconf",
                    }
            finally:
                if temp_path:
                    try:
                        Path(temp_path).unlink(missing_ok=True)
                    except Exception:
                        pass

        return self.apply_interface(clean_interface)

    def sync_users_to_wg0(self, db: Any) -> Dict[str, Any]:
        """Rebuild wg0 config with [Peer] sections from active unified users and reload interface."""
        from backend.models.general_settings import GeneralSettings
        from backend.models.vpn_user import VPNUser
        from backend.models.wireguard_settings import WireGuardSettings

        settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
        if not settings:
            return {"success": False, "message": "WireGuard settings not found"}

        server_private_key = (settings.server_private_key or "").strip()
        server_public_key = (settings.server_public_key or "").strip()
        if not server_private_key or not server_public_key:
            return {"success": False, "message": "WireGuard server keypair is missing in settings"}

        general_settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
        wan_interface = (getattr(general_settings, "wan_interface", "") or "").strip() or None

        peers: list[dict[str, str]] = []
        users = db.query(VPNUser).all()
        for user in users:
            if not bool(getattr(user, "is_enabled", False)):
                continue
            if not self._user_has_active_wireguard_config(user):
                continue

            user_public_key = (getattr(user, "wg_public_key", "") or "").strip()
            user_ip = (getattr(user, "wg_allocated_ip", "") or "").strip()
            if not user_public_key or not user_ip:
                continue
            peers.append({"public_key": user_public_key, "allocated_ip": user_ip})

        interface_config = self.build_server_config(
            interface_name=settings.interface_name,
            listen_port=settings.listen_port,
            address_range=settings.address_range,
            private_key=server_private_key,
            wan_interface=wan_interface,
        )
        peer_sections = self._build_peer_sections(peers)
        final_config = interface_config if not peer_sections else f"{interface_config}\n{peer_sections}\n"

        config_path = self.config.BASE_DIR / f"{settings.interface_name}.conf"
        self.config.BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        config_path.write_text(final_config, encoding="utf-8")
        config_path.chmod(0o600)

        reload_result = self._reload_interface_smoothly(settings.interface_name)
        if not reload_result.get("success"):
            return reload_result

        reload_result["peer_count"] = len(peers)
        reload_result["config_path"] = str(config_path)
        return reload_result

    def build_client_config_for_user(self, db: Any, user: Any) -> str:
        """Generate WireGuard client .conf content for a unified user."""
        from backend.models.general_settings import GeneralSettings
        from backend.models.wireguard_settings import WireGuardSettings

        settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
        if not settings:
            raise ValueError("WireGuard settings not found")

        general_settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
        endpoint_host = (getattr(settings, "endpoint_address", "") or "").strip()
        if not endpoint_host:
            endpoint_host = (
                (getattr(general_settings, "public_ipv4_address", "") if general_settings else "")
                or (getattr(general_settings, "server_address", "") if general_settings else "")
            )
        endpoint_host = (endpoint_host or "").strip()
        if not endpoint_host:
            raise ValueError("Server endpoint is not configured. Set Endpoint Address or General Settings Server IP first")

        user_private_key = (getattr(user, "wg_private_key", "") or "").strip()
        user_allocated_ip = (getattr(user, "wg_allocated_ip", "") or "").strip()
        server_public_key = (settings.server_public_key or "").strip()
        if not user_private_key or not user_allocated_ip:
            raise ValueError("User WireGuard identity is not fully provisioned")
        if not server_public_key:
            raise ValueError("WireGuard server public key is missing")

        self._validate_key_material(user_private_key)
        self._validate_key_material(server_public_key)

        dns_servers: list[str] = []
        if general_settings:
            for dns_value in [
                getattr(general_settings, "server_system_dns_primary", None),
                getattr(general_settings, "server_system_dns_secondary", None),
            ]:
                candidate = str(dns_value or "").strip()
                if candidate and candidate not in dns_servers:
                    dns_servers.append(candidate)

        lines = [
            "[Interface]",
            f"PrivateKey = {user_private_key}",
            f"Address = {user_allocated_ip}/32",
        ]
        if dns_servers:
            lines.append(f"DNS = {', '.join(dns_servers)}")

        lines.extend(
            [
                "",
                "[Peer]",
                f"PublicKey = {server_public_key}",
                f"Endpoint = {endpoint_host}:{int(settings.listen_port)}",
                "AllowedIPs = 0.0.0.0/0",
                "PersistentKeepalive = 25",
            ]
        )
        return "\n".join(lines) + "\n"

    def get_active_sessions(self) -> list[dict[str, Any]]:
        """Return lightweight active WireGuard peer sessions using `wg show ... dump`."""
        try:
            from backend.database import SessionLocal
            from backend.models.vpn_user import VPNUser
            from backend.models.wireguard_settings import WireGuardSettings

            db = SessionLocal()
            try:
                settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
                if not settings:
                    return []

                interface_name = (settings.interface_name or self.config.DEFAULT_INTERFACE).strip() or self.config.DEFAULT_INTERFACE
                dump_result = self._run_command(["wg", "show", interface_name, "dump"], check=False)
                if dump_result.returncode != 0:
                    return []

                users_by_pub = {
                    (u.wg_public_key or "").strip(): u
                    for u in db.query(VPNUser).all()
                    if (u.wg_public_key or "").strip()
                }

                sessions: list[dict[str, Any]] = []
                for index, line in enumerate((dump_result.stdout or "").splitlines()):
                    if index == 0:
                        continue
                    parts = line.strip().split("\t")
                    if len(parts) < 8:
                        continue

                    public_key = parts[0].strip()
                    user = users_by_pub.get(public_key)
                    if user is None:
                        continue

                    sessions.append(
                        {
                            "username": user.username,
                            "public_key": public_key,
                            "real_address": parts[2].strip() or None,
                            "bytes_received": int(parts[5] or 0),
                            "bytes_sent": int(parts[6] or 0),
                            "latest_handshake": int(parts[4] or 0),
                            "allowed_ips": parts[3].strip(),
                        }
                    )
                return sessions
            finally:
                db.close()
        except Exception:
            return []

    def kill_user(self, username: str) -> dict[str, Any]:
        """Disconnect WireGuard peer by removing it from runtime and syncing server peers."""
        username = (username or "").strip()
        if not username:
            return {"success": False, "message": "Missing username", "protocol": self.protocol_name}

        try:
            from backend.database import SessionLocal
            from backend.models.vpn_user import VPNUser
            from backend.models.wireguard_settings import WireGuardSettings

            db = SessionLocal()
            try:
                user = db.query(VPNUser).filter(VPNUser.username == username).first()
                settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
                if not user or not settings:
                    return {"success": False, "message": "User or WireGuard settings not found", "protocol": self.protocol_name}

                interface_name = (settings.interface_name or self.config.DEFAULT_INTERFACE).strip() or self.config.DEFAULT_INTERFACE
                public_key = (user.wg_public_key or "").strip()
                if public_key:
                    self._run_command(["wg", "set", interface_name, "peer", public_key, "remove"], check=False)

                sync_result = self.sync_users_to_wg0(db)
                db.commit()
                if not sync_result.get("success"):
                    return {"success": False, "message": sync_result.get("message", "Failed to sync WireGuard peers"), "protocol": self.protocol_name}

                return {
                    "success": True,
                    "message": f"Disconnected WireGuard peer for {username}",
                    "protocol": self.protocol_name,
                    "username": username,
                }
            finally:
                db.close()
        except Exception as exc:
            return {"success": False, "message": str(exc), "protocol": self.protocol_name, "username": username}

    def get_traffic_usage(self, username: Optional[str] = None) -> dict[str, Any]:
        """Return aggregate traffic usage from WireGuard runtime sessions."""
        sessions = self.get_active_sessions()
        usage_by_user: dict[str, dict[str, int]] = {}
        for session in sessions:
            key = str(session.get("username") or "").strip()
            if not key:
                continue
            usage = usage_by_user.setdefault(key, {"bytes_received": 0, "bytes_sent": 0, "total_bytes": 0})
            usage["bytes_received"] += int(session.get("bytes_received") or 0)
            usage["bytes_sent"] += int(session.get("bytes_sent") or 0)
            usage["total_bytes"] = usage["bytes_received"] + usage["bytes_sent"]

        if username:
            scoped = usage_by_user.get(username, {"bytes_received": 0, "bytes_sent": 0, "total_bytes": 0})
            return {"protocol": self.protocol_name, "username": username, "usage": scoped}

        return {"protocol": self.protocol_name, "users": usage_by_user, "session_count": len(sessions)}
