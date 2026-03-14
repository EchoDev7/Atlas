# Atlas — WireGuard service: peer management, keypair generation (Phase 2)
# Phase 0: skeleton only

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Set

from backend.core.wireguard import WireGuardManager
from backend.services.protocols.base import BaseProtocolService


class WireGuardService(BaseProtocolService):
    """Enterprise adapter that wraps WireGuard core operations."""

    protocol_name = "wireguard"

    def __init__(self, manager: Optional[WireGuardManager] = None) -> None:
        self._manager = manager or WireGuardManager()

    @property
    def default_interface(self) -> str:
        return self._manager.config.DEFAULT_INTERFACE

    def get_manager(self) -> WireGuardManager:
        return self._manager

    def start_client(self, db: Any, username: str) -> Dict[str, Any]:
        if not (username or "").strip():
            return {"success": False, "message": "Missing username", "protocol": self.protocol_name}
        sync_result = self.sync_users_runtime(db)
        if not sync_result.get("success"):
            return sync_result
        return {
            "success": True,
            "protocol": self.protocol_name,
            "username": username,
            "message": f"WireGuard runtime synchronized for {username}",
        }

    def stop_client(self, username: str) -> Dict[str, Any]:
        return self._manager.kill_user(username)

    def kill_user(self, username: str) -> Dict[str, Any]:
        return self.stop_client(username)

    def get_status(self, db: Optional[Any] = None) -> Dict[str, Any]:
        sessions = self.get_active_sessions()
        return {
            "success": True,
            "protocol": self.protocol_name,
            "active_sessions": len(sessions),
            "online_usernames": sorted({str(item.get("username") or "").strip() for item in sessions if str(item.get("username") or "").strip()}),
        }

    async def enforce_limits(self, db: Any) -> Dict[str, Any]:
        _ = db
        return {
            "success": True,
            "protocol": self.protocol_name,
            "message": "WireGuard enforcement is delegated to global scheduler policy",
        }

    async def sync_runtime_stats(
        self,
        db: Any,
        online_window_seconds: int = 90,
        openvpn_online_usernames: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        return await self._manager.sync_wireguard_stats(
            db,
            online_window_seconds=online_window_seconds,
            openvpn_online_usernames=openvpn_online_usernames,
        )

    def sync_users_runtime(self, db: Any) -> Dict[str, Any]:
        return self._manager.sync_users_to_wg0(db)

    def generate_server_keypair(self) -> tuple[str, str]:
        return self._manager.generate_server_keypair()

    def write_server_config(
        self,
        interface_name: str,
        listen_port: int,
        address_range: str,
        private_key: str,
        wan_interface: Optional[str] = None,
    ) -> Any:
        return self._manager.write_server_config(
            interface_name=interface_name,
            listen_port=listen_port,
            address_range=address_range,
            private_key=private_key,
            wan_interface=wan_interface,
        )

    def apply_interface(self, interface_name: str) -> Dict[str, Any]:
        return self._manager.apply_interface(interface_name)

    def generate_user_identity(self, address_range: str, existing_allocated_ips: list[str]) -> tuple[str, str, str]:
        return self._manager.generate_user_identity(address_range=address_range, existing_allocated_ips=existing_allocated_ips)

    def build_client_config_for_user(self, db: Any, user: Any) -> str:
        return self._manager.build_client_config_for_user(db, user)

    def get_active_sessions(self) -> list[dict[str, Any]]:
        return self._manager.get_active_sessions()

    def get_traffic_usage(self, username: Optional[str] = None) -> dict[str, Any]:
        return self._manager.get_traffic_usage(username=username)

    def reinject_existing_peer(
        self,
        db: Any,
        username: str,
        public_key: str,
        allocated_ip: str,
    ) -> Dict[str, Any]:
        from backend.models.wireguard_settings import WireGuardSettings

        normalized_public_key = (public_key or "").strip()
        normalized_ip = (allocated_ip or "").strip()
        if not normalized_public_key or not normalized_ip:
            return {"success": True, "message": "No WireGuard peer material to re-inject", "protocol": self.protocol_name}

        settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
        if settings is None:
            return {"success": False, "message": "WireGuard server settings are not configured", "protocol": self.protocol_name}

        interface_name = (settings.interface_name or self.default_interface).strip() or self.default_interface
        allowed_ips = normalized_ip if "/" in normalized_ip else f"{normalized_ip}/32"
        command = [
            "wg",
            "set",
            interface_name,
            "peer",
            normalized_public_key,
            "allowed-ips",
            allowed_ips,
        ]
        result = self._manager._run_command(command, check=False)
        if result.returncode != 0:
            return {
                "success": False,
                "message": (result.stderr or result.stdout or "wg set failed").strip(),
                "protocol": self.protocol_name,
                "username": username,
            }

        return {
            "success": True,
            "message": f"Re-injected WireGuard peer for {username}",
            "protocol": self.protocol_name,
            "username": username,
            "interface_name": interface_name,
            "allowed_ips": allowed_ips,
        }

    def get_online_usernames(self, db: Any, online_window_seconds: int = 90) -> Set[str]:
        from backend.models.vpn_user import VPNUser
        from backend.models.wireguard_settings import WireGuardSettings

        settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
        interface_name = ((getattr(settings, "interface_name", "") if settings else "") or self.default_interface).strip() or self.default_interface

        try:
            result = self._manager._run_command(["wg", "show", interface_name, "dump"], check=False)
        except Exception:
            return set()
        if result.returncode != 0:
            return set()

        users_by_public_key = {
            (str(user.wg_public_key or "").strip()): str(user.username or "").strip()
            for user in db.query(VPNUser).all()
            if str(user.wg_public_key or "").strip() and str(user.username or "").strip()
        }
        if not users_by_public_key:
            return set()

        now_epoch = int(datetime.utcnow().timestamp())
        online_usernames: Set[str] = set()
        for raw_line in str(result.stdout or "").splitlines():
            line = (raw_line or "").strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 9:
                public_key = (parts[1] or "").strip()
                latest_handshake = int(parts[5] or 0) if str(parts[5] or "0").isdigit() else 0
            elif len(parts) >= 8:
                public_key = (parts[0] or "").strip()
                latest_handshake = int(parts[4] or 0) if str(parts[4] or "0").isdigit() else 0
            else:
                continue

            username = users_by_public_key.get(public_key)
            if not username:
                continue

            seconds_ago = now_epoch - int(latest_handshake) if latest_handshake > 0 else -1
            if latest_handshake > 0 and seconds_ago <= int(online_window_seconds):
                online_usernames.add(username)

        return online_usernames
