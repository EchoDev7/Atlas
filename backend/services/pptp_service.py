from __future__ import annotations

from typing import Any, Dict, Optional

from backend.core.config import PPTP_DEFAULT_PORT
from backend.core.ppp_manager import PPPManager
from backend.models.vpn_user import VPNUser
from backend.services.protocols.base import BaseProtocolService


class PPTPService(BaseProtocolService):
    """Enterprise adapter for PPTP over shared PPP manager."""

    protocol_name = "pptp"

    def __init__(self, manager: Optional[PPPManager] = None) -> None:
        self._manager = manager or PPPManager()

    def start_client(self, db: Any, username: str) -> Dict[str, Any]:
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "message": "Missing username", "protocol": self.protocol_name}

        user = db.query(VPNUser).filter(VPNUser.username == normalized_username).first()
        if user is None:
            return {"success": False, "message": "User not found", "protocol": self.protocol_name}

        ppp_password = str(user.ppp_password or "").strip() or self._manager.generate_ppp_password()
        if not str(user.ppp_password or "").strip():
            user.ppp_password = ppp_password
            db.flush()

        result = self._manager.ensure_user_credentials(normalized_username, ppp_password)
        return {
            "success": bool(result.get("success")),
            "protocol": self.protocol_name,
            "username": normalized_username,
            "ppp_password": ppp_password,
            "port": PPTP_DEFAULT_PORT,
            "message": "PPTP credentials provisioned",
        }

    def stop_client(self, username: str) -> Dict[str, Any]:
        return self._manager.disconnect_user(username, protocol=self.protocol_name)

    def kill_user(self, username: str) -> Dict[str, Any]:
        return self.stop_client(username)

    def get_status(self, db: Optional[Any] = None) -> Dict[str, Any]:
        _ = db
        sessions = self._manager.get_active_sessions(protocol=self.protocol_name)
        online = sorted({str(item.get("username") or "").strip() for item in sessions if str(item.get("username") or "").strip()})
        return {
            "success": True,
            "protocol": self.protocol_name,
            "port": PPTP_DEFAULT_PORT,
            "active_sessions": len(sessions),
            "online_usernames": online,
        }

    async def enforce_limits(self, db: Any) -> Dict[str, Any]:
        _ = db
        return {
            "success": True,
            "protocol": self.protocol_name,
            "message": "PPTP enforcement is delegated to global scheduler policy",
        }

    def get_active_sessions(self) -> list[dict[str, Any]]:
        return self._manager.get_active_sessions(protocol=self.protocol_name)

    def get_traffic_usage(self, username: Optional[str] = None) -> Dict[str, Any]:
        return self._manager.get_traffic_usage(username=username, protocol=self.protocol_name)

    def ensure_credentials(self, username: str, password: Optional[str]) -> Dict[str, Any]:
        return self._manager.ensure_user_credentials(username, password)
