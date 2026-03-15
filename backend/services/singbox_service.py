from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from backend.models.general_settings import GeneralSettings
from backend.models.vpn_user import VPNUser
from backend.services.protocols.base import BaseProtocolService


class SingBoxService(BaseProtocolService):
    """Protocol adapter for sing-box core runtime."""

    protocol_name = "singbox"
    service_name = "sing-box"
    config_path = Path("/usr/local/etc/sing-box/config.json")
    _allowed_log_levels = {"trace", "debug", "info", "warn", "error", "fatal"}

    def start_client(self, db: Any, username: str) -> Dict[str, Any]:
        _ = db
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}
        return {
            "success": True,
            "protocol": self.protocol_name,
            "username": normalized_username,
            "message": "Sing-box client runtime is protocol-specific and not enabled in Phase 1",
        }

    def stop_client(self, username: str) -> Dict[str, Any]:
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}
        return {
            "success": True,
            "protocol": self.protocol_name,
            "username": normalized_username,
            "message": "Sing-box client runtime disconnect is not enabled in Phase 1",
        }

    def get_status(self, db: Optional[Any] = None) -> Dict[str, Any]:
        _ = db
        if shutil.which("systemctl") is None:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "service_name": self.service_name,
                "message": "systemctl is not available",
            }

        active = subprocess.run(
            ["systemctl", "is-active", self.service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        enabled = subprocess.run(
            ["systemctl", "is-enabled", self.service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            "success": True,
            "protocol": self.protocol_name,
            "service_name": self.service_name,
            "is_active": active.returncode == 0 and active.stdout.strip().lower() == "active",
            "is_enabled": enabled.returncode == 0 and enabled.stdout.strip().lower() in {"enabled", "static", "indirect", "generated"},
        }

    async def enforce_limits(self, db: Any) -> Dict[str, Any]:
        _ = db
        return {
            "success": True,
            "protocol": self.protocol_name,
            "message": "Sing-box enforcement is delegated to future protocol adapters",
        }

    def apply_settings(self, db: Any) -> Dict[str, Any]:
        settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
        if settings is None:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": "General settings not found",
            }
        raw_level = str(getattr(settings, "singbox_log_level", "info") or "info").strip().lower()
        log_level = raw_level if raw_level in self._allowed_log_levels else "info"
        vless_port = int(getattr(settings, "vless_port", 443) or 443)
        if vless_port < 1 or vless_port > 65535:
            vless_port = 443

        reality_sni = str(getattr(settings, "singbox_reality_sni", "yahoo.com") or "yahoo.com").strip() or "yahoo.com"
        reality_private_key = str(getattr(settings, "singbox_reality_private_key", "") or "").strip()
        reality_short_ids_raw = str(getattr(settings, "singbox_reality_short_ids", "0123456789abcdef") or "0123456789abcdef")
        reality_short_ids = [value.strip().lower() for value in reality_short_ids_raw.split(",") if value.strip()]
        if not reality_short_ids:
            reality_short_ids = ["0123456789abcdef"]

        active_users = (
            db.query(VPNUser)
            .filter(VPNUser.is_enabled.is_(True))
            .order_by(VPNUser.id.asc())
            .all()
        )
        vless_users = []
        for user in active_users:
            if not bool(getattr(user, "is_active", False)):
                continue
            user_uuid = str(getattr(user, "vless_uuid", "") or "").strip()
            if not user_uuid:
                continue
            vless_users.append(
                {
                    "name": str(user.username),
                    "uuid": user_uuid,
                    "flow": "xtls-rprx-vision",
                }
            )

        config_payload = {
            "log": {"level": log_level},
            "inbounds": [],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": []},
        }

        if bool(getattr(settings, "enable_vless", True)):
            config_payload["inbounds"].append(
                {
                    "type": "vless",
                    "tag": "vless-in",
                    "listen": "::",
                    "listen_port": vless_port,
                    "users": vless_users,
                    "tls": {
                        "enabled": True,
                        "server_name": reality_sni,
                        "reality": {
                            "enabled": True,
                            "handshake": {"server": reality_sni, "server_port": 443},
                            "private_key": reality_private_key,
                            "short_id": reality_short_ids,
                        },
                    },
                }
            )
            config_payload["route"]["rules"].append({"inbound": "vless-in", "action": "sniff"})

        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(
                json.dumps(config_payload, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
        except Exception as exc:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": f"Failed to write sing-box config: {exc}",
            }

        restart_result = self._restart_service()
        if not restart_result.get("success"):
            return restart_result

        return {
            "success": True,
            "protocol": self.protocol_name,
            "service_name": self.service_name,
            "config_path": str(self.config_path),
            "log_level": log_level,
            "message": "Sing-box core config applied successfully",
        }

    def _restart_service(self) -> Dict[str, Any]:
        if shutil.which("systemctl") is None:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": "systemctl is not available",
            }

        process = subprocess.run(
            ["systemctl", "restart", self.service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": process.stderr.strip() or process.stdout.strip() or "Failed to restart sing-box service",
            }
        return {"success": True, "protocol": self.protocol_name, "service_name": self.service_name}
