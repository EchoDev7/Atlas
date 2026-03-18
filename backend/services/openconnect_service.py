from __future__ import annotations

import ipaddress
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from backend.services.protocols.base import BaseProtocolService


class OpenConnectService(BaseProtocolService):
    """Protocol adapter for OpenConnect (ocserv)."""

    protocol_name = "openconnect"
    service_name = "ocserv"
    config_path = Path("/etc/ocserv/ocserv.conf")
    passwd_file = Path("/etc/ocserv/ocpasswd")

    def start_client(self, db: Any, username: str) -> Dict[str, Any]:
        _ = db
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}
        return {
            "success": True,
            "protocol": self.protocol_name,
            "username": normalized_username,
            "message": "OpenConnect user access is managed via ocpasswd hooks",
        }

    def stop_client(self, username: str) -> Dict[str, Any]:
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}
        return {
            "success": True,
            "protocol": self.protocol_name,
            "username": normalized_username,
            "message": "OpenConnect runtime disconnect is not implemented by ocserv adapter",
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
            "message": "OpenConnect enforcement is delegated to global scheduler policy",
        }

    def apply_settings(self, *, port: int, client_subnet: str) -> Dict[str, Any]:
        if int(port) < 1 or int(port) > 65535:
            raise ValueError("OpenConnect port must be between 1 and 65535")

        normalized_subnet = str(client_subnet or "").strip()
        if not normalized_subnet:
            raise ValueError("OpenConnect client subnet cannot be empty")

        try:
            parsed_subnet = ipaddress.ip_network(normalized_subnet, strict=False)
        except ValueError as exc:
            raise ValueError("OpenConnect client subnet must be a valid IPv4 CIDR") from exc

        if parsed_subnet.version != 4:
            raise ValueError("OpenConnect client subnet must be an IPv4 CIDR")

        current_cert, current_key = self._read_existing_ssl_paths()
        config_content = self._render_ocserv_config(
            port=int(port),
            client_subnet=str(parsed_subnet),
            cert_path=current_cert,
            key_path=current_key,
        )

        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(config_content, encoding="utf-8")
        except Exception as exc:
            return {"success": False, "protocol": self.protocol_name, "message": f"Failed to write ocserv config: {exc}"}

        restart_result = self._restart_service()
        if not restart_result.get("success"):
            return restart_result

        return {
            "success": True,
            "protocol": self.protocol_name,
            "port": int(port),
            "client_subnet": str(parsed_subnet),
            "message": "OpenConnect settings applied successfully",
        }

    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        return self._sync_user_password(username=username, password=password)

    def update_user(self, username: str, password: str) -> Dict[str, Any]:
        return self._sync_user_password(username=username, password=password)

    def delete_user(self, username: str) -> Dict[str, Any]:
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}

        if shutil.which("ocpasswd") is None:
            return {"success": False, "protocol": self.protocol_name, "message": "ocpasswd command is not available"}

        command = ["ocpasswd", "-c", str(self.passwd_file), "-d", normalized_username]
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        if process.returncode != 0:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": process.stderr.strip() or process.stdout.strip() or "Failed to delete ocserv user",
            }

        return {"success": True, "protocol": self.protocol_name, "username": normalized_username}

    def _sync_user_password(self, *, username: str, password: str) -> Dict[str, Any]:
        normalized_username = str(username or "").strip()
        normalized_password = str(password or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}
        if not normalized_password:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing password"}

        if shutil.which("ocpasswd") is None:
            return {"success": False, "protocol": self.protocol_name, "message": "ocpasswd command is not available"}

        command = ["ocpasswd", "-c", str(self.passwd_file), normalized_username]
        process = subprocess.run(
            command,
            input=f"{normalized_password}\n{normalized_password}\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": process.stderr.strip() or process.stdout.strip() or "Failed to update ocserv user",
            }

        return {"success": True, "protocol": self.protocol_name, "username": normalized_username}

    def _read_existing_ssl_paths(self) -> tuple[str, str]:
        cert_path = "/etc/ocserv/ssl/server-cert.pem"
        key_path = "/etc/ocserv/ssl/server-key.pem"

        if not self.config_path.exists() or not self.config_path.is_file():
            return cert_path, key_path

        try:
            lines = self.config_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            return cert_path, key_path

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("server-cert") and "=" in stripped:
                cert_path = stripped.split("=", 1)[1].strip() or cert_path
            elif stripped.startswith("server-key") and "=" in stripped:
                key_path = stripped.split("=", 1)[1].strip() or key_path

        return cert_path, key_path

    def _render_ocserv_config(self, *, port: int, client_subnet: str, cert_path: str, key_path: str) -> str:
        return "\n".join(
            [
                "auth = \"plain[/etc/ocserv/ocpasswd]\"",
                f"tcp-port = {int(port)}",
                f"udp-port = {int(port)}",
                "device = vpns",
                f"ipv4-network = {client_subnet}",
                "ipv4-netmask = 255.255.255.0",
                "max-clients = 1024",
                "max-same-clients = 4",
                "keepalive = 32400",
                "dpd = 90",
                "mobile-dpd = 1800",
                "switch-to-tcp-timeout = 25",
                "default-domain = atlas.local",
                "run-as-user = nobody",
                "run-as-group = daemon",
                "socket-file = /run/ocserv-socket",
                f"server-cert = {cert_path}",
                f"server-key = {key_path}",
                "isolate-workers = true",
                "",
            ]
        )

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
                "message": process.stderr.strip() or process.stdout.strip() or "Failed to restart ocserv service",
            }

        return {"success": True, "protocol": self.protocol_name, "service_name": self.service_name}
