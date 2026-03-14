# Atlas — OpenVPN service: PKI, client create/revoke, service control (Phase 1)
# Phase 0: skeleton only

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from backend.core.openvpn import OpenVPNManager, validate_openvpn_readiness
from backend.services.protocols.base import BaseProtocolService


class OpenVPNService(BaseProtocolService):
    """Enterprise adapter that wraps OpenVPN core operations."""

    protocol_name = "openvpn"

    def __init__(self, manager: Optional[OpenVPNManager] = None) -> None:
        self._manager = manager or OpenVPNManager()

    @property
    def service_name(self) -> str:
        return self._manager.service_name

    def get_manager(self) -> OpenVPNManager:
        return self._manager

    def start_client(self, db: Any, username: str) -> Dict[str, Any]:
        _ = db
        normalized_username = (username or "").strip()
        if not normalized_username:
            return {"success": False, "message": "Missing username", "protocol": self.protocol_name}
        return self.create_client_certificate(normalized_username)

    def stop_client(self, username: str) -> Dict[str, Any]:
        return self._manager.kill_user(username)

    def kill_user(self, username: str) -> Dict[str, Any]:
        return self.stop_client(username)

    def get_status(self, db: Optional[Any] = None) -> Dict[str, Any]:
        _ = db
        return self._manager.get_service_status()

    async def enforce_limits(self, db: Any) -> Dict[str, Any]:
        _ = db
        return {
            "success": True,
            "protocol": self.protocol_name,
            "message": "OpenVPN enforcement is delegated to global scheduler policy",
        }

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        return self._manager.get_active_sessions()

    def get_traffic_usage(self, username: Optional[str] = None) -> Dict[str, Any]:
        return self._manager.get_traffic_usage(username=username)

    def create_client_certificate(self, client_name: str) -> Dict[str, Any]:
        return self._manager.create_client_certificate(client_name)

    def revoke_client_certificate(self, client_name: str) -> Dict[str, Any]:
        return self._manager.revoke_client_certificate(client_name)

    def generate_client_config(self, client_name: str, **kwargs: Any) -> Optional[str]:
        return self._manager.generate_client_config(client_name=client_name, **kwargs)

    def generate_qr_code(self, config_content: str) -> Optional[str]:
        return self._manager.generate_qr_code(config_content)

    def control_service(self, action: str) -> Dict[str, Any]:
        return self._manager.control_service(action)

    def get_runtime_health(self) -> Dict[str, Any]:
        return self._manager.get_runtime_health()

    def sync_auth_database_snapshot(self) -> Dict[str, Any]:
        return self._manager.sync_auth_database_snapshot()

    def stream_ssl_issue_logs(self, domains: List[str], email: str) -> Iterator[str]:
        return self._manager.stream_ssl_issue_logs(domains=domains, email=email)

    def sync_system_general_settings(
        self,
        old_global_ipv6_support: bool,
        new_global_ipv6_support: bool,
        old_timezone: str,
        new_timezone: str,
        old_panel_https_port: int,
        new_panel_https_port: int,
        old_subscription_https_port: int,
        new_subscription_https_port: int,
    ) -> Dict[str, Any]:
        return self._manager.sync_system_general_settings(
            old_global_ipv6_support=old_global_ipv6_support,
            new_global_ipv6_support=new_global_ipv6_support,
            old_timezone=old_timezone,
            new_timezone=new_timezone,
            old_panel_https_port=old_panel_https_port,
            new_panel_https_port=new_panel_https_port,
            old_subscription_https_port=old_subscription_https_port,
            new_subscription_https_port=new_subscription_https_port,
        )

    def sync_firewall_for_transport_change(
        self,
        old_port: int,
        old_protocol: str,
        new_port: int,
        new_protocol: str,
    ) -> Dict[str, Any]:
        return self._manager.sync_firewall_for_transport_change(
            old_port=old_port,
            old_protocol=old_protocol,
            new_port=new_port,
            new_protocol=new_protocol,
        )

    def generate_server_config(self, settings_dict: Dict[str, Any]) -> Dict[str, Any]:
        return self._manager.generate_server_config(settings_dict)

    def get_auth_assets_health(self) -> Dict[str, Any]:
        return self._manager.get_auth_assets_health()

    def validate_readiness(self, general_settings: Any, openvpn_settings: Any) -> List[str]:
        return validate_openvpn_readiness(general_settings, openvpn_settings)

    def get_status_log_path(self) -> Path:
        return self._manager.config.STATUS_LOG

    def get_openvpn_server_dir(self) -> Path:
        return self._manager.config.OPENVPN_SERVER_DIR

    def get_pki_dir(self) -> Path:
        return self._manager.config.PKI_DIR

    def get_server_conf_path(self) -> Path:
        return self._manager.config.SERVER_CONF

    def get_crl_file_path(self) -> Path:
        return self._manager.config.CRL_FILE

    def get_auth_user_pass_script_path(self) -> Path:
        return self._manager.config.AUTH_USER_PASS_SCRIPT

    def get_enforcement_hook_path(self) -> Path:
        return self._manager.config.ENFORCEMENT_HOOK
