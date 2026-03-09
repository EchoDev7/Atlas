from typing import Dict

from backend.services.protocols.base_vpn_service import BaseVPNService
from backend.core.openvpn import OpenVPNManager
from backend.core.wireguard import WireGuardManager


class ProtocolRegistry:
    """Simple plugin registry for protocol management services."""

    def __init__(self) -> None:
        self._services: Dict[str, BaseVPNService] = {}

    def register(self, service: BaseVPNService) -> None:
        key = (service.protocol_name or "").strip().lower()
        if not key:
            raise ValueError("Protocol service must define protocol_name")
        self._services[key] = service

    def get(self, protocol_name: str) -> BaseVPNService:
        key = (protocol_name or "").strip().lower()
        if key not in self._services:
            raise KeyError(f"Protocol plugin not registered: {protocol_name}")
        return self._services[key]


protocol_registry = ProtocolRegistry()
protocol_registry.register(OpenVPNManager())
protocol_registry.register(WireGuardManager())
