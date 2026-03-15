from typing import Dict, Union

from backend.services.protocols.base import BaseProtocolService
from backend.services.protocols.base_vpn_service import BaseVPNService
from backend.services.l2tp_service import L2TPService
from backend.services.openconnect_service import OpenConnectService
from backend.services.openvpn_service import OpenVPNService
from backend.services.wireguard_service import WireGuardService


ProtocolService = Union[BaseVPNService, BaseProtocolService]


class ProtocolRegistry:
    """Simple plugin registry for protocol management services."""

    def __init__(self) -> None:
        self._services: Dict[str, ProtocolService] = {}

    def register(self, service: ProtocolService) -> None:
        key = (service.protocol_name or "").strip().lower()
        if not key:
            raise ValueError("Protocol service must define protocol_name")
        self._services[key] = service

    def get(self, protocol_name: str) -> ProtocolService:
        key = (protocol_name or "").strip().lower()
        if key not in self._services:
            raise KeyError(f"Protocol plugin not registered: {protocol_name}")
        return self._services[key]


protocol_registry = ProtocolRegistry()
protocol_registry.register(OpenVPNService())
protocol_registry.register(WireGuardService())
protocol_registry.register(L2TPService())
protocol_registry.register(OpenConnectService())
