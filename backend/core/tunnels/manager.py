from __future__ import annotations

from importlib import import_module

from backend.models.general_settings import GeneralSettings


class TunnelManager:
    """Loads tunnel implementations dynamically based on persisted mode."""

    TUNNEL_CLASS_MAP = {
        "direct": "backend.core.tunnels.tunnels.direct.DirectTunnel",
        "dnstt": "backend.core.tunnels.tunnels.direct.DirectTunnel",
        "gost": "backend.core.tunnels.tunnels.direct.DirectTunnel",
        "xray": "backend.core.tunnels.tunnels.direct.DirectTunnel",
    }

    def resolve_mode(self, settings: GeneralSettings) -> str:
        mode = str(getattr(settings, "tunnel_mode", "direct") or "direct").strip().lower()
        return mode if mode in self.TUNNEL_CLASS_MAP else "direct"

    def _load_class(self, class_path: str):
        module_path, class_name = class_path.rsplit(".", 1)
        module = import_module(module_path)
        return getattr(module, class_name)

    def get_tunnel(self, settings: GeneralSettings):
        mode = self.resolve_mode(settings)
        class_path = self.TUNNEL_CLASS_MAP.get(mode, self.TUNNEL_CLASS_MAP["direct"])
        tunnel_cls = self._load_class(class_path)
        return tunnel_cls(settings=settings)
