from __future__ import annotations

from backend.core.tunnels.base import BaseTunnel


class DirectTunnel(BaseTunnel):
    """Dummy tunnel implementation for direct mode."""

    mode = "direct"

    def setup_domestic(self) -> dict:
        return {
            "success": True,
            "mode": self.mode,
            "message": "Domestic node is ready for direct relay mode",
        }

    def setup_foreign(self) -> dict:
        return {
            "success": True,
            "mode": self.mode,
            "message": "Foreign node placeholder setup completed",
        }

    def start(self) -> dict:
        return {
            "success": True,
            "mode": self.mode,
            "message": "Direct tunnel dummy start completed",
        }

    def stop(self) -> dict:
        return {
            "success": True,
            "mode": self.mode,
            "message": "Direct tunnel dummy stop completed",
        }
