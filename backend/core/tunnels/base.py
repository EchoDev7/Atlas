from __future__ import annotations

from abc import ABC, abstractmethod


class BaseTunnel(ABC):
    """Contract for tunnel implementations used by the master orchestrator."""

    mode: str = "base"

    def __init__(self, *, settings: object):
        self.settings = settings

    @abstractmethod
    def setup_domestic(self) -> dict:
        """Prepare local/master node for selected tunnel mode."""

    @abstractmethod
    def setup_foreign(self) -> dict:
        """Prepare foreign/exit node for selected tunnel mode."""

    @abstractmethod
    def start(self) -> dict:
        """Start the tunnel components."""

    @abstractmethod
    def stop(self) -> dict:
        """Stop the tunnel components."""
