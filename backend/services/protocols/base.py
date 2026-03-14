from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseProtocolService(ABC):
    """Enterprise protocol service interface for adapter-based protocol operations."""

    protocol_name: str = "unknown"

    @abstractmethod
    def start_client(self, db: Any, username: str) -> Dict[str, Any]:
        """Start or activate protocol access for a specific client/user."""
        raise NotImplementedError

    @abstractmethod
    def stop_client(self, username: str) -> Dict[str, Any]:
        """Stop or disconnect protocol access for a specific client/user."""
        raise NotImplementedError

    @abstractmethod
    def get_status(self, db: Optional[Any] = None) -> Dict[str, Any]:
        """Return protocol service status and high-level runtime health."""
        raise NotImplementedError

    @abstractmethod
    async def enforce_limits(self, db: Any) -> Dict[str, Any]:
        """Run protocol-specific runtime limit enforcement logic."""
        raise NotImplementedError
