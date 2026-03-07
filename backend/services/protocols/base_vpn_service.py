from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseVPNService(ABC):
    """Abstract base for protocol plugins used by monitoring and control layers."""

    protocol_name: str = "unknown"

    @abstractmethod
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Return live active sessions for the protocol."""
        raise NotImplementedError

    @abstractmethod
    def kill_user(self, username: str) -> Dict[str, Any]:
        """Disconnect all active sessions for a username/common_name."""
        raise NotImplementedError

    @abstractmethod
    def get_traffic_usage(self, username: Optional[str] = None) -> Dict[str, Any]:
        """Return traffic usage map (or single user usage) from live protocol state."""
        raise NotImplementedError
