import base64
import ipaddress
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class WireGuardConfig:
    """WireGuard runtime paths and service naming."""

    BASE_DIR = Path("/etc/wireguard")
    DEFAULT_INTERFACE = "wg0"
    SERVICE_TEMPLATE = "wg-quick@{interface}"


class WireGuardManager:
    """Core WireGuard manager for key generation, config rendering, and service control."""

    def __init__(self) -> None:
        self.config = WireGuardConfig()

    @staticmethod
    def _run_command(command: list[str], input_text: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            check=check,
        )

    @staticmethod
    def _validate_key_material(key: str) -> None:
        normalized = (key or "").strip()
        if not normalized:
            raise ValueError("WireGuard key cannot be empty")

        try:
            decoded = base64.b64decode(normalized, validate=True)
        except Exception as exc:
            raise ValueError("WireGuard key is not valid base64") from exc

        if len(decoded) != 32:
            raise ValueError("WireGuard key must decode to 32 bytes")

    @staticmethod
    def _validate_interface_name(interface_name: str) -> str:
        normalized = (interface_name or "").strip()
        if not normalized:
            raise ValueError("WireGuard interface name cannot be empty")
        if len(normalized) > 15:
            raise ValueError("WireGuard interface name must be 15 characters or fewer")
        if not re.fullmatch(r"[a-zA-Z0-9_=+.-]+", normalized):
            raise ValueError("WireGuard interface name contains invalid characters")
        return normalized

    def generate_server_keypair(self) -> Tuple[str, str]:
        """Generate WireGuard private/public key pair using wg(8)."""
        try:
            private_result = self._run_command(["wg", "genkey"])
            private_key = private_result.stdout.strip()
            self._validate_key_material(private_key)

            public_result = self._run_command(["wg", "pubkey"], input_text=f"{private_key}\n")
            public_key = public_result.stdout.strip()
            self._validate_key_material(public_key)
            return private_key, public_key
        except FileNotFoundError as exc:
            raise RuntimeError("wg command is not available. Install wireguard-tools first.") from exc
        except subprocess.CalledProcessError as exc:
            error_message = (exc.stderr or exc.stdout or str(exc)).strip()
            raise RuntimeError(f"Failed to generate WireGuard key pair: {error_message}") from exc

    @staticmethod
    def _detect_wan_interface() -> str:
        try:
            route_result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in route_result.stdout.splitlines():
                parts = line.strip().split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]
        except Exception:
            pass
        return "eth0"

    @staticmethod
    def _compute_interface_address(address_range: str) -> str:
        network = ipaddress.ip_network((address_range or "").strip(), strict=False)
        first_host = next(network.hosts(), network.network_address)
        return f"{first_host}/{network.prefixlen}"

    def build_server_config(
        self,
        interface_name: str,
        listen_port: int,
        address_range: str,
        private_key: str,
        wan_interface: Optional[str] = None,
    ) -> str:
        """Render wg-quick config with NAT PostUp/PostDown rules."""
        self._validate_interface_name(interface_name or self.config.DEFAULT_INTERFACE)
        clean_private_key = (private_key or "").strip()
        self._validate_key_material(clean_private_key)

        network = ipaddress.ip_network((address_range or "").strip(), strict=False)
        interface_address = self._compute_interface_address(address_range)
        external_interface = self._validate_interface_name(wan_interface or self._detect_wan_interface())

        post_up = (
            f"iptables -C FORWARD -i %i -j ACCEPT || iptables -A FORWARD -i %i -j ACCEPT; "
            f"iptables -C FORWARD -o %i -j ACCEPT || iptables -A FORWARD -o %i -j ACCEPT; "
            f"iptables -t nat -C POSTROUTING -s {network.with_prefixlen} -o {external_interface} -j MASQUERADE || "
            f"iptables -t nat -A POSTROUTING -s {network.with_prefixlen} -o {external_interface} -j MASQUERADE"
        )
        post_down = (
            f"iptables -D FORWARD -i %i -j ACCEPT; "
            f"iptables -D FORWARD -o %i -j ACCEPT; "
            f"iptables -t nat -D POSTROUTING -s {network.with_prefixlen} -o {external_interface} -j MASQUERADE"
        )

        return (
            "[Interface]\n"
            f"Address = {interface_address}\n"
            f"ListenPort = {int(listen_port)}\n"
            f"PrivateKey = {clean_private_key}\n"
            f"PostUp = {post_up}\n"
            f"PostDown = {post_down}\n"
            "SaveConfig = false\n"
        )

    def write_server_config(
        self,
        interface_name: str,
        listen_port: int,
        address_range: str,
        private_key: str,
        wan_interface: Optional[str] = None,
    ) -> Path:
        """Write /etc/wireguard/<interface>.conf with strict permissions."""
        clean_interface = self._validate_interface_name(interface_name or self.config.DEFAULT_INTERFACE)
        self.config.BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

        config_body = self.build_server_config(
            interface_name=clean_interface,
            listen_port=listen_port,
            address_range=address_range,
            private_key=private_key,
            wan_interface=wan_interface,
        )

        config_path = self.config.BASE_DIR / f"{clean_interface}.conf"
        config_path.write_text(config_body, encoding="utf-8")
        config_path.chmod(0o600)
        return config_path

    def apply_interface(self, interface_name: str) -> Dict[str, Any]:
        """Enable and start/restart wg-quick@interface via systemd."""
        clean_interface = self._validate_interface_name(interface_name or self.config.DEFAULT_INTERFACE)
        unit_name = self.config.SERVICE_TEMPLATE.format(interface=clean_interface)

        try:
            enable_result = self._run_command(["systemctl", "enable", unit_name], check=False)
            if enable_result.returncode != 0:
                return {
                    "success": False,
                    "message": (enable_result.stderr or enable_result.stdout or "failed to enable service").strip(),
                }

            active_probe = self._run_command(["systemctl", "is-active", "--quiet", unit_name], check=False)
            action = "restart" if active_probe.returncode == 0 else "start"
            action_result = self._run_command(["systemctl", action, unit_name], check=False)
            if action_result.returncode != 0:
                return {
                    "success": False,
                    "message": (action_result.stderr or action_result.stdout or f"failed to {action} {unit_name}").strip(),
                }

            final_probe = self._run_command(["systemctl", "is-active", "--quiet", unit_name], check=False)
            if final_probe.returncode != 0:
                return {
                    "success": False,
                    "message": f"{unit_name} is not active after {action}",
                }

            return {
                "success": True,
                "message": f"{unit_name} {action}ed successfully",
                "service": unit_name,
            }
        except FileNotFoundError as exc:
            return {"success": False, "message": f"systemctl command is not available: {exc}"}
        except Exception as exc:
            logger.exception("Failed to apply WireGuard interface %s", clean_interface)
            return {"success": False, "message": str(exc)}
