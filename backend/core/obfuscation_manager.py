import logging
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from backend.models.openvpn_settings import OpenVPNSettings

logger = logging.getLogger(__name__)

IS_LINUX = platform.system() == "Linux"


class ObfuscationManager:
    """Manage OS-level automation for OpenVPN obfuscation modes."""

    SQUID_CONFIG_PATH = Path("/etc/squid/squid.conf")

    def __init__(self):
        self.is_production = IS_LINUX
        if not self.is_production:
            logger.warning("Running in DEVELOPMENT mode - obfuscation subprocess calls are mocked")

    @staticmethod
    def _normalize_mode(mode: Optional[str]) -> str:
        return (mode or "standard").strip().lower()

    @staticmethod
    def _normalize_proto(proto: Optional[str]) -> str:
        normalized = (proto or "udp").strip().lower()
        if normalized.startswith("tcp"):
            return "tcp"
        return "udp"

    @staticmethod
    def _requires_http_proxy(mode: str) -> bool:
        return mode in {"http_proxy_basic", "http_proxy_advanced"}

    @staticmethod
    def _requires_transport_override(mode: str) -> bool:
        return mode != "standard"

    def _run_command(self, cmd: List[str], check: bool = False) -> Dict[str, object]:
        try:
            if not self.is_production:
                logger.info("[MOCK] Would execute: %s", " ".join(cmd))
                return {
                    "success": True,
                    "stdout": f"Mock command executed: {' '.join(cmd)}",
                    "stderr": "",
                    "is_mock": True,
                }

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check,
            )
            return {
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "is_mock": False,
            }
        except subprocess.CalledProcessError as exc:
            return {
                "success": False,
                "stdout": exc.stdout or "",
                "stderr": exc.stderr or str(exc),
                "is_mock": False,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "success": False,
                "stdout": "",
                "stderr": str(exc),
                "is_mock": not self.is_production,
            }

    def _command_exists(self, command: str) -> bool:
        if not self.is_production:
            return True
        return shutil.which(command) is not None

    def _ensure_squid_installed(self, executed_commands: List[str]) -> Dict[str, object]:
        if not self.is_production:
            logger.info("[MOCK] Would verify/install squid package")
            return {"success": True, "message": "Squid check skipped in mock mode", "is_mock": True}

        check_result = self._run_command(["dpkg-query", "-W", "-f=${Status}", "squid"], check=False)
        executed_commands.append("dpkg-query -W -f=${Status} squid")
        is_installed = check_result.get("success") and "install ok installed" in str(check_result.get("stdout", ""))

        if is_installed:
            return {"success": True, "message": "Squid already installed", "is_mock": False}

        install_result = self._run_command(["apt-get", "install", "-y", "squid"], check=False)
        executed_commands.append("apt-get install -y squid")
        if not install_result.get("success"):
            return {
                "success": False,
                "message": f"Failed to install squid: {install_result.get('stderr', '').strip()}",
                "is_mock": False,
            }

        return {"success": True, "message": "Squid installed", "is_mock": False}

    def _write_squid_config(self, proxy_port: int, executed_commands: List[str]) -> Dict[str, object]:
        config_content = (
            f"http_port {proxy_port}\n"
            "acl SSL_ports port 443\n"
            "acl CONNECT method CONNECT\n"
            "http_access deny !CONNECT\n"
            "http_access deny CONNECT !SSL_ports\n"
            "http_access allow CONNECT SSL_ports\n"
            "http_access deny all\n"
            "via off\n"
            "forwarded_for delete\n"
            "request_header_access All deny all\n"
        )

        if not self.is_production:
            logger.info("[MOCK] Would write squid config to %s", self.SQUID_CONFIG_PATH)
            logger.info("[MOCK] squid.conf content:\n%s", config_content)
            executed_commands.append(f"write {self.SQUID_CONFIG_PATH}")
            return {"success": True, "message": "Squid config written (mock)", "is_mock": True}

        try:
            self.SQUID_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.SQUID_CONFIG_PATH.write_text(config_content)
            executed_commands.append(f"write {self.SQUID_CONFIG_PATH}")
            return {"success": True, "message": "Squid config written", "is_mock": False}
        except Exception as exc:  # noqa: BLE001
            return {
                "success": False,
                "message": f"Failed to write squid config: {exc}",
                "is_mock": False,
            }

    def _sync_service(self, service_name: str, action: str, executed_commands: List[str]) -> Dict[str, object]:
        cmd = ["systemctl", action, service_name]
        result = self._run_command(cmd, check=False)
        executed_commands.append(" ".join(cmd))
        if not result.get("success"):
            return {
                "success": False,
                "message": f"Failed to run {' '.join(cmd)}: {result.get('stderr', '').strip()}",
                "is_mock": not self.is_production,
            }
        return {
            "success": True,
            "message": f"Service action completed: {' '.join(cmd)}",
            "is_mock": not self.is_production,
        }

    def _allow_port(self, port: int, proto: str, executed_commands: List[str]) -> Dict[str, object]:
        normalized_proto = self._normalize_proto(proto)

        if self._command_exists("ufw"):
            cmd = ["ufw", "allow", f"{port}/{normalized_proto}"]
            result = self._run_command(cmd, check=False)
            executed_commands.append(" ".join(cmd))
            if not result.get("success"):
                return {
                    "success": False,
                    "message": f"Failed to allow firewall rule {port}/{normalized_proto}: {result.get('stderr', '').strip()}",
                }
            return {"success": True, "message": "Firewall allow applied"}

        if self._command_exists("iptables"):
            check_cmd = ["iptables", "-C", "INPUT", "-p", normalized_proto, "--dport", str(port), "-j", "ACCEPT"]
            check_result = self._run_command(check_cmd, check=False)
            executed_commands.append(" ".join(check_cmd))
            if check_result.get("success"):
                return {"success": True, "message": "Firewall allow already present"}

            add_cmd = ["iptables", "-A", "INPUT", "-p", normalized_proto, "--dport", str(port), "-j", "ACCEPT"]
            add_result = self._run_command(add_cmd, check=False)
            executed_commands.append(" ".join(add_cmd))
            if not add_result.get("success"):
                return {
                    "success": False,
                    "message": f"Failed to add iptables allow rule {port}/{normalized_proto}: {add_result.get('stderr', '').strip()}",
                }
            return {"success": True, "message": "iptables allow applied"}

        return {
            "success": False,
            "message": "Neither ufw nor iptables is available to manage firewall",
        }

    def _deny_port(self, port: int, proto: str, executed_commands: List[str]) -> Dict[str, object]:
        normalized_proto = self._normalize_proto(proto)

        if self._command_exists("ufw"):
            cmd = ["ufw", "deny", f"{port}/{normalized_proto}"]
            result = self._run_command(cmd, check=False)
            executed_commands.append(" ".join(cmd))
            if not result.get("success"):
                return {
                    "success": False,
                    "message": f"Failed to deny firewall rule {port}/{normalized_proto}: {result.get('stderr', '').strip()}",
                }
            return {"success": True, "message": "Firewall deny applied"}

        if self._command_exists("iptables"):
            delete_cmd = ["iptables", "-D", "INPUT", "-p", normalized_proto, "--dport", str(port), "-j", "ACCEPT"]
            delete_result = self._run_command(delete_cmd, check=False)
            executed_commands.append(" ".join(delete_cmd))
            if not delete_result.get("success"):
                return {
                    "success": True,
                    "message": "iptables allow rule not present",
                }
            return {"success": True, "message": "iptables allow removed"}

        return {
            "success": False,
            "message": "Neither ufw nor iptables is available to manage firewall",
        }

    def _setup_http_proxy_mode(self, proxy_port: int, executed_commands: List[str]) -> Dict[str, object]:
        install_result = self._ensure_squid_installed(executed_commands)
        if not install_result.get("success"):
            return install_result

        config_result = self._write_squid_config(proxy_port, executed_commands)
        if not config_result.get("success"):
            return config_result

        enable_result = self._sync_service("squid", "enable", executed_commands)
        if not enable_result.get("success"):
            return enable_result

        restart_result = self._sync_service("squid", "restart", executed_commands)
        if not restart_result.get("success"):
            return restart_result

        return {
            "success": True,
            "message": "HTTP proxy mode automation completed",
            "is_mock": not self.is_production,
        }

    def _teardown_http_proxy_mode(self, executed_commands: List[str]) -> Dict[str, object]:
        stop_result = self._sync_service("squid", "stop", executed_commands)
        if not stop_result.get("success"):
            return stop_result

        disable_result = self._sync_service("squid", "disable", executed_commands)
        if not disable_result.get("success"):
            return disable_result

        return {
            "success": True,
            "message": "HTTP proxy service stopped",
            "is_mock": not self.is_production,
        }

    def apply_mode_automation(
        self,
        previous_mode: Optional[str],
        previous_proxy_port: Optional[int],
        settings: OpenVPNSettings,
    ) -> Dict[str, object]:
        """Apply OS-level automation and enforce transport/security overrides for obfuscation mode."""
        mode = self._normalize_mode(settings.obfuscation_mode)
        old_mode = self._normalize_mode(previous_mode)

        executed_commands: List[str] = []
        enforced_values: Dict[str, object] = {}

        try:
            if self._requires_transport_override(mode):
                if settings.port != 443:
                    settings.port = 443
                    enforced_values["port"] = 443
                if self._normalize_proto(settings.protocol) != "tcp":
                    settings.protocol = "tcp"
                    enforced_values["protocol"] = "tcp"
                if (settings.tls_mode or "").strip().lower() != "tls-crypt":
                    settings.tls_mode = "tls-crypt"
                    enforced_values["tls_mode"] = "tls-crypt"

            if self._requires_http_proxy(mode):
                proxy_port = int(settings.proxy_port or 8080)
                settings.proxy_port = proxy_port
                settings.proxy_server = (settings.proxy_server or settings.proxy_address or "").strip() or None
                settings.proxy_address = settings.proxy_server

                proxy_result = self._setup_http_proxy_mode(proxy_port=proxy_port, executed_commands=executed_commands)
                if not proxy_result.get("success"):
                    return {
                        "success": False,
                        "message": proxy_result.get("message", "Failed to setup HTTP proxy mode"),
                        "commands": executed_commands,
                        "is_mock": not self.is_production,
                    }

                proxy_allow = self._allow_port(proxy_port, "tcp", executed_commands)
                if not proxy_allow.get("success"):
                    return {
                        "success": False,
                        "message": proxy_allow.get("message", "Failed to allow proxy port"),
                        "commands": executed_commands,
                        "is_mock": not self.is_production,
                    }

                if self._requires_http_proxy(old_mode) and previous_proxy_port and previous_proxy_port != proxy_port:
                    old_proxy_cleanup = self._deny_port(int(previous_proxy_port), "tcp", executed_commands)
                    if not old_proxy_cleanup.get("success"):
                        return {
                            "success": False,
                            "message": old_proxy_cleanup.get("message", "Failed to cleanup previous proxy port"),
                            "commands": executed_commands,
                            "is_mock": not self.is_production,
                        }

            else:
                if self._requires_http_proxy(old_mode):
                    if previous_proxy_port:
                        old_proxy_cleanup = self._deny_port(int(previous_proxy_port), "tcp", executed_commands)
                        if not old_proxy_cleanup.get("success"):
                            return {
                                "success": False,
                                "message": old_proxy_cleanup.get("message", "Failed to deny previous proxy port"),
                                "commands": executed_commands,
                                "is_mock": not self.is_production,
                            }

                    teardown_result = self._teardown_http_proxy_mode(executed_commands)
                    if not teardown_result.get("success"):
                        return {
                            "success": False,
                            "message": teardown_result.get("message", "Failed to stop squid service"),
                            "commands": executed_commands,
                            "is_mock": not self.is_production,
                        }

                if mode == "standard" and settings.proxy_port:
                    current_proxy_cleanup = self._deny_port(int(settings.proxy_port), "tcp", executed_commands)
                    if not current_proxy_cleanup.get("success"):
                        return {
                            "success": False,
                            "message": current_proxy_cleanup.get("message", "Failed to deny current proxy port"),
                            "commands": executed_commands,
                            "is_mock": not self.is_production,
                        }

            if self._requires_transport_override(mode):
                openvpn_allow = self._allow_port(443, "tcp", executed_commands)
                if not openvpn_allow.get("success"):
                    return {
                        "success": False,
                        "message": openvpn_allow.get("message", "Failed to allow OpenVPN TCP 443"),
                        "commands": executed_commands,
                        "is_mock": not self.is_production,
                    }

            return {
                "success": True,
                "message": "Obfuscation OS-level automation applied successfully",
                "commands": executed_commands,
                "enforced_values": enforced_values,
                "is_mock": not self.is_production,
            }
        except Exception as exc:  # noqa: BLE001
            logger.error("Obfuscation automation failed: %s", exc)
            return {
                "success": False,
                "message": f"Obfuscation automation failed: {exc}",
                "commands": executed_commands,
                "enforced_values": enforced_values,
                "is_mock": not self.is_production,
            }
