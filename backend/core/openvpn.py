# Atlas — OpenVPN Core Logic
# Phase 2: OpenVPN management with mock support for development

import subprocess
import os
import platform
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterator
from fastapi import HTTPException
from datetime import datetime
import qrcode
import io
import base64
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Detect if running on Linux (production) or Mac/Windows (development)
IS_LINUX = platform.system() == "Linux"


class OpenVPNConfig:
    """
    OpenVPN configuration paths following Ubuntu standard locations.
    Based on official OpenVPN documentation.
    """
    # Standard Ubuntu paths
    OPENVPN_DIR = Path("/etc/openvpn")
    EASYRSA_DIR = Path("/usr/share/easy-rsa")
    PKI_DIR = Path("/etc/openvpn/easy-rsa/pki")
    
    # Server configuration
    SERVER_CONF = OPENVPN_DIR / "server" / "server.conf"
    
    # PKI paths (Easy-RSA 3 standard structure)
    CA_CERT = PKI_DIR / "ca.crt"
    SERVER_CERT = PKI_DIR / "issued" / "server.crt"
    SERVER_KEY = PKI_DIR / "private" / "server.key"
    DH_PARAMS = PKI_DIR / "dh.pem"
    TA_KEY = OPENVPN_DIR / "server" / "ta.key"
    
    # Client certificates directory
    CLIENT_CERTS_DIR = PKI_DIR / "issued"
    CLIENT_KEYS_DIR = PKI_DIR / "private"
    
    # Client configs output directory
    CLIENT_CONFIGS_DIR = Path("/etc/openvpn/client-configs")
    
    # Service name
    SERVICE_NAME = "openvpn-server@server"


class MockOpenVPNResponse:
    """Mock responses for development environment"""
    
    @staticmethod
    def easyrsa_build_client(client_name: str) -> str:
        return f"""
Note: using Easy-RSA configuration from: /etc/openvpn/easy-rsa/vars
Using SSL: openssl OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

Notice
------
Keypair and certificate request completed. Your files are:
req: /etc/openvpn/easy-rsa/pki/reqs/{client_name}.req
key: /etc/openvpn/easy-rsa/pki/private/{client_name}.key

Notice
------
Certificate created at: /etc/openvpn/easy-rsa/pki/issued/{client_name}.crt
"""
    
    @staticmethod
    def easyrsa_revoke(client_name: str) -> str:
        return f"""
Note: using Easy-RSA configuration from: /etc/openvpn/easy-rsa/vars
Using SSL: openssl OpenSSL 3.0.2 15 Mar 2022

Please confirm you wish to revoke the certificate with the following subject:

subject=
    commonName                = {client_name}

Type the word 'yes' to continue, or any other input to abort.
  Continue with revocation: yes

Revoking Certificate {client_name}.
Data Base Updated

IMPORTANT!!!

Revocation was successful. You must run gen-crl and upload a CRL to your
infrastructure in order to prevent the revoked cert from being accepted.
"""
    
    @staticmethod
    def systemctl_status() -> str:
        return """
● openvpn-server@server.service - OpenVPN service for server
     Loaded: loaded (/lib/systemd/system/openvpn-server@.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2026-02-25 14:00:00 UTC; 1h ago
       Docs: man:openvpn(8)
             https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
   Main PID: 1234 (openvpn)
     Status: "Initialization Sequence Completed"
      Tasks: 1 (limit: 1137)
     Memory: 2.5M
        CPU: 123ms
     CGroup: /system.slice/system-openvpn\\x2dserver.slice/openvpn-server@server.service
             └─1234 /usr/sbin/openvpn --status /run/openvpn-server/status-server.log --status-version 2 --suppress-timestamps --config server.conf

Feb 25 14:00:00 atlas systemd[1]: Starting OpenVPN service for server...
Feb 25 14:00:00 atlas systemd[1]: Started OpenVPN service for server.
"""


def validate_openvpn_readiness(general_settings, openvpn_settings) -> List[str]:
    """
    Stage 1: The Gatekeeper - Granular validation of required fields.
    Returns list of human-readable missing field names.
    """
    missing = []
    
    # Absolute Requirements
    if not general_settings.server_address or not general_settings.server_address.strip():
        missing.append("Server IP/Domain")
    if not openvpn_settings.port:
        missing.append("Port")
    if not openvpn_settings.protocol or not openvpn_settings.protocol.strip():
        missing.append("Protocol")
    
    # Conditional Requirements
    if openvpn_settings.obfuscation_mode and openvpn_settings.obfuscation_mode != "standard":
        if not openvpn_settings.proxy_port:
            missing.append("Proxy Port (Required for HTTP Proxy)")
        if openvpn_settings.obfuscation_mode in ["http_proxy_basic", "http_proxy_advanced"] and (
            not openvpn_settings.proxy_address or not openvpn_settings.proxy_address.strip()
        ):
            missing.append("Proxy Address (Required for HTTP Proxy)")
    
    if openvpn_settings.tls_mode and openvpn_settings.tls_mode != "none":
        # TLS keys should exist - this is a logical check since actual file existence
        # would be checked during config generation
        pass
    
    return missing


def _safe_int(value, default=None):
    """Stage 2: The Safe Builder - Convert to int safely."""
    try:
        if value is None or (isinstance(value, str) and not value.strip()):
            return default
        return int(value)
    except (ValueError, TypeError):
        return default


class OpenVPNManager:
    """
    Core OpenVPN management logic.
    Follows official OpenVPN and Easy-RSA 3 documentation.
    Includes mock support for development on non-Linux systems.
    """
    
    def __init__(self):
        self.config = OpenVPNConfig()
        self.is_production = IS_LINUX
        
        if not self.is_production:
            logger.warning("Running in DEVELOPMENT mode - subprocess calls will be mocked")

    def _load_runtime_settings(self) -> Tuple[Dict[str, any], Dict[str, any]]:
        """Load persisted OpenVPN and General settings from SQLite."""
        openvpn_defaults: Dict[str, any] = {
            "port": 1194,
            "protocol": "udp",
            "data_ciphers": "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "auth_digest": "SHA256",
            "tls_version_min": "1.2",
            "obfuscation_mode": "standard",
            "proxy_server": None,
            "proxy_address": None,
            "proxy_port": 8080,
            "spoofed_host": "speedtest.net",
            "socks_server": None,
            "socks_port": None,
            "stunnel_port": 443,
            "sni_domain": None,
            "cdn_domain": None,
            "ws_path": "/stream",
            "ws_port": 8080,
            "device_type": "tun",
            "topology": "subnet",
            "ipv4_network": "10.8.0.0",
            "ipv4_netmask": "255.255.255.0",
            "ipv4_pool": "10.8.0.0 255.255.255.0",
            "ipv6_network": None,
            "ipv6_prefix": None,
            "ipv6_pool": None,
            "max_clients": 100,
            "client_to_client": False,
            "redirect_gateway": True,
            "primary_dns": "8.8.8.8",
            "secondary_dns": "1.1.1.1",
            "block_outside_dns": False,
            "push_custom_routes": None,
            "tls_mode": "tls-crypt",
            "reneg_sec": 3600,
            "tun_mtu": 1500,
            "mssfix": 1450,
            "sndbuf": 393216,
            "rcvbuf": 393216,
            "fast_io": False,
            "tcp_nodelay": False,
            "explicit_exit_notify": 1,
            "keepalive_ping": 10,
            "keepalive_timeout": 120,
            "inactive_timeout": 300,
            "management_port": 5555,
            "verbosity": 3,
            "enable_auth_nocache": True,
<<<<<<< HEAD
            "resolv_retry_mode": "infinite",
            "persist_key": True,
            "persist_tun": True,
=======
>>>>>>> feature-server-settings
            "custom_directives": None,
            "advanced_client_push": None,
        }
        general_defaults: Dict[str, any] = {
            "server_address": "YOUR_SERVER_IP",
            "public_ipv4_address": None,
        }

        try:
            from backend.database import SessionLocal
            from backend.models.general_settings import GeneralSettings
            from backend.models.openvpn_settings import OpenVPNSettings

            db = SessionLocal()
            try:
                openvpn_settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
                if openvpn_settings:
                    for key in openvpn_defaults:
                        openvpn_defaults[key] = getattr(openvpn_settings, key, openvpn_defaults[key])

                general_settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
                if general_settings:
                    persisted_server_address = (general_settings.server_address or "").strip()
                    persisted_ipv4 = (general_settings.public_ipv4_address or "").strip()
                    general_defaults["server_address"] = (
                        persisted_server_address
                        or persisted_ipv4
                        or general_defaults["server_address"]
                    )
                    general_defaults["public_ipv4_address"] = persisted_ipv4 or None
            finally:
                db.close()
        except Exception as exc:
            logger.warning("Failed to load runtime settings from database: %s", exc)

        return openvpn_defaults, general_defaults
    
    def _run_command(self, cmd: List[str], check: bool = True) -> Tuple[bool, str, str]:
        """
        Execute system command with mock support for development.
        
        Args:
            cmd: Command and arguments as list
            check: Raise exception on non-zero exit code
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            if not self.is_production:
                # Mock responses for development
                logger.info(f"[MOCK] Would execute: {' '.join(cmd)}")
                
                if "easyrsa" in cmd[0]:
                    if "build-client-full" in cmd:
                        client_name = cmd[2] if len(cmd) > 2 else "client"
                        return True, MockOpenVPNResponse.easyrsa_build_client(client_name), ""
                    elif "revoke" in cmd:
                        client_name = cmd[2] if len(cmd) > 2 else "client"
                        return True, MockOpenVPNResponse.easyrsa_revoke(client_name), ""
                    elif "gen-crl" in cmd:
                        return True, "CRL generated successfully", ""
                
                elif "systemctl" in cmd[0]:
                    if "status" in cmd:
                        return True, MockOpenVPNResponse.systemctl_status(), ""
                    else:
                        action = cmd[1] if len(cmd) > 1 else "unknown"
                        return True, f"Service {action} completed successfully", ""
                
                return True, f"Mock command executed: {' '.join(cmd)}", ""
            
            # Production: execute real command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return True, result.stdout, result.stderr
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}\nError: {e.stderr}")
            if check:
                raise
            return False, e.stdout, e.stderr
        except FileNotFoundError as e:
            logger.error(f"Command not found: {cmd[0]}")
            if not self.is_production:
                # In development, return mock success
                return True, f"Mock: {cmd[0]} not found but continuing in dev mode", ""
            raise
        except Exception as e:
            logger.error(f"Unexpected error running command: {e}")
            if check:
                raise
            return False, "", str(e)

    @staticmethod
    def _normalize_transport_protocol(protocol: str) -> str:
        normalized = (protocol or "udp").lower().strip()
        if normalized.startswith("tcp"):
            return "tcp"
        return "udp"

    def sync_firewall_for_transport_change(
        self,
        old_port: int,
        old_protocol: str,
        new_port: int,
        new_protocol: str,
    ) -> Dict[str, any]:
        """Apply UFW rule updates when OpenVPN transport changes."""
        old_proto = self._normalize_transport_protocol(old_protocol)
        new_proto = self._normalize_transport_protocol(new_protocol)

        if old_port == new_port and old_proto == new_proto:
            return {
                "success": True,
                "message": "Firewall rules unchanged",
                "is_mock": not self.is_production,
                "commands": [],
            }

        commands: List[List[str]] = []
        allow_rule = ["ufw", "allow", f"{new_port}/{new_proto}"]
        commands.append(allow_rule)

        if old_port != new_port or old_proto != new_proto:
            commands.append(["ufw", "delete", "allow", f"{old_port}/{old_proto}"])

        if not self.is_production:
            for cmd in commands:
                logger.info(f"[MOCK] Would execute firewall command: {' '.join(cmd)}")
            return {
                "success": True,
                "message": "Firewall rules updated (mock)",
                "is_mock": True,
                "commands": [" ".join(cmd) for cmd in commands],
            }

        allow_success, _, allow_error = self._run_command(allow_rule, check=False)
        if not allow_success:
            return {
                "success": False,
                "message": f"Failed to allow new firewall rule: {allow_error}",
                "is_mock": False,
                "commands": [" ".join(allow_rule)],
            }

        old_rule_results: List[str] = []
        if len(commands) > 1:
            delete_cmd = commands[1]
            delete_success, _, delete_error = self._run_command(delete_cmd, check=False)
            if not delete_success:
                deny_cmd = ["ufw", "deny", f"{old_port}/{old_proto}"]
                deny_success, _, deny_error = self._run_command(deny_cmd, check=False)
                old_rule_results.append(" ".join(delete_cmd))
                old_rule_results.append(" ".join(deny_cmd))
                if not deny_success:
                    return {
                        "success": False,
                        "message": f"Failed to remove old firewall rule: {delete_error or deny_error}",
                        "is_mock": False,
                        "commands": [" ".join(allow_rule), *old_rule_results],
                    }
            else:
                old_rule_results.append(" ".join(delete_cmd))

        return {
            "success": True,
            "message": "Firewall rules updated",
            "is_mock": False,
            "commands": [" ".join(allow_rule), *old_rule_results],
        }

    def sync_system_general_settings(
        self,
        old_global_ipv6_support: bool,
        new_global_ipv6_support: bool,
        old_timezone: str,
        new_timezone: str,
        old_panel_https_port: Optional[int] = None,
        new_panel_https_port: Optional[int] = None,
        old_subscription_https_port: Optional[int] = None,
        new_subscription_https_port: Optional[int] = None,
    ) -> Dict[str, any]:
        """Apply OS-level sync for General settings changes."""
        commands: List[List[str]] = []

        if old_global_ipv6_support != new_global_ipv6_support:
            disable_value = "0" if new_global_ipv6_support else "1"
            commands.extend(
                [
                    ["sysctl", "-w", f"net.ipv6.conf.all.disable_ipv6={disable_value}"],
                    ["sysctl", "-w", f"net.ipv6.conf.default.disable_ipv6={disable_value}"],
                ]
            )

        normalized_old_timezone = (old_timezone or "").strip()
        normalized_new_timezone = (new_timezone or "").strip()
        if normalized_new_timezone and normalized_new_timezone != normalized_old_timezone:
            commands.append(["timedatectl", "set-timezone", normalized_new_timezone])

        port_sync_result = self.sync_https_firewall_ports(
            old_panel_port=old_panel_https_port,
            new_panel_port=new_panel_https_port,
            old_subscription_port=old_subscription_https_port,
            new_subscription_port=new_subscription_https_port,
        )
        if not port_sync_result.get("success"):
            return port_sync_result

        if not commands:
            return {
                "success": True,
                "message": "General system settings unchanged",
                "is_mock": not self.is_production,
                "commands": port_sync_result.get("commands", []),
            }

        if not self.is_production:
            for cmd in commands:
                logger.info(f"[MOCK] Would execute general system command: {' '.join(cmd)}")
            return {
                "success": True,
                "message": "General system settings updated (mock)",
                "is_mock": True,
                "commands": [*port_sync_result.get("commands", []), *[" ".join(cmd) for cmd in commands]],
            }

        executed_commands: List[str] = []
        for cmd in commands:
            success, _, stderr = self._run_command(cmd, check=False)
            executed_commands.append(" ".join(cmd))
            if not success:
                return {
                    "success": False,
                    "message": f"Failed to apply general system command: {' '.join(cmd)}. {stderr}".strip(),
                    "is_mock": False,
                    "commands": executed_commands,
                }

        return {
            "success": True,
            "message": "General system settings updated",
            "is_mock": False,
            "commands": [*port_sync_result.get("commands", []), *executed_commands],
        }

    def sync_https_firewall_ports(
        self,
        old_panel_port: Optional[int],
        new_panel_port: Optional[int],
        old_subscription_port: Optional[int],
        new_subscription_port: Optional[int],
    ) -> Dict[str, any]:
        """Sync UFW rules for panel/subscription HTTPS ports."""

        old_ports = {int(port) for port in [old_panel_port, old_subscription_port] if port is not None}
        new_ports = {int(port) for port in [new_panel_port, new_subscription_port] if port is not None}

        allow_ports = sorted(new_ports - old_ports)
        remove_ports = sorted(old_ports - new_ports)

        if not allow_ports and not remove_ports:
            return {
                "success": True,
                "message": "HTTPS firewall rules unchanged",
                "is_mock": not self.is_production,
                "commands": [],
            }

        commands: List[List[str]] = []
        for port in allow_ports:
            commands.append(["ufw", "allow", f"{port}/tcp"])

        for port in remove_ports:
            commands.append(["ufw", "delete", "allow", f"{port}/tcp"])

        if not self.is_production:
            for cmd in commands:
                logger.info(f"[MOCK] Would execute HTTPS firewall command: {' '.join(cmd)}")
            return {
                "success": True,
                "message": "HTTPS firewall rules updated (mock)",
                "is_mock": True,
                "commands": [" ".join(cmd) for cmd in commands],
            }

        executed_commands: List[str] = []
        for cmd in commands:
            success, _, stderr = self._run_command(cmd, check=False)
            executed_commands.append(" ".join(cmd))
            if not success:
                if cmd[:3] == ["ufw", "delete", "allow"]:
                    deny_cmd = ["ufw", "deny", cmd[-1]]
                    deny_success, _, deny_error = self._run_command(deny_cmd, check=False)
                    executed_commands.append(" ".join(deny_cmd))
                    if deny_success:
                        continue
                    stderr = deny_error or stderr

                return {
                    "success": False,
                    "message": f"Failed to update HTTPS firewall rules: {stderr}".strip(),
                    "is_mock": False,
                    "commands": executed_commands,
                }

        return {
            "success": True,
            "message": "HTTPS firewall rules updated",
            "is_mock": False,
            "commands": executed_commands,
        }

    @staticmethod
    def _normalize_cert_domain(value: str) -> str:
        candidate = (value or "").strip()
        if not candidate:
            raise ValueError("Domain is required")

        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        domain = (parsed.hostname or "").strip().lower()
        if not domain:
            domain = candidate.split("/")[0].split(":")[0].strip().lower()
        if not domain:
            raise ValueError("Domain is invalid")
        return domain

    def _build_ssl_targets(
        self,
        panel_domain: Optional[str],
        subscription_domain: Optional[str],
    ) -> List[Tuple[str, str]]:
        targets: List[Tuple[str, str]] = []

        panel_raw = (panel_domain or "").strip()
        if panel_raw:
            targets.append(("Panel Domain", self._normalize_cert_domain(panel_raw)))

        subscription_raw = (subscription_domain or "").strip()
        if subscription_raw:
            targets.append(("Subscription Domain", self._normalize_cert_domain(subscription_raw)))

        if not targets:
            raise ValueError("At least one domain is required for SSL issuance")

        return targets

    @staticmethod
    def _build_certbot_command(domain: str, email: str) -> List[str]:
        return [
            "certbot",
            "certonly",
            "--standalone",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "-m",
            email,
        ]

    def _stream_mock_ssl_issue_logs(self, targets: List[Tuple[str, str]], email: str) -> Iterator[str]:
        for label, domain in targets:
            command = self._build_certbot_command(domain, email)
            yield f">>> Starting SSL issuance for {label}..."
            time.sleep(0.25)
            yield f"$ {' '.join(command)}"
            time.sleep(0.25)
            yield f"Saving debug log to /var/log/letsencrypt/letsencrypt-{domain}.log"
            time.sleep(0.25)
            yield f"Requesting a certificate for {domain}"
            time.sleep(0.4)
            yield "Successfully received certificate"
            time.sleep(0.2)
            yield f"Certificate is saved at: /etc/letsencrypt/live/{domain}/fullchain.pem"
            time.sleep(0.2)
            yield f"Key is saved at: /etc/letsencrypt/live/{domain}/privkey.pem"
            time.sleep(0.2)
            yield ">>> Success!"
            time.sleep(0.2)

        yield ">>> SSL issuance completed for all requested domains."

    def _stream_production_ssl_issue_logs(self, targets: List[Tuple[str, str]], email: str) -> Iterator[str]:
        for label, domain in targets:
            command = self._build_certbot_command(domain, email)
            yield f">>> Starting SSL issuance for {label}..."
            yield f"$ {' '.join(command)}"

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            try:
                if process.stdout is not None:
                    for line in process.stdout:
                        rendered = line.rstrip("\n")
                        if rendered:
                            yield rendered
            finally:
                if process.stdout is not None:
                    process.stdout.close()

            return_code = process.wait()
            if return_code != 0:
                yield f">>> Error: SSL issuance failed for {label} with exit code {return_code}."
                return

            yield ">>> Success!"

        yield ">>> SSL issuance completed for all requested domains."

    def stream_ssl_issue_logs(
        self,
        panel_domain: Optional[str],
        subscription_domain: Optional[str],
        email: str,
    ) -> Iterator[str]:
        normalized_email = (email or "").strip()
        if not normalized_email:
            raise ValueError("Let's Encrypt email is required")

        targets = self._build_ssl_targets(panel_domain, subscription_domain)

        if not self.is_production:
            yield ">>> Running in development mode with mock SSL logs."
            yield from self._stream_mock_ssl_issue_logs(targets, normalized_email)
            return

        yield from self._stream_production_ssl_issue_logs(targets, normalized_email)
    
    def check_easyrsa_installed(self) -> bool:
        """Check if Easy-RSA is installed"""
        try:
            success, _, _ = self._run_command(["easyrsa", "version"], check=False)
            return success
        except:
            return not self.is_production  # Always true in dev mode
    
    def initialize_pki(self) -> Dict[str, any]:
        """
        Initialize PKI infrastructure using Easy-RSA 3.
        This should be run once during initial setup.
        """
        try:
            if not self.is_production:
                logger.info("[MOCK] PKI initialization skipped in development mode")
                return {
                    "success": True,
                    "message": "PKI initialized (mock)",
                    "ca_created": True,
                    "server_cert_created": True
                }
            
            # Change to Easy-RSA directory
            os.chdir(self.config.EASYRSA_DIR)
            
            # Initialize PKI
            self._run_command(["./easyrsa", "init-pki"])
            
            # Build CA (non-interactive)
            self._run_command(["./easyrsa", "build-ca", "nopass"])
            
            # Generate DH parameters
            self._run_command(["./easyrsa", "gen-dh"])
            
            # Build server certificate
            self._run_command(["./easyrsa", "build-server-full", "server", "nopass"])
            
            # Generate TLS auth key
            self._run_command(["openvpn", "--genkey", "--secret", str(self.config.TA_KEY)])
            
            return {
                "success": True,
                "message": "PKI initialized successfully",
                "ca_created": True,
                "server_cert_created": True
            }
            
        except Exception as e:
            logger.error(f"PKI initialization failed: {e}")
            return {
                "success": False,
                "message": f"PKI initialization failed: {str(e)}",
                "error": str(e)
            }
    
    def create_client_certificate(self, client_name: str) -> Dict[str, any]:
        """
        Create client certificate using Easy-RSA 3.
        
        Args:
            client_name: Unique client identifier (alphanumeric, no spaces)
            
        Returns:
            Dict with success status and file paths
        """
        try:
            # Validate client name
            if not client_name.replace("-", "").replace("_", "").isalnum():
                return {
                    "success": False,
                    "message": "Client name must be alphanumeric (-, _ allowed)"
                }
            
            if not self.is_production:
                logger.info(f"[MOCK] Creating certificate for client: {client_name}")
            
            # Build client certificate with Easy-RSA
            success, stdout, stderr = self._run_command([
                "easyrsa",
                "build-client-full",
                client_name,
                "nopass"
            ])
            
            if not success:
                return {
                    "success": False,
                    "message": f"Certificate creation failed: {stderr}"
                }
            
            # Get certificate paths
            cert_path = self.config.CLIENT_CERTS_DIR / f"{client_name}.crt"
            key_path = self.config.CLIENT_KEYS_DIR / f"{client_name}.key"
            
            return {
                "success": True,
                "message": f"Certificate created for {client_name}",
                "client_name": client_name,
                "cert_path": str(cert_path),
                "key_path": str(key_path),
                "ca_path": str(self.config.CA_CERT),
                "ta_key_path": str(self.config.TA_KEY)
            }
            
        except Exception as e:
            logger.error(f"Client certificate creation failed: {e}")
            return {
                "success": False,
                "message": f"Certificate creation failed: {str(e)}",
                "error": str(e)
            }
    
    def revoke_client_certificate(self, client_name: str) -> Dict[str, any]:
        """
        Revoke client certificate using Easy-RSA 3.
        
        Args:
            client_name: Client identifier to revoke
            
        Returns:
            Dict with success status
        """
        try:
            if not self.is_production:
                logger.info(f"[MOCK] Revoking certificate for client: {client_name}")
            
            # Revoke certificate
            success, stdout, stderr = self._run_command([
                "easyrsa",
                "revoke",
                client_name
            ])
            
            if not success:
                return {
                    "success": False,
                    "message": f"Certificate revocation failed: {stderr}"
                }
            
            # Generate new CRL
            self._run_command(["easyrsa", "gen-crl"])
            
            return {
                "success": True,
                "message": f"Certificate revoked for {client_name}",
                "client_name": client_name,
                "revoked_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Certificate revocation failed: {e}")
            return {
                "success": False,
                "message": f"Revocation failed: {str(e)}",
                "error": str(e)
            }
    
    def _generate_apple_config(
        self,
        client_name: str,
        openvpn_settings: dict,
        general_settings: dict,
        server_address: str,
        server_port: int,
        protocol: str,
        os_type: str = "ios",
    ) -> str:
        """
        Standalone Apple (iOS/macOS) config generator with strict whitelist.
        NO sndbuf, NO rcvbuf, NO block-outside-dns, NO comp-lzo/compress.
        """
        # Clean slate
        lines: List[str] = []
        
        # MANDATORY FIXED CORE
<<<<<<< HEAD
<<<<<<< HEAD
        device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
        resolv_retry_mode = str(openvpn_settings.get("resolv_retry_mode", "infinite")).strip().lower()
        persist_key = bool(openvpn_settings.get("persist_key", True))
        persist_tun = bool(openvpn_settings.get("persist_tun", True))
        
        lines.extend([
            "# Atlas VPN - OpenVPN Client Configuration",
            "# OS: iOS/macOS",
=======
        lines.extend([
            "# Atlas VPN - OpenVPN Client Configuration",
>>>>>>> feature-server-settings
=======
        device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
        lines.extend([
            "# Atlas VPN - OpenVPN Client Configuration",
            "# OS: iOS/macOS",
>>>>>>> feature-server-settings
            f"# Client: {client_name}",
            f"# Generated: {datetime.utcnow().isoformat()}",
            "",
            "client",
<<<<<<< HEAD
<<<<<<< HEAD
            f"dev {device_type}",
        ])
        
        # Conditional: resolv-retry
        if resolv_retry_mode == "infinite":
            lines.append("resolv-retry infinite")
        elif resolv_retry_mode.isdigit():
            lines.append(f"resolv-retry {resolv_retry_mode}")
        # else: disabled - don't add directive
        
        lines.extend(["nobind"])
        
        # Conditional: persist-key and persist-tun
        if persist_key:
            lines.append("persist-key")
        if persist_tun:
            lines.append("persist-tun")
        
        lines.extend([
=======
            "dev tun",
=======
            f"dev {device_type}",
>>>>>>> feature-server-settings
            "resolv-retry infinite",
            "nobind",
            "persist-key",
            "persist-tun",
>>>>>>> feature-server-settings
            "remote-cert-tls server",
            "verb 3",
        ])
        
        # CONDITIONAL: proto
        resolved_protocol = str(protocol or openvpn_settings.get("protocol", "udp")).strip().lower()
        obfuscation_mode = str(openvpn_settings.get("obfuscation_mode") or "standard").strip().lower()
        effective_protocol = "tcp" if obfuscation_mode != "standard" else resolved_protocol
        is_tcp = "tcp" in effective_protocol.lower()
        
        if effective_protocol:
            lines.append(f"proto {effective_protocol}")
        
        # CONDITIONAL: remote
        resolved_server = (
            (server_address or "").strip()
            or (general_settings.get("server_address") or "").strip()
            or "YOUR_SERVER_IP"
        )
        resolved_port = int(server_port if server_port is not None else openvpn_settings.get("port", 1194))
        
        if obfuscation_mode == "stealth":
            lines.append(f"remote {resolved_server} 443")
        else:
            lines.append(f"remote {resolved_server} {resolved_port}")
        
        # CONDITIONAL: Cryptography
        raw_data_ciphers = openvpn_settings.get("data_ciphers") or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
        if isinstance(raw_data_ciphers, list):
            client_data_ciphers = ":".join([c.strip() for c in raw_data_ciphers if c and c.strip()])
        else:
            client_data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
        
        if client_data_ciphers:
            lines.append(f"data-ciphers {client_data_ciphers}")
            fallback = client_data_ciphers.split(":")[0].strip() if ":" in client_data_ciphers else client_data_ciphers
            if fallback:
                lines.append(f"data-ciphers-fallback {fallback}")
        
        auth_digest = str(openvpn_settings.get("auth_digest") or "SHA256").strip().upper()
        if auth_digest:
            lines.append(f"auth {auth_digest}")
        
        tls_version_min = str(openvpn_settings.get("tls_version_min") or "1.2").strip()
        if tls_version_min:
            lines.append(f"tls-version-min {tls_version_min}")
        
        tls_mode = str(openvpn_settings.get("tls_mode") or "tls-crypt").strip().lower()
        if tls_mode == "tls-auth":
            lines.append("key-direction 1")
        
        # CONDITIONAL: Verbosity (dynamic from DB)
        verbosity = _safe_int(openvpn_settings.get("verbosity"))
        if verbosity and verbosity != 3:
            lines[-9] = f"verb {int(verbosity)}"
        
        # CONDITIONAL: Performance (safe only)
        tun_mtu = _safe_int(openvpn_settings.get("tun_mtu"))
        mssfix = _safe_int(openvpn_settings.get("mssfix"))
        if tun_mtu:
            lines.append(f"tun-mtu {int(tun_mtu)}")
        if mssfix:
            lines.append(f"mssfix {int(mssfix)}")
        
        # CONDITIONAL: Keepalive
        keepalive_ping = _safe_int(openvpn_settings.get("keepalive_ping"))
        keepalive_timeout = _safe_int(openvpn_settings.get("keepalive_timeout"))
        if keepalive_ping and keepalive_timeout:
            lines.append(f"keepalive {int(keepalive_ping)} {int(keepalive_timeout)}")
        
        # CONDITIONAL: tcp-nodelay (ONLY if TCP AND enabled)
        tcp_nodelay = bool(openvpn_settings.get("tcp_nodelay", False))
        if tcp_nodelay and is_tcp:
            lines.append("tcp-nodelay")
        
        # CONDITIONAL: Routing
        redirect_gateway = bool(openvpn_settings.get("redirect_gateway", False))
        if redirect_gateway:
            ipv6_network = (openvpn_settings.get("ipv6_network") or "").strip()
            ipv6_prefix = openvpn_settings.get("ipv6_prefix")
            ipv6_enabled = bool(ipv6_network and ipv6_prefix is not None)
            if ipv6_enabled:
                lines.append("redirect-gateway def1 ipv6 bypass-dhcp")
            else:
                lines.append("redirect-gateway def1 bypass-dhcp")
        
        # CONDITIONAL: DNS
        primary_dns = (openvpn_settings.get("primary_dns") or "").strip()
        secondary_dns = (openvpn_settings.get("secondary_dns") or "").strip()
        if primary_dns:
            lines.append(f"dhcp-option DNS {primary_dns}")
        if secondary_dns:
            lines.append(f"dhcp-option DNS {secondary_dns}")
        
        # CONDITIONAL: Custom routes
        push_custom_routes = (openvpn_settings.get("push_custom_routes") or "").strip()
        if push_custom_routes:
            for route_line in push_custom_routes.splitlines():
                route_clean = route_line.strip()
                if route_clean:
                    lines.append(f"route {route_clean}")
        
        # CONDITIONAL: Obfuscation directives (all modes)
        proxy_server = (openvpn_settings.get("proxy_server") or "").strip()
        proxy_address = (openvpn_settings.get("proxy_address") or "").strip()
        proxy_target = proxy_server or proxy_address or resolved_server
        proxy_port = _safe_int(openvpn_settings.get("proxy_port")) or 8080
        spoofed_host = (openvpn_settings.get("spoofed_host") or "").strip()
        socks_server = (openvpn_settings.get("socks_server") or "").strip()
        socks_port = _safe_int(openvpn_settings.get("socks_port")) or 1080
        stunnel_port = _safe_int(openvpn_settings.get("stunnel_port")) or 443
        sni_domain = (openvpn_settings.get("sni_domain") or "").strip()
        ws_path = (openvpn_settings.get("ws_path") or "/stream").strip() or "/stream"
        ws_port = _safe_int(openvpn_settings.get("ws_port")) or 8080
        cdn_domain = (openvpn_settings.get("cdn_domain") or "").strip()
        
        if obfuscation_mode == "stealth":
            lines.append(f"http-proxy {proxy_target} {proxy_port}")
            lines.append("http-proxy-retry")
            if spoofed_host:
                lines.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
        
        elif obfuscation_mode == "http_proxy_basic":
            lines.append(f"http-proxy {proxy_target} {proxy_port}")
            lines.append("http-proxy-retry")
        
        elif obfuscation_mode == "http_proxy_advanced":
            lines.append(f"http-proxy {proxy_target} {proxy_port}")
            lines.append("http-proxy-retry")
            if spoofed_host:
                lines.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
        
        elif obfuscation_mode == "socks5_proxy_injection":
            socks_target = socks_server or proxy_target
            lines.append(f"socks-proxy {socks_target} {socks_port}")
            lines.append("socks-proxy-retry")
        
        elif obfuscation_mode == "tls_tunnel":
            lines.append("# TLS tunnel mode: run local Stunnel client before connecting.")
            if sni_domain:
                lines.append(f"# TLS SNI domain hint: {sni_domain}")
        
        elif obfuscation_mode == "websocket_cdn":
            lines.append(f"# WebSocket path hint: {ws_path}")
            lines.append(f"# Local WebSocket port hint: {ws_port}")
        
        # CONDITIONAL: Custom Apple-specific directives from DB
        os_name = (os_type or "").strip().lower()
        custom_apple = (openvpn_settings.get("custom_mac") if os_name in {"mac", "macos"} else openvpn_settings.get("custom_ios"))
        custom_apple = (custom_apple or "").strip()
        blocked_directives = (
            "sndbuf",
            "rcvbuf",
            "comp-lzo",
            "compress",
            "explicit-exit-notify",
            "block-outside-dns",
        )
        if custom_apple:
            lines.append("")
            lines.append("# Custom Apple Directives")
            for custom_line in custom_apple.splitlines():
                custom_clean = custom_line.strip()
                if custom_clean and not custom_clean.startswith("#"):
                    custom_lower = custom_clean.lower()
                    if any(custom_lower == directive or custom_lower.startswith(f"{directive} ") for directive in blocked_directives):
                        continue
                    lines.append(custom_clean)
        
        # AUTHENTICATION: auth-user-pass and conditional auth-nocache (BEFORE certificates)
        lines.append("")
        lines.append("auth-user-pass")
        enable_auth_nocache = bool(openvpn_settings.get("enable_auth_nocache", True))
        if enable_auth_nocache:
            lines.append("auth-nocache")
        
        # CERTIFICATES (always last for readability)
        if not self.is_production:
            ca_cert = "-----BEGIN CERTIFICATE-----\nMOCK CA CERTIFICATE\n-----END CERTIFICATE-----"
            client_cert = "-----BEGIN CERTIFICATE-----\nMOCK CLIENT CERTIFICATE\n-----END CERTIFICATE-----"
            client_key = "-----BEGIN PRIVATE KEY-----\nMOCK CLIENT KEY\n-----END PRIVATE KEY-----"
            ta_key = "-----BEGIN OpenVPN Static key V1-----\nMOCK TA KEY\n-----END OpenVPN Static key V1-----"
        else:
            cert_path = self.config.CLIENT_CERTS_DIR / f"{client_name}.crt"
            key_path = self.config.CLIENT_KEYS_DIR / f"{client_name}.key"
            with open(self.config.CA_CERT, 'r') as f:
                ca_cert = f.read()
            with open(cert_path, 'r') as f:
                client_cert = f.read()
            with open(key_path, 'r') as f:
                client_key = f.read()
            with open(self.config.TA_KEY, 'r') as f:
                ta_key = f.read()
        
        lines.extend([
            "",
            "<ca>",
            ca_cert,
            "</ca>",
            "",
            "<cert>",
            client_cert,
            "</cert>",
            "",
            "<key>",
            client_key,
            "</key>",
        ])
        
        if tls_mode == "tls-crypt":
            lines.extend(["", "<tls-crypt>", ta_key, "</tls-crypt>"])
        elif tls_mode == "tls-auth":
            lines.extend(["", "<tls-auth>", ta_key, "</tls-auth>"])
        
        # Final strict sanitize pass to guarantee blocked directives are never emitted.
        sanitized_lines: List[str] = []
        for line in lines:
            stripped = line.strip()
            lowered = stripped.lower()
            if stripped and not stripped.startswith("#"):
                if any(lowered == directive or lowered.startswith(f"{directive} ") for directive in blocked_directives):
                    continue
            sanitized_lines.append(line)

        sanitized_lines.append("")
        return "\n".join(sanitized_lines)

    def _generate_android_config(
        self,
        client_name: str,
        openvpn_settings: dict,
        general_settings: dict,
        server_address: str,
        server_port: int,
        protocol: str,
    ) -> str:
        """Generate Android config using global settings with Android-specific smart filtering."""
        device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
        resolved_protocol = str(protocol or openvpn_settings.get("protocol", "udp")).strip().lower()
        obfuscation_mode = str(openvpn_settings.get("obfuscation_mode") or "standard").strip().lower()
        effective_protocol = "tcp" if obfuscation_mode != "standard" else resolved_protocol

        resolved_server = (
            (server_address or "").strip()
            or (general_settings.get("server_address") or "").strip()
            or "YOUR_SERVER_IP"
        )
        resolved_port = int(server_port if server_port is not None else openvpn_settings.get("port", 1194))

        obfuscation_settings = {
            "obfuscation_mode": openvpn_settings.get("obfuscation_mode"),
            "proxy_server": openvpn_settings.get("proxy_server"),
            "proxy_address": openvpn_settings.get("proxy_address"),
            "proxy_port": openvpn_settings.get("proxy_port"),
            "spoofed_host": openvpn_settings.get("spoofed_host"),
            "socks_server": openvpn_settings.get("socks_server"),
            "socks_port": openvpn_settings.get("socks_port"),
            "stunnel_port": openvpn_settings.get("stunnel_port"),
            "sni_domain": openvpn_settings.get("sni_domain"),
            "cdn_domain": openvpn_settings.get("cdn_domain"),
            "ws_path": openvpn_settings.get("ws_path"),
            "ws_port": openvpn_settings.get("ws_port"),
        }

        (
            client_protocol,
            client_remote_line,
            obfuscation_directives,
        ) = self._build_client_transport_directives(
            server_address=resolved_server,
            default_port=resolved_port,
            default_protocol=effective_protocol,
            obfuscation_settings=obfuscation_settings,
        )

        is_udp = "udp" in client_protocol.lower()

        raw_data_ciphers = openvpn_settings.get("data_ciphers") or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
        if isinstance(raw_data_ciphers, list):
            client_data_ciphers = ":".join([c.strip() for c in raw_data_ciphers if c and c.strip()])
        else:
            client_data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

        data_cipher_fallback = client_data_ciphers.split(":")[0].strip() if ":" in client_data_ciphers else client_data_ciphers
        auth_digest = str(openvpn_settings.get("auth_digest") or "SHA256").strip().upper()
        tls_version_min = str(openvpn_settings.get("tls_version_min") or "1.2").strip()
        tls_mode = str(openvpn_settings.get("tls_mode") or "tls-crypt").strip().lower()
        redirect_gateway = bool(openvpn_settings.get("redirect_gateway", False))
        primary_dns = (openvpn_settings.get("primary_dns") or "").strip()
        secondary_dns = (openvpn_settings.get("secondary_dns") or "").strip()
        push_custom_routes = (openvpn_settings.get("push_custom_routes") or "").strip()
        tun_mtu = _safe_int(openvpn_settings.get("tun_mtu"))
        mssfix = _safe_int(openvpn_settings.get("mssfix"))
        sndbuf = _safe_int(openvpn_settings.get("sndbuf"))
        rcvbuf = _safe_int(openvpn_settings.get("rcvbuf"))
        fast_io = bool(openvpn_settings.get("fast_io", False))
        explicit_exit_notify = _safe_int(openvpn_settings.get("explicit_exit_notify"))
        keepalive_ping = _safe_int(openvpn_settings.get("keepalive_ping"))
        keepalive_timeout = _safe_int(openvpn_settings.get("keepalive_timeout"))
        tcp_nodelay = bool(openvpn_settings.get("tcp_nodelay", False))
        persist_key = bool(openvpn_settings.get("persist_key", True))
        persist_tun = bool(openvpn_settings.get("persist_tun", True))

        lines: List[str] = [
            "# Atlas VPN - OpenVPN Client Configuration",
            "# OS: ANDROID",
            f"# Client: {client_name}",
            f"# Generated: {datetime.utcnow().isoformat()}",
            "",
            "client",
            f"dev {device_type}",
            f"proto {client_protocol}",
            client_remote_line,
            "resolv-retry infinite",
            "nobind",
        ]
        if persist_key:
            lines.append("persist-key")
        if persist_tun:
            lines.append("persist-tun")
        lines.extend([
            "remote-cert-tls server",
            "verb 3",
        ])

        if client_data_ciphers:
            lines.append(f"data-ciphers {client_data_ciphers}")
        if data_cipher_fallback:
            lines.append(f"data-ciphers-fallback {data_cipher_fallback}")
        if auth_digest:
            lines.append(f"auth {auth_digest}")
        if tls_version_min:
            lines.append(f"tls-version-min {tls_version_min}")
        if tls_mode == "tls-auth":
            lines.append("key-direction 1")

        if tun_mtu:
            lines.append(f"tun-mtu {int(tun_mtu)}")
        if mssfix:
            lines.append(f"mssfix {int(mssfix)}")

        # Android-only dynamic buffers from global OpenVPN settings.
        if sndbuf is not None:
            lines.append(f"sndbuf {int(sndbuf)}")
        if rcvbuf is not None:
            lines.append(f"rcvbuf {int(rcvbuf)}")

        if keepalive_ping and keepalive_timeout:
            lines.append(f"keepalive {int(keepalive_ping)} {int(keepalive_timeout)}")

        if tcp_nodelay and "tcp" in client_protocol.lower():
            lines.append("tcp-nodelay")
        if fast_io and is_udp:
            lines.append("fast-io")
        if explicit_exit_notify and is_udp:
            lines.append(f"explicit-exit-notify {int(explicit_exit_notify)}")

        if redirect_gateway:
            ipv6_network = (openvpn_settings.get("ipv6_network") or "").strip()
            ipv6_prefix = openvpn_settings.get("ipv6_prefix")
            ipv6_enabled = bool(ipv6_network and ipv6_prefix is not None)
            if ipv6_enabled:
                lines.append("redirect-gateway def1 ipv6 bypass-dhcp")
            else:
                lines.append("redirect-gateway def1 bypass-dhcp")

        if primary_dns:
            lines.append(f"dhcp-option DNS {primary_dns}")
        if secondary_dns:
            lines.append(f"dhcp-option DNS {secondary_dns}")

        if push_custom_routes:
            for route_line in push_custom_routes.splitlines():
                route_clean = route_line.strip()
                if route_clean:
                    lines.append(f"route {route_clean}")

        for directive in obfuscation_directives:
            normalized = (directive or "").strip().lower()
            if normalized and "comp-lzo" not in normalized and "compress" not in normalized:
                lines.append((directive or "").strip())

        custom_android = (openvpn_settings.get("custom_android") or "").strip()
        if custom_android:
            lines.append("")
            lines.append("# Custom ANDROID Directives")
            for custom_line in custom_android.splitlines():
                custom_clean = custom_line.strip()
                custom_lower = custom_clean.lower()
                if custom_clean and not custom_clean.startswith("#"):
                    if "comp-lzo" in custom_lower or "compress" in custom_lower:
                        continue
                    lines.append(custom_clean)

        lines.append("")
        lines.append("auth-user-pass")
        enable_auth_nocache = bool(openvpn_settings.get("enable_auth_nocache", True))
        if enable_auth_nocache:
            lines.append("auth-nocache")

        if not self.is_production:
            ca_cert = "-----BEGIN CERTIFICATE-----\nMOCK CA CERTIFICATE\n-----END CERTIFICATE-----"
            client_cert = "-----BEGIN CERTIFICATE-----\nMOCK CLIENT CERTIFICATE\n-----END CERTIFICATE-----"
            client_key = "-----BEGIN PRIVATE KEY-----\nMOCK CLIENT KEY\n-----END PRIVATE KEY-----"
            ta_key = "-----BEGIN OpenVPN Static key V1-----\nMOCK TA KEY\n-----END OpenVPN Static key V1-----"
        else:
            cert_path = self.config.CLIENT_CERTS_DIR / f"{client_name}.crt"
            key_path = self.config.CLIENT_KEYS_DIR / f"{client_name}.key"
            with open(self.config.CA_CERT, 'r') as f:
                ca_cert = f.read()
            with open(cert_path, 'r') as f:
                client_cert = f.read()
            with open(key_path, 'r') as f:
                client_key = f.read()
            with open(self.config.TA_KEY, 'r') as f:
                ta_key = f.read()

        lines.extend([
            "",
            "<ca>",
            ca_cert,
            "</ca>",
            "",
            "<cert>",
            client_cert,
            "</cert>",
            "",
            "<key>",
            client_key,
            "</key>",
        ])

        if tls_mode == "tls-crypt":
            lines.extend(["", "<tls-crypt>", ta_key, "</tls-crypt>"])
        elif tls_mode == "tls-auth":
            lines.extend(["", "<tls-auth>", ta_key, "</tls-auth>"])

        lines.append("")
        return "\n".join(lines)
    
    def generate_client_config(
        self,
        client_name: str,
        server_address: Optional[str] = None,
        server_port: Optional[int] = None,
        protocol: Optional[str] = None,
        os_type: str = "default"
    ) -> Optional[str]:
        """
        Generate .ovpn configuration file for client.
        
        Args:
            client_name: Client identifier
            server_address: Server IP or domain
            server_port: OpenVPN server port
            protocol: udp or tcp
            
        Returns:
            Complete .ovpn configuration as string
        """
        print(f"!!! DEBUG OS DETECTED: {os_type} !!!")
        
        # EARLY RETURN FOR APPLE DEVICES - Use standalone whitelist function
        if os_type and os_type.lower() in ['ios', 'mac', 'macos']:
            try:
                openvpn_settings, general_settings = self._load_runtime_settings()
                return self._generate_apple_config(
                    client_name=client_name,
                    openvpn_settings=openvpn_settings,
                    general_settings=general_settings,
                    server_address=server_address,
                    server_port=server_port,
                    protocol=protocol,
                    os_type=os_type,
                )
            except Exception as e:
                logger.error(f"Apple config generation failed: {e}")
                return None

        if os_type and os_type.lower() == 'android':
            try:
                openvpn_settings, general_settings = self._load_runtime_settings()
                return self._generate_android_config(
                    client_name=client_name,
                    openvpn_settings=openvpn_settings,
                    general_settings=general_settings,
                    server_address=server_address,
                    server_port=server_port,
                    protocol=protocol,
                )
            except Exception as e:
                logger.error(f"Android config generation failed: {e}")
                return None
        
        try:
            openvpn_settings, general_settings = self._load_runtime_settings()

            resolved_port = int(server_port if server_port is not None else openvpn_settings.get("port", 1194))
            resolved_protocol = str(protocol or openvpn_settings.get("protocol", "udp")).strip().lower()
            obfuscation_mode = str(openvpn_settings.get("obfuscation_mode") or "standard").strip().lower()
            effective_protocol = "tcp" if obfuscation_mode != "standard" else resolved_protocol
            resolved_server_address = (
                (server_address or "").strip()
                or (general_settings.get("server_address") or "").strip()
                or "YOUR_SERVER_IP"
            )

            obfuscation_settings = {
                "obfuscation_mode": openvpn_settings.get("obfuscation_mode"),
                "proxy_server": openvpn_settings.get("proxy_server"),
                "proxy_address": openvpn_settings.get("proxy_address"),
                "proxy_port": openvpn_settings.get("proxy_port"),
                "spoofed_host": openvpn_settings.get("spoofed_host"),
                "socks_server": openvpn_settings.get("socks_server"),
                "socks_port": openvpn_settings.get("socks_port"),
                "stunnel_port": openvpn_settings.get("stunnel_port"),
                "sni_domain": openvpn_settings.get("sni_domain"),
                "cdn_domain": openvpn_settings.get("cdn_domain"),
                "ws_path": openvpn_settings.get("ws_path"),
                "ws_port": openvpn_settings.get("ws_port"),
            }

            raw_data_ciphers = openvpn_settings.get("data_ciphers") or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
            if isinstance(raw_data_ciphers, list):
                client_data_ciphers = ":".join([cipher.strip() for cipher in raw_data_ciphers if cipher and cipher.strip()])
            else:
                client_data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
            data_cipher_fallback = client_data_ciphers.split(":")[0].strip() if ":" in client_data_ciphers else client_data_ciphers
            auth_digest = str(openvpn_settings.get("auth_digest") or "SHA256").strip().upper()
            tls_version_min = str(openvpn_settings.get("tls_version_min") or "1.2").strip()
            tls_mode = str(openvpn_settings.get("tls_mode") or "tls-crypt").strip().lower()
            tcp_nodelay = bool(openvpn_settings.get("tcp_nodelay", False))
            explicit_exit_notify = openvpn_settings.get("explicit_exit_notify")

            (
                client_protocol,
                client_remote_line,
                obfuscation_directives,
            ) = self._build_client_transport_directives(
                server_address=resolved_server_address,
                default_port=resolved_port,
                default_protocol=effective_protocol,
                obfuscation_settings=obfuscation_settings,
            )

            if not self.is_production:
                # Mock certificate content for development
                ca_cert = "-----BEGIN CERTIFICATE-----\nMOCK CA CERTIFICATE\n-----END CERTIFICATE-----"
                client_cert = "-----BEGIN CERTIFICATE-----\nMOCK CLIENT CERTIFICATE\n-----END CERTIFICATE-----"
                client_key = "-----BEGIN PRIVATE KEY-----\nMOCK CLIENT KEY\n-----END PRIVATE KEY-----"
                ta_key = "-----BEGIN OpenVPN Static key V1-----\nMOCK TA KEY\n-----END OpenVPN Static key V1-----"
            else:
                # Read actual certificate files
                cert_path = self.config.CLIENT_CERTS_DIR / f"{client_name}.crt"
                key_path = self.config.CLIENT_KEYS_DIR / f"{client_name}.key"
                
                with open(self.config.CA_CERT, 'r') as f:
                    ca_cert = f.read()
                with open(cert_path, 'r') as f:
                    client_cert = f.read()
                with open(key_path, 'r') as f:
                    client_key = f.read()
                with open(self.config.TA_KEY, 'r') as f:
                    ta_key = f.read()
            
            # Default builder for non-Apple devices
<<<<<<< HEAD
            is_windows = (os_type or "").lower() == "windows"
<<<<<<< HEAD
            device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
            resolv_retry_mode = str(openvpn_settings.get("resolv_retry_mode", "infinite")).strip().lower()
            persist_key = bool(openvpn_settings.get("persist_key", True))
            persist_tun = bool(openvpn_settings.get("persist_tun", True))
            os_display = os_type.upper() if os_type else "GENERIC"
            
=======
            os_name = (os_type or "").lower()
            is_windows = os_name == "windows"
            is_tcp = "tcp" in client_protocol.lower()
            is_udp = "udp" in client_protocol.lower()
            device_type = str(openvpn_settings.get("device_type", "tun")).strip().lower()
>>>>>>> feature-server-settings
            config_lines: List[str] = [
                "# Atlas VPN - OpenVPN Client Configuration",
                f"# OS: {os_display}",
=======
            config_lines: List[str] = [
                "# Atlas VPN - OpenVPN Client Configuration",
>>>>>>> feature-server-settings
                f"# Client: {client_name}",
                f"# Generated: {datetime.utcnow().isoformat()}",
                "",
                "client",
<<<<<<< HEAD
<<<<<<< HEAD
                f"dev {device_type}",
                f"proto {client_protocol}",
                client_remote_line,
            ]
            
            # Conditional: resolv-retry
            if resolv_retry_mode == "infinite":
                config_lines.append("resolv-retry infinite")
            elif resolv_retry_mode.isdigit():
                config_lines.append(f"resolv-retry {resolv_retry_mode}")
            # else: disabled - don't add directive
            
            config_lines.append("nobind")
            
            # Conditional: persist-key and persist-tun
            if persist_key:
                config_lines.append("persist-key")
            if persist_tun:
                config_lines.append("persist-tun")
            
            config_lines.extend([
                "remote-cert-tls server",
                "verb 3",
            ])
=======
                "dev tun",
=======
                f"dev {device_type}",
>>>>>>> feature-server-settings
                f"proto {client_protocol}",
                client_remote_line,
                "resolv-retry infinite",
                "nobind",
                "persist-key",
                "persist-tun",
                "remote-cert-tls server",
                "verb 3",
            ]
>>>>>>> feature-server-settings

            # Conditional Whitelist: Cryptography (Always Safe)
            if client_data_ciphers:
                config_lines.append(f"data-ciphers {client_data_ciphers}")
            if data_cipher_fallback:
                config_lines.append(f"data-ciphers-fallback {data_cipher_fallback}")
            if auth_digest:
                config_lines.append(f"auth {auth_digest}")
            if tls_version_min:
                config_lines.append(f"tls-version-min {tls_version_min}")

            if tls_mode == "tls-auth":
                config_lines.append("key-direction 1")

            # Stage 2: Safe Builder - Extract DB values with NoneType protection
            tun_mtu = _safe_int(openvpn_settings.get("tun_mtu"))
            mssfix = _safe_int(openvpn_settings.get("mssfix"))
            sndbuf = _safe_int(openvpn_settings.get("sndbuf"))
            rcvbuf = _safe_int(openvpn_settings.get("rcvbuf"))
            keepalive_ping = _safe_int(openvpn_settings.get("keepalive_ping"))
            keepalive_timeout = _safe_int(openvpn_settings.get("keepalive_timeout"))
            redirect_gateway = bool(openvpn_settings.get("redirect_gateway", False))
            primary_dns = (openvpn_settings.get("primary_dns") or "").strip()
            secondary_dns = (openvpn_settings.get("secondary_dns") or "").strip()
            push_custom_routes = (openvpn_settings.get("push_custom_routes") or "").strip()
            
            # Conditional Whitelist: Performance Tuning
            if tun_mtu:
                config_lines.append(f"tun-mtu {int(tun_mtu)}")
            if mssfix:
                config_lines.append(f"mssfix {int(mssfix)}")
            
<<<<<<< HEAD
            # sndbuf/rcvbuf: Only for non-Apple devices (Android/Windows/Linux)
            # Apple devices (iOS/Mac) don't support these directives
            if sndbuf and sndbuf > 0:
                config_lines.append(f"sndbuf {int(sndbuf)}")
            if rcvbuf and rcvbuf > 0:
=======
            if sndbuf:
                config_lines.append(f"sndbuf {int(sndbuf)}")
            if rcvbuf:
>>>>>>> feature-server-settings
                config_lines.append(f"rcvbuf {int(rcvbuf)}")
            
            # Conditional Whitelist: Keepalive
            if keepalive_ping and keepalive_timeout:
                config_lines.append(f"keepalive {int(keepalive_ping)} {int(keepalive_timeout)}")
            
            # Conditional Whitelist: TCP Optimization (ONLY if TCP protocol)
            if tcp_nodelay and is_tcp:
                config_lines.append("tcp-nodelay")

            # STRICT BLACKLIST: Apple devices NEVER get explicit-exit-notify on TCP
            # Only inject for UDP, and skip entirely for Apple on TCP
            if explicit_exit_notify and is_udp:
                config_lines.append(f"explicit-exit-notify {int(explicit_exit_notify)}")
            
            # Conditional Whitelist: Routing
            if redirect_gateway:
                ipv6_network = (openvpn_settings.get("ipv6_network") or "").strip()
                ipv6_prefix = openvpn_settings.get("ipv6_prefix")
                ipv6_enabled = bool(ipv6_network and ipv6_prefix is not None)
                if ipv6_enabled:
                    config_lines.append("redirect-gateway def1 ipv6 bypass-dhcp")
                else:
                    config_lines.append("redirect-gateway def1 bypass-dhcp")
            
            # Conditional Whitelist: DNS Servers
            if primary_dns:
                config_lines.append(f"dhcp-option DNS {primary_dns}")
            if secondary_dns:
                config_lines.append(f"dhcp-option DNS {secondary_dns}")
            
            # Conditional Whitelist: Custom Routes
            if push_custom_routes:
                for route_line in push_custom_routes.splitlines():
                    route_clean = route_line.strip()
                    if route_clean:
                        config_lines.append(f"route {route_clean}")
            
<<<<<<< HEAD
            # Windows-only directive (NOT supported on iOS/Mac)
=======
            # Windows-only directive
>>>>>>> feature-server-settings
            if is_windows:
                config_lines.append("block-outside-dns")

            # Conditional Whitelist: Obfuscation Directives (Proxy/SOCKS)
            # STRICT BLACKLIST: Never inject comp-lzo or compress (deprecated/vulnerable)
            for directive in obfuscation_directives:
                normalized = (directive or "").strip().lower()
                if normalized:
                    # Blacklist forbidden directives
                    if "comp-lzo" in normalized or "compress" in normalized:
                        continue
                    config_lines.append((directive or "").strip())

            # AUTHENTICATION: auth-user-pass and conditional auth-nocache (BEFORE certificates)
            config_lines.append("")
            config_lines.append("auth-user-pass")
            enable_auth_nocache = bool(openvpn_settings.get("enable_auth_nocache", True))
            if enable_auth_nocache:
                config_lines.append("auth-nocache")

            # CERTIFICATES (always last for readability)
            config_lines.extend(
                [
                    "",
                    "<ca>",
                    ca_cert,
                    "</ca>",
                    "",
                    "<cert>",
                    client_cert,
                    "</cert>",
                    "",
                    "<key>",
                    client_key,
                    "</key>",
                ]
            )

            if tls_mode == "tls-crypt":
                config_lines.extend(["", "<tls-crypt>", ta_key, "</tls-crypt>"])
            elif tls_mode == "tls-auth":
                config_lines.extend(["", "<tls-auth>", ta_key, "</tls-auth>"])

            # Conditional Whitelist: OS-Specific Custom Directives
            # ONLY inject if database field is not empty
            os_custom_map = {
                "ios": openvpn_settings.get("custom_ios"),
                "android": openvpn_settings.get("custom_android"),
                "windows": openvpn_settings.get("custom_windows"),
                "mac": openvpn_settings.get("custom_mac"),
                "macos": openvpn_settings.get("custom_mac"),
            }
            
            custom_directives = os_custom_map.get(os_name)
            if custom_directives and (custom_directives or "").strip():
                config_lines.append("")
                config_lines.append(f"# Custom {os_name.upper()} Directives")
                for line in (custom_directives or "").strip().splitlines():
                    cleaned = line.strip().lower()
                    if cleaned:
                        # STRICT BLACKLIST: Filter forbidden directives from custom fields
                        if "comp-lzo" in cleaned or "compress" in cleaned:
                            continue
                        config_lines.append(line.strip())
            
<<<<<<< HEAD
<<<<<<< HEAD
=======
            # Always add auth-user-pass for user authentication
            config_lines.append("")
            config_lines.append("auth-user-pass")
            enable_auth_nocache_final = bool(openvpn_settings.get("enable_auth_nocache", True))
            if enable_auth_nocache_final:
                config_lines.append("auth-nocache")
=======
>>>>>>> feature-server-settings
            config_lines.append("")

>>>>>>> feature-server-settings
            config = "\n".join(config_lines)
            
            # Stage 3: Final Sanity Check - Verify core directives exist
            if "remote " not in config and "client" not in config:
                raise HTTPException(status_code=500, detail="Config was generated but is missing core directives.")
            
            return config
            
        except Exception as e:
            logger.error(f"Config generation failed: {e}")
            return None

    @staticmethod
    def _extract_remote_hostname(value: str) -> str:
        candidate = (value or "").strip()
        if not candidate:
            return ""

        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        hostname = (parsed.hostname or "").strip()
        if hostname:
            return hostname

        return candidate.split("/")[0].split(":")[0].strip()

    def _build_client_transport_directives(
        self,
        server_address: str,
        default_port: int,
        default_protocol: str,
        obfuscation_settings: Dict[str, any],
    ) -> Tuple[str, str, List[str]]:
        mode = str(obfuscation_settings.get("obfuscation_mode", "standard") or "standard").strip().lower()

        proxy_server = (obfuscation_settings.get("proxy_server") or "").strip()
        proxy_address = (obfuscation_settings.get("proxy_address") or "").strip()
        proxy_target = proxy_server or proxy_address or server_address
        proxy_port = int(obfuscation_settings.get("proxy_port") or 8080)
        spoofed_host = (obfuscation_settings.get("spoofed_host") or "").strip()
        socks_server = (obfuscation_settings.get("socks_server") or "").strip()
        socks_port = obfuscation_settings.get("socks_port")
        stunnel_port = int(obfuscation_settings.get("stunnel_port") or 443)
        sni_domain = (obfuscation_settings.get("sni_domain") or "").strip()
        ws_path = (obfuscation_settings.get("ws_path") or "/stream").strip() or "/stream"
        ws_port = int(obfuscation_settings.get("ws_port") or 8080)
        cdn_raw = (obfuscation_settings.get("cdn_domain") or "").strip()
        cdn_host = self._extract_remote_hostname(cdn_raw)

        if mode == "stealth":
            directives: List[str] = ["http-proxy-retry"]
            if spoofed_host:
                directives.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
            return "tcp", f"remote {server_address} 443", directives

        if mode == "http_proxy_basic":
            directives = [
                f"http-proxy {proxy_target} {proxy_port}",
                "http-proxy-retry",
            ]
            return "tcp", f"remote {server_address} 443", directives

        if mode == "http_proxy_advanced":
            directives: List[str] = [
                f"http-proxy {proxy_target} {proxy_port}",
                "http-proxy-retry",
            ]
            if spoofed_host:
                directives.append(f"http-proxy-option CUSTOM-HEADER Host {spoofed_host}")
            return "tcp", f"remote {server_address} 443", directives

        if mode == "socks5_proxy_injection":
            socks_target = socks_server or proxy_target
            socks_target_port = int(socks_port or 1080)
            directives = [
                f"socks-proxy {socks_target} {socks_target_port}",
                "socks-proxy-retry",
            ]
            return "tcp", f"remote {server_address} 443", directives

        if mode == "tls_tunnel":
            directives = [
                "# TLS tunnel mode: run local Stunnel client before connecting.",
            ]
            if sni_domain:
                directives.append(f"# TLS SNI domain hint: {sni_domain}")
            return "tcp", f"remote 127.0.0.1 {stunnel_port}", directives

        if mode == "websocket_cdn":
            remote_target = cdn_host or server_address
            directives = [
                f"# WebSocket path hint: {ws_path}",
                f"# Local WebSocket port hint: {ws_port}",
            ]
            return "tcp", f"remote {remote_target} 443", directives

        return default_protocol, f"remote {server_address} {default_port}", []

    def _resolve_client_transport_settings(
        self,
        server_port: Optional[int],
        protocol: Optional[str],
    ) -> Tuple[int, str]:
        if server_port is not None and protocol:
            return int(server_port), str(protocol).strip().lower()

        try:
            from backend.database import SessionLocal
            from backend.models.openvpn_settings import OpenVPNSettings

            db = SessionLocal()
            try:
                settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
                if settings:
                    resolved_port = int(server_port if server_port is not None else settings.port)
                    resolved_protocol = str(protocol or settings.protocol).strip().lower()
                    return resolved_port, resolved_protocol
            finally:
                db.close()
        except Exception as exc:
            logger.warning(f"Falling back to default OpenVPN transport settings: {exc}")

        resolved_port = int(server_port if server_port is not None else 1194)
        resolved_protocol = str(protocol or "udp").strip().lower()
        return resolved_port, resolved_protocol

    def _resolve_client_obfuscation_settings(self) -> Dict[str, any]:
        try:
            from backend.database import SessionLocal
            from backend.models.openvpn_settings import OpenVPNSettings

            db = SessionLocal()
            try:
                settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
                if settings:
                    return {
                        "obfuscation_mode": settings.obfuscation_mode,
                        "proxy_server": settings.proxy_server,
                        "proxy_address": settings.proxy_address,
                        "proxy_port": settings.proxy_port,
                        "spoofed_host": settings.spoofed_host,
                        "socks_server": settings.socks_server,
                        "socks_port": settings.socks_port,
                        "stunnel_port": settings.stunnel_port,
                        "sni_domain": settings.sni_domain,
                        "cdn_domain": settings.cdn_domain,
                        "ws_path": settings.ws_path,
                        "ws_port": settings.ws_port,
                    }
            finally:
                db.close()
        except Exception as exc:
            logger.warning(f"Falling back to default obfuscation settings: {exc}")

        return {
            "obfuscation_mode": "standard",
            "proxy_server": None,
            "proxy_address": None,
            "proxy_port": 8080,
            "spoofed_host": "speedtest.net",
            "socks_server": None,
            "socks_port": None,
            "stunnel_port": 443,
            "sni_domain": None,
            "cdn_domain": None,
            "ws_path": "/stream",
            "ws_port": 8080,
        }

    def _resolve_client_remote_address(
        self,
        server_address: Optional[str],
        protocol: str,
    ) -> str:
        explicit_address = (server_address or "").strip()
        if explicit_address:
            return explicit_address

        try:
            from backend.database import SessionLocal
            from backend.models.general_settings import GeneralSettings

            db = SessionLocal()
            try:
                settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
                if settings:
                    persisted_address = (settings.server_address or "").strip()
                    if persisted_address:
                        return persisted_address
            finally:
                db.close()
        except Exception as exc:
            logger.warning(f"Falling back to default client remote address: {exc}")

        return "YOUR_SERVER_IP"

    def _validate_openvpn_settings(self, settings: Dict[str, Any]) -> None:
        """Legacy validation - kept for compatibility but should not be used."""
        pass

    def generate_server_config(self, settings: Optional[Dict[str, any]] = None) -> Dict[str, any]:
        """Generate OpenVPN 2.6 server.conf content from persisted settings."""
        try:
            runtime_openvpn_settings, _ = self._load_runtime_settings()
            effective_settings: Dict[str, any] = dict(runtime_openvpn_settings)
            if settings:
                for key, value in settings.items():
                    if value is not None:
                        effective_settings[key] = value

            settings = effective_settings
            self._validate_openvpn_settings(settings)

            port = int(settings.get("port", 1194))
            protocol = str(settings.get("protocol", "udp")).lower().strip()
            obfuscation_mode = str(settings.get("obfuscation_mode", "standard") or "standard").strip().lower()
            if obfuscation_mode != "standard":
                protocol = "tcp"
            device_type = str(settings.get("device_type", "tun")).lower().strip()
            topology = str(settings.get("topology", "subnet")).lower().strip()
            ipv4_network = str(settings.get("ipv4_network", "10.8.0.0")).strip()
            ipv4_netmask = str(settings.get("ipv4_netmask", "255.255.255.0")).strip()
            legacy_ipv4_pool = str(settings.get("ipv4_pool", "")).strip()
            if legacy_ipv4_pool and not settings.get("ipv4_network"):
                parts = [part for part in legacy_ipv4_pool.split() if part]
                if len(parts) >= 2:
                    ipv4_network, ipv4_netmask = parts[0], parts[1]

            ipv6_network = (settings.get("ipv6_network") or "").strip()
            ipv6_prefix = settings.get("ipv6_prefix")
            legacy_ipv6_pool = (settings.get("ipv6_pool") or "").strip()
            if legacy_ipv6_pool and not ipv6_network:
                if "/" in legacy_ipv6_pool:
                    pool_parts = legacy_ipv6_pool.split("/", 1)
                    ipv6_network = pool_parts[0].strip()
                    try:
                        ipv6_prefix = int(pool_parts[1].strip())
                    except ValueError:
                        ipv6_prefix = None
                else:
                    ipv6_network = legacy_ipv6_pool

            ipv4_pool = f"{ipv4_network} {ipv4_netmask}".strip()
            max_clients = int(settings.get("max_clients", 100))
            client_to_client = bool(settings.get("client_to_client", False))

            redirect_gateway = bool(settings.get("redirect_gateway", True))
            primary_dns = str(settings.get("primary_dns", "8.8.8.8")).strip()
            secondary_dns = str(settings.get("secondary_dns", "1.1.1.1")).strip()
            block_outside_dns = bool(settings.get("block_outside_dns", False))
            push_custom_routes = (settings.get("push_custom_routes") or "").strip()

            raw_data_ciphers = settings.get("data_ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
            if isinstance(raw_data_ciphers, list):
                data_ciphers = ":".join([cipher.strip() for cipher in raw_data_ciphers if cipher and cipher.strip()])
            else:
                data_ciphers = str(raw_data_ciphers).strip() or "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

            tls_version_min = str(settings.get("tls_version_min", "1.2")).strip()
            tls_mode = str(settings.get("tls_mode", "tls-crypt")).lower().strip()
            auth_digest = str(settings.get("auth_digest", "SHA256")).upper().strip()
            reneg_sec = int(settings.get("reneg_sec", 3600))

            def _safe_int(value, default=None):
                try:
                    if value is None or (isinstance(value, str) and not value.strip()):
                        return default
                    return int(value)
                except (ValueError, TypeError):
                    return default

            tun_mtu = _safe_int(settings.get("tun_mtu"))
            mssfix = _safe_int(settings.get("mssfix"))
            sndbuf = _safe_int(settings.get("sndbuf"))
            rcvbuf = _safe_int(settings.get("rcvbuf"))
            fast_io = bool(settings.get("fast_io", False))
            tcp_nodelay = bool(settings.get("tcp_nodelay", False))
            explicit_exit_notify = int(settings.get("explicit_exit_notify", 1))

            keepalive_ping = int(settings.get("keepalive_ping", 10))
            keepalive_timeout = int(settings.get("keepalive_timeout", 120))
            inactive_timeout = int(settings.get("inactive_timeout", 300))
            management_port = int(settings.get("management_port", 5555))
            verbosity = int(settings.get("verbosity", 3))

            custom_directives = (settings.get("custom_directives") or "").strip()

            if protocol not in {"udp", "tcp", "udp6", "tcp6"}:
                raise ValueError("Protocol must be udp, tcp, udp6, or tcp6")
            if device_type not in {"tun", "tap"}:
                raise ValueError("Device type must be tun or tap")
            if topology != "subnet":
                raise ValueError("Topology must be subnet")
            if tls_version_min not in {"1.2", "1.3"}:
                raise ValueError("TLS minimum version must be 1.2 or 1.3")
            if tls_mode not in {"tls-crypt", "tls-auth", "none"}:
                raise ValueError("TLS mode must be tls-crypt, tls-auth, or none")
            if auth_digest not in {"SHA256", "SHA384", "SHA512"}:
                raise ValueError("Auth digest must be SHA256, SHA384, or SHA512")

            push_lines: List[str] = []
            if redirect_gateway:
                ipv6_enabled = bool(ipv6_network and ipv6_prefix is not None)
                if ipv6_enabled:
                    push_lines.append('push "redirect-gateway def1 ipv6 bypass-dhcp"')
                else:
                    push_lines.append('push "redirect-gateway def1 bypass-dhcp"')
            if primary_dns:
                push_lines.append(f'push "dhcp-option DNS {primary_dns}"')
            if secondary_dns:
                push_lines.append(f'push "dhcp-option DNS {secondary_dns}"')
            if block_outside_dns:
                push_lines.append('push "block-outside-dns"')
            # Custom Routes (comma or newline separated)
            push_custom_routes = (settings.get("push_custom_routes") or "").strip()
            if push_custom_routes:
                for route in [seg.strip() for seg in push_custom_routes.replace(',', '\n').splitlines() if seg.strip()]:
                    # Normalize and prepend push route
                    sanitized = route.replace('route ', '').strip()
                    push_lines.append(f'push "route {sanitized}"')
            
            advanced_client_push = (settings.get("advanced_client_push") or "").strip()
            if advanced_client_push:
                for directive in [line.strip() for line in advanced_client_push.splitlines() if line.strip()]:
                    if directive.startswith("push "):
                        push_lines.append(directive)
                    else:
                        push_lines.append(f'push "{directive}"')

            if tls_mode == "tls-crypt":
                tls_mode_line = f"tls-crypt {self.config.TA_KEY}"
            elif tls_mode == "tls-auth":
                tls_mode_line = f"tls-auth {self.config.TA_KEY} 0"
            else:
                tls_mode_line = None

            server_lines: List[str] = [
                "# Atlas VPN - OpenVPN Server Configuration",
                f"# Generated: {datetime.utcnow().isoformat()}",
                "",
                f"port {port}",
                f"proto {protocol}",
                f"dev {device_type}",
                f"topology {topology}",
                f"server {ipv4_pool}",
            ]

            if ipv6_network and ipv6_prefix is not None:
                server_lines.append(f"server-ipv6 {ipv6_network}/{int(ipv6_prefix)}")

            if max_clients:
                server_lines.append(f"max-clients {max_clients}")
            if client_to_client:
                server_lines.append("client-to-client")

            server_lines.extend(
                [
                    "",
                    f"ca {self.config.CA_CERT}",
                    f"cert {self.config.SERVER_CERT}",
                    f"key {self.config.SERVER_KEY}",
                    f"dh {self.config.DH_PARAMS}",
                ]
            )

            if data_ciphers:
                server_lines.append(f"data-ciphers {data_ciphers}")
                server_lines.append("data-ciphers-fallback AES-256-GCM")
            if auth_digest:
                server_lines.append(f"auth {auth_digest}")
            if tls_version_min:
                server_lines.append(f"tls-version-min {tls_version_min}")
            if tls_mode_line:
                server_lines.append(tls_mode_line)
            if reneg_sec is not None:
                server_lines.append(f"reneg-sec {int(reneg_sec)}")

            if keepalive_ping and keepalive_timeout:
                server_lines.append(f"keepalive {keepalive_ping} {keepalive_timeout}")
            if inactive_timeout and int(inactive_timeout) > 0:
                server_lines.append(f"inactive {int(inactive_timeout)}")

            server_lines.extend(["persist-key", "persist-tun"])

            if sndbuf and int(sndbuf) > 0:
                server_lines.append(f"sndbuf {int(sndbuf)}")
            if rcvbuf and int(rcvbuf) > 0:
                server_lines.append(f"rcvbuf {int(rcvbuf)}")
            if fast_io and protocol in {"udp", "udp6"}:
                server_lines.append("fast-io")
            if tcp_nodelay and protocol in {"tcp", "tcp6"}:
                server_lines.append("tcp-nodelay")
            if tun_mtu and int(tun_mtu) > 0:
                server_lines.append(f"tun-mtu {int(tun_mtu)}")
            if mssfix and int(mssfix) > 0:
                server_lines.append(f"mssfix {int(mssfix)}")
            if protocol in {"udp", "udp6"} and explicit_exit_notify and int(explicit_exit_notify) > 0:
                server_lines.append(f"explicit-exit-notify {int(explicit_exit_notify)}")
            if management_port and int(management_port) > 0:
                server_lines.append(f"management 127.0.0.1 {int(management_port)}")

            if push_lines:
                server_lines.append("")
                server_lines.extend(push_lines)

            server_lines.extend(["", "user nobody", "group nogroup"])
            if verbosity is not None:
                server_lines.append(f"verb {int(verbosity)}")

            if custom_directives:
                server_lines.append("")
                server_lines.extend([line.strip() for line in custom_directives.splitlines() if line.strip()])

            server_lines.append("")
            server_conf = "\n".join(server_lines)

            if self.is_production:
                self.config.SERVER_CONF.parent.mkdir(parents=True, exist_ok=True)
                self.config.SERVER_CONF.write_text(server_conf)
                logger.info(f"OpenVPN server configuration written to {self.config.SERVER_CONF}")
            else:
                logger.info("[MOCK] OpenVPN server configuration generated (not written in development mode)")

            return {
                "success": True,
                "message": "OpenVPN server configuration generated successfully",
                "config_path": str(self.config.SERVER_CONF),
                "content": server_conf,
                "is_mock": not self.is_production,
            }

        except Exception as e:
            logger.error(f"OpenVPN server configuration generation failed: {e}")
            return {
                "success": False,
                "message": f"Failed to generate OpenVPN server configuration: {str(e)}",
                "error": str(e),
            }

    def _get_os_specific_directives(self, os_type: str) -> str:
        """Return additional directives optimized for target client OS."""
        directives_by_os = {
            "windows": "setenv opt block-outside-dns\nregister-dns",
            "mac": "resolv-retry 30\nroute-delay 2",
            "macos": "resolv-retry 30\nroute-delay 2",
            "ios": "resolv-retry 30\nexplicit-exit-notify",
            "mac_ios": "resolv-retry 30\nexplicit-exit-notify",
            "android": "explicit-exit-notify\nremote-cert-tls server",
            "linux": "resolv-retry infinite\nscript-security 2"
        }
        return directives_by_os.get(os_type, "")
    
    def generate_qr_code(self, config_content: str) -> Optional[str]:
        """
        Generate QR code for mobile clients.
        
        Args:
            config_content: .ovpn configuration content
            
        Returns:
            Base64 encoded PNG image
        """
        try:
            qr = qrcode.QRCode(
                version=None,  # Auto-determine size
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(config_content)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
            
        except Exception as e:
            logger.error(f"QR code generation failed: {e}")
            return None
    
    def get_service_status(self) -> Dict[str, any]:
        """
        Get OpenVPN service status using systemctl.
        
        Returns:
            Dict with service status information
        """
        try:
            success, stdout, stderr = self._run_command([
                "systemctl",
                "status",
                self.config.SERVICE_NAME
            ], check=False)
            
            # Parse systemctl output
            is_active = "active (running)" in stdout
            is_enabled = "enabled" in stdout
            
            return {
                "success": True,
                "service_name": self.config.SERVICE_NAME,
                "is_active": is_active,
                "is_enabled": is_enabled,
                "status_output": stdout,
                "is_mock": not self.is_production
            }
            
        except Exception as e:
            logger.error(f"Service status check failed: {e}")
            return {
                "success": False,
                "message": f"Status check failed: {str(e)}",
                "error": str(e)
            }
    
    def control_service(self, action: str) -> Dict[str, any]:
        """
        Control OpenVPN service (start/stop/restart).
        
        Args:
            action: start, stop, restart, or enable
            
        Returns:
            Dict with operation result
        """
        if action not in ["start", "stop", "restart", "enable", "disable"]:
            return {
                "success": False,
                "message": f"Invalid action: {action}"
            }
        
        try:
            success, stdout, stderr = self._run_command([
                "systemctl",
                action,
                self.config.SERVICE_NAME
            ])
            
            return {
                "success": success,
                "action": action,
                "service_name": self.config.SERVICE_NAME,
                "message": f"Service {action} completed",
                "is_mock": not self.is_production
            }
            
        except Exception as e:
            logger.error(f"Service control failed: {e}")
            return {
                "success": False,
                "message": f"Service {action} failed: {str(e)}",
                "error": str(e)
            }
