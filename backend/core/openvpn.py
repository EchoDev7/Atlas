# Atlas — OpenVPN Core Logic
# Phase 2: OpenVPN management with mock support for development

import subprocess
import os
import platform
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime
import qrcode
import io
import base64

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
    
    def generate_client_config(
        self,
        client_name: str,
        server_address: str,
        server_port: int = 1194,
        protocol: str = "udp"
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
        try:
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
            
            # Generate .ovpn configuration
            config = f"""# Atlas VPN - OpenVPN Client Configuration
# Client: {client_name}
# Generated: {datetime.utcnow().isoformat()}

client
dev tun
proto {protocol}
remote {server_address} {server_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
key-direction 1
verb 3

<ca>
{ca_cert}
</ca>

<cert>
{client_cert}
</cert>

<key>
{client_key}
</key>

<tls-auth>
{ta_key}
</tls-auth>
"""
            return config
            
        except Exception as e:
            logger.error(f"Config generation failed: {e}")
            return None
    
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
