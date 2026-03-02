import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


class PKIManager:
    """Production-safe Easy-RSA/OpenVPN PKI lifecycle manager."""

    def __init__(
        self,
        *,
        easyrsa_dir: Path,
        pki_dir: Path,
        ca_cert_path: Path,
        ta_key_path: Path,
        client_certs_dir: Path,
        client_keys_dir: Path,
        is_production: bool,
    ) -> None:
        self.easyrsa_dir = Path(easyrsa_dir)
        self.pki_dir = Path(pki_dir)
        self.ca_cert_path = Path(ca_cert_path)
        self.ta_key_path = Path(ta_key_path)
        self.client_certs_dir = Path(client_certs_dir)
        self.client_keys_dir = Path(client_keys_dir)
        self.is_production = bool(is_production)

    def _is_supported_runtime(self) -> bool:
        return self.is_production and platform.system() == "Linux"

    def _find_easyrsa_executable(self) -> Optional[List[str]]:
        local_bin = self.easyrsa_dir / "easyrsa"
        if local_bin.exists():
            return [str(local_bin)]

        global_bin = shutil.which("easyrsa")
        if global_bin:
            return [global_bin]

        return None

    def is_easyrsa_available(self) -> bool:
        return self._find_easyrsa_executable() is not None

    def _run_command(
        self,
        command: List[str],
        *,
        cwd: Optional[Path] = None,
        input_text: Optional[str] = None,
        check: bool = True,
    ) -> Tuple[bool, str, str]:
        try:
            env = dict(os.environ)
            env["EASYRSA_BATCH"] = "1"

            result = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                input=input_text,
                text=True,
                capture_output=True,
                check=check,
                env=env,
            )
            return True, result.stdout, result.stderr
        except subprocess.CalledProcessError as exc:
            return False, exc.stdout or "", exc.stderr or str(exc)
        except FileNotFoundError as exc:
            return False, "", str(exc)
        except Exception as exc:
            return False, "", str(exc)

    def ensure_ready(self) -> Dict[str, Any]:
        """Auto-init PKI (init-pki/build-ca/ta.key) if missing; never crash in dev."""
        if not self._is_supported_runtime():
            logger.warning("PKI skipped: non-production or non-Linux runtime")
            return {
                "success": False,
                "degraded": True,
                "message": "PKI unavailable in development/non-Linux runtime",
            }

        easyrsa_cmd = self._find_easyrsa_executable()
        if not easyrsa_cmd:
            logger.warning("PKI skipped: easyrsa executable not found")
            return {
                "success": False,
                "degraded": True,
                "message": "Easy-RSA not installed",
            }

        ca_exists = self.ca_cert_path.exists()
        ta_exists = self.ta_key_path.exists()
        if ca_exists and ta_exists:
            return {
                "success": True,
                "message": "PKI already initialized",
                "auto_initialized": False,
            }

        self.easyrsa_dir.mkdir(parents=True, exist_ok=True)
        self.ta_key_path.parent.mkdir(parents=True, exist_ok=True)

        ok, out, err = self._run_command([*easyrsa_cmd, "init-pki"], cwd=self.easyrsa_dir, check=False)
        if not ok:
            return {"success": False, "message": f"init-pki failed: {err or out}"}

        ok, out, err = self._run_command([*easyrsa_cmd, "build-ca", "nopass"], cwd=self.easyrsa_dir, check=False)
        if not ok:
            return {"success": False, "message": f"build-ca failed: {err or out}"}

        ok, out, err = self._run_command(["openvpn", "--genkey", "secret", str(self.ta_key_path)], check=False)
        if not ok:
            # Fallback syntax supported by older OpenVPN versions
            ok, out, err = self._run_command(["openvpn", "--genkey", "--secret", str(self.ta_key_path)], check=False)
            if not ok:
                return {"success": False, "message": f"ta.key generation failed: {err or out}"}

        return {
            "success": True,
            "message": "PKI initialized",
            "auto_initialized": True,
            "ca_created": self.ca_cert_path.exists(),
            "ta_key_created": self.ta_key_path.exists(),
        }

    def build_client(self, username: str) -> Dict[str, Any]:
        username = (username or "").strip()
        if not username:
            return {"success": False, "message": "Missing username"}

        ready = self.ensure_ready()
        if not ready.get("success"):
            return ready

        easyrsa_cmd = self._find_easyrsa_executable()
        if not easyrsa_cmd:
            return {"success": False, "message": "Easy-RSA not installed"}

        ok, out, err = self._run_command(
            [*easyrsa_cmd, "build-client-full", username, "nopass"],
            cwd=self.easyrsa_dir,
            check=False,
        )
        if not ok:
            return {"success": False, "message": f"build-client-full failed: {err or out}"}

        cert_path = self.client_certs_dir / f"{username}.crt"
        key_path = self.client_keys_dir / f"{username}.key"
        return {
            "success": cert_path.exists() and key_path.exists(),
            "message": f"Client certificate created for {username}",
            "client_name": username,
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "ca_path": str(self.ca_cert_path),
            "ta_key_path": str(self.ta_key_path),
        }

    def revoke_client(self, username: str) -> Dict[str, Any]:
        username = (username or "").strip()
        if not username:
            return {"success": False, "message": "Missing username"}

        if not self._is_supported_runtime():
            logger.warning("Revoke skipped: non-production or non-Linux runtime")
            return {
                "success": False,
                "degraded": True,
                "message": "Revoke unavailable in development/non-Linux runtime",
            }

        easyrsa_cmd = self._find_easyrsa_executable()
        if not easyrsa_cmd:
            return {"success": False, "degraded": True, "message": "Easy-RSA not installed"}

        ok, out, err = self._run_command(
            [*easyrsa_cmd, "revoke", username],
            cwd=self.easyrsa_dir,
            input_text="yes\n",
            check=False,
        )
        if not ok:
            return {"success": False, "message": f"revoke failed: {err or out}"}

        ok, out, err = self._run_command([*easyrsa_cmd, "gen-crl"], cwd=self.easyrsa_dir, check=False)
        if not ok:
            return {"success": False, "message": f"gen-crl failed: {err or out}"}

        return {
            "success": True,
            "message": f"Certificate revoked and CRL regenerated for {username}",
            "client_name": username,
        }
