import logging
import os
import platform
import shutil
import subprocess
import time
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
        pki_crl_path: Path,
        openvpn_crl_path: Path,
        client_certs_dir: Path,
        client_keys_dir: Path,
        is_production: bool,
    ) -> None:
        self.easyrsa_dir = Path(easyrsa_dir)
        self.pki_dir = Path(pki_dir)
        self.ca_cert_path = Path(ca_cert_path)
        self.ta_key_path = Path(ta_key_path)
        self.pki_crl_path = Path(pki_crl_path)
        self.openvpn_crl_path = Path(openvpn_crl_path)
        self.client_certs_dir = Path(client_certs_dir)
        self.client_keys_dir = Path(client_keys_dir)
        self.server_cert_path = self.pki_dir / "issued" / "server.crt"
        self.server_key_path = self.pki_dir / "private" / "server.key"
        self.dh_params_path = self.pki_dir / "dh.pem"
        self.is_production = bool(is_production)

    def _chmod_if_exists(self, path: Path, mode: int) -> None:
        if not self._is_supported_runtime():
            return
        try:
            if path.exists():
                os.chmod(path, mode)
        except Exception as exc:
            logger.warning("Failed to chmod %s to %o: %s", path, mode, exc)

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
        env_overrides: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, str, str]:
        try:
            env = dict(os.environ)
            env["EASYRSA_BATCH"] = "1"
            if env_overrides:
                env.update(env_overrides)

            result = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                input=input_text,
                text=True,
                capture_output=True,
                check=check,
                env=env,
            )

            stderr_text = (result.stderr or "").strip()
            if "No Easy-RSA 'vars' configuration file exists" in stderr_text:
                logger.warning("Easy-RSA vars file is missing; proceeding based on return code")

            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.CalledProcessError as exc:
            return False, exc.stdout or "", exc.stderr or str(exc)
        except FileNotFoundError as exc:
            return False, "", str(exc)
        except Exception as exc:
            return False, "", str(exc)

    def _ensure_crl_available(self, easyrsa_cmd: List[str]) -> Dict[str, Any]:
        ok, out, err = self._run_command([*easyrsa_cmd, "gen-crl"], cwd=self.easyrsa_dir, check=False)
        if not ok:
            return {"success": False, "message": f"gen-crl failed: {err or out}"}

        if not self.pki_crl_path.exists():
            return {"success": False, "message": f"gen-crl succeeded but CRL file missing at {self.pki_crl_path}"}

        self.openvpn_crl_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(self.pki_crl_path, self.openvpn_crl_path)
        except Exception as exc:
            return {"success": False, "message": f"failed to place crl.pem for OpenVPN: {exc}"}

        self._chmod_if_exists(self.openvpn_crl_path, 0o644)
        return {"success": True, "crl_path": str(self.openvpn_crl_path)}

    def ensure_ready(self) -> Dict[str, Any]:
        """Auto-init PKI and server materials if missing; never crash in dev."""
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
        server_cert_exists = self.server_cert_path.exists()
        server_key_exists = self.server_key_path.exists()
        dh_exists = self.dh_params_path.exists()

        if ca_exists and ta_exists and server_cert_exists and server_key_exists and dh_exists:
            crl_result = self._ensure_crl_available(easyrsa_cmd)
            if not crl_result.get("success"):
                return crl_result
            return {
                "success": True,
                "message": "PKI already initialized",
                "auto_initialized": False,
                "crl_path": crl_result.get("crl_path"),
            }

        self.easyrsa_dir.mkdir(parents=True, exist_ok=True)
        self.ta_key_path.parent.mkdir(parents=True, exist_ok=True)

        index_file = self.pki_dir / "index.txt"
        if not index_file.exists():
            ok, out, err = self._run_command([*easyrsa_cmd, "init-pki"], cwd=self.easyrsa_dir, check=False)
            if not ok:
                return {"success": False, "message": f"init-pki failed: {err or out}"}

        if not ca_exists:
            ok, out, err = self._run_command(
                [*easyrsa_cmd, "build-ca", "nopass"],
                cwd=self.easyrsa_dir,
                check=False,
                env_overrides={"EASYRSA_REQ_CN": "Atlas-CA"},
            )
            if not ok:
                return {"success": False, "message": f"build-ca failed: {err or out}"}

        if not (server_cert_exists and server_key_exists):
            ok, out, err = self._run_command(
                [*easyrsa_cmd, "build-server-full", "server", "nopass"],
                cwd=self.easyrsa_dir,
                check=False,
            )
            if not ok:
                return {"success": False, "message": f"build-server-full failed: {err or out}"}

        if not dh_exists:
            ok, out, err = self._run_command([*easyrsa_cmd, "gen-dh"], cwd=self.easyrsa_dir, check=False)
            if not ok:
                return {"success": False, "message": f"gen-dh failed: {err or out}"}

        if not ta_exists:
            ok, out, err = self._run_command(["openvpn", "--genkey", "secret", str(self.ta_key_path)], check=False)
            if not ok:
                # Fallback syntax supported by older OpenVPN versions
                ok, out, err = self._run_command(["openvpn", "--genkey", "--secret", str(self.ta_key_path)], check=False)
                if not ok:
                    return {"success": False, "message": f"ta.key generation failed: {err or out}"}

        self._chmod_if_exists(self.ta_key_path, 0o600)
        self._chmod_if_exists(self.server_key_path, 0o600)
        self._chmod_if_exists(self.dh_params_path, 0o600)

        crl_result = self._ensure_crl_available(easyrsa_cmd)
        if not crl_result.get("success"):
            return crl_result

        return {
            "success": True,
            "message": "PKI initialized",
            "auto_initialized": True,
            "ca_created": self.ca_cert_path.exists(),
            "server_cert_created": self.server_cert_path.exists(),
            "server_key_created": self.server_key_path.exists(),
            "dh_created": self.dh_params_path.exists(),
            "ta_key_created": self.ta_key_path.exists(),
            "crl_path": crl_result.get("crl_path"),
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

        # File-system preflight confirmation for successful provisioning.
        # Easy-RSA can emit informative logs on stderr even when return code is zero.
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if cert_path.exists() and key_path.exists():
                break
            time.sleep(0.1)

        if not cert_path.exists() or not key_path.exists():
            missing_paths = []
            if not cert_path.exists():
                missing_paths.append(str(cert_path))
            if not key_path.exists():
                missing_paths.append(str(key_path))
            return {
                "success": False,
                "message": "build-client-full completed but expected PKI files are missing: " + ", ".join(missing_paths),
                "client_name": username,
                "cert_path": str(cert_path),
                "key_path": str(key_path),
                "ca_path": str(self.ca_cert_path),
                "ta_key_path": str(self.ta_key_path),
            }

        self._chmod_if_exists(key_path, 0o600)
        return {
            "success": True,
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

        if self.pki_crl_path.exists():
            self.openvpn_crl_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(self.pki_crl_path, self.openvpn_crl_path)
            except Exception as exc:
                return {"success": False, "message": f"failed to place crl.pem for OpenVPN: {exc}"}

            # CRL should be readable by OpenVPN process immediately.
            self._chmod_if_exists(self.openvpn_crl_path, 0o644)

        return {
            "success": True,
            "message": f"Certificate revoked and CRL regenerated for {username}",
            "client_name": username,
            "crl_path": str(self.openvpn_crl_path),
        }
