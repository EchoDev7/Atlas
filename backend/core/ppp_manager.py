from __future__ import annotations

import os
import re
import secrets
import shutil
import string
import subprocess
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.core.config import (
    IPSEC_SECRETS_PATH,
    L2TP_DEFAULT_LOCAL_IP,
    PPP_CHAP_SECRETS_PATH,
    PPP_INTERFACE_PREFIX,
    PPP_PS_COMMAND,
    PPP_RADATTR_DIR,
    XL2TPD_CONFIG_PATH,
)


class PPPManager:
    """Shared PPP core manager for L2TP credentials and runtime sessions."""

    def __init__(self, chap_secrets_path: Optional[Path] = None) -> None:
        self.chap_secrets_path = Path(chap_secrets_path or PPP_CHAP_SECRETS_PATH)

    @staticmethod
    def _extract_l2tp_pool(subnet_cidr: str) -> tuple[str, str]:
        network: IPv4Network = ip_network(str(subnet_cidr or "").strip(), strict=False)
        hosts = list(network.hosts())
        if len(hosts) < 12:
            raise ValueError("L2TP subnet must have at least 12 usable host IPs")
        local_ip = str(hosts[0])
        remote_start = str(hosts[9])
        remote_end = str(hosts[-1])
        return local_ip, f"{remote_start}-{remote_end}"

    @staticmethod
    def _render_ipsec_secrets(psk: str) -> str:
        normalized_psk = str(psk or "").strip()
        if len(normalized_psk) < 8:
            raise ValueError("L2TP IPsec PSK must be at least 8 characters")
        return f'%any %any : PSK "{normalized_psk}"\n'

    @staticmethod
    def _render_xl2tpd_config(local_ip: str, remote_pool: str) -> str:
        normalized_local = str(local_ip or "").strip() or L2TP_DEFAULT_LOCAL_IP
        normalized_pool = str(remote_pool or "").strip()
        if not normalized_pool:
            raise ValueError("L2TP remote pool cannot be empty")
        return "\n".join(
            [
                "[global]",
                "ipsec saref = yes",
                "",
                "[lns default]",
                f"ip range = {normalized_pool}",
                f"local ip = {normalized_local}",
                "require chap = yes",
                "refuse pap = yes",
                "require authentication = yes",
                "name = xl2tpd",
                "pppoptfile = /etc/ppp/options.xl2tpd",
                "length bit = yes",
                "",
            ]
        )

    @staticmethod
    def _restart_l2tp_daemons() -> Dict[str, Any]:
        actions: list[Dict[str, Any]] = []

        if shutil.which("systemctl"):
            for unit in ("strongswan-starter", "strongswan", "xl2tpd"):
                result = subprocess.run(["systemctl", "restart", unit], capture_output=True, text=True, check=False)
                actions.append(
                    {
                        "command": f"systemctl restart {unit}",
                        "returncode": int(result.returncode),
                        "stdout": (result.stdout or "").strip(),
                        "stderr": (result.stderr or "").strip(),
                    }
                )
        elif shutil.which("ipsec"):
            result = subprocess.run(["ipsec", "restart"], capture_output=True, text=True, check=False)
            actions.append(
                {
                    "command": "ipsec restart",
                    "returncode": int(result.returncode),
                    "stdout": (result.stdout or "").strip(),
                    "stderr": (result.stderr or "").strip(),
                }
            )

        failed = [action for action in actions if action.get("returncode") != 0]
        return {
            "success": len(failed) == 0,
            "actions": actions,
            "failed": failed,
        }

    def apply_l2tp_runtime_settings(self, ipsec_psk: str, client_subnet: str) -> Dict[str, Any]:
        local_ip, remote_pool = self._extract_l2tp_pool(client_subnet)
        ipsec_content = self._render_ipsec_secrets(ipsec_psk)
        xl2tpd_content = self._render_xl2tpd_config(local_ip=local_ip, remote_pool=remote_pool)

        IPSEC_SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
        XL2TPD_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        IPSEC_SECRETS_PATH.write_text(ipsec_content, encoding="utf-8")
        XL2TPD_CONFIG_PATH.write_text(xl2tpd_content, encoding="utf-8")

        restart_result = self._restart_l2tp_daemons()
        return {
            "success": bool(restart_result.get("success")),
            "ipsec_secrets_path": str(IPSEC_SECRETS_PATH),
            "xl2tpd_config_path": str(XL2TPD_CONFIG_PATH),
            "local_ip": local_ip,
            "remote_pool": remote_pool,
            "client_subnet": str(ip_network(str(client_subnet or "").strip(), strict=False)),
            "restart": restart_result,
        }

    @staticmethod
    def _run_command(command: List[str], check: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, check=check)

    @staticmethod
    def _normalize_username(value: str) -> str:
        username = str(value or "").strip()
        if not username:
            raise ValueError("username is required")
        return username

    @staticmethod
    def generate_ppp_password(length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(max(8, int(length))))

    def _ensure_chap_parent_dir(self) -> None:
        self.chap_secrets_path.parent.mkdir(parents=True, exist_ok=True)

    def _read_chap_secrets_lines(self) -> List[str]:
        if not self.chap_secrets_path.exists():
            return []
        return self.chap_secrets_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    @staticmethod
    def _parse_chap_entry(raw_line: str) -> Optional[Dict[str, str]]:
        line = str(raw_line or "").strip()
        if not line or line.startswith("#"):
            return None
        parts = re.split(r"\s+", line)
        if len(parts) < 3:
            return None
        username = parts[0].strip('"')
        server = parts[1].strip('"')
        password = parts[2].strip('"')
        ip = parts[3].strip('"') if len(parts) >= 4 else "*"
        if not username:
            return None
        return {
            "username": username,
            "server": server or "*",
            "password": password,
            "ip": ip or "*",
        }

    def get_user_secret(self, username: str) -> Optional[str]:
        normalized_username = self._normalize_username(username)
        for raw in self._read_chap_secrets_lines():
            parsed = self._parse_chap_entry(raw)
            if parsed and parsed["username"] == normalized_username:
                return parsed["password"]
        return None

    def upsert_user_secret(self, username: str, password: str) -> Dict[str, Any]:
        normalized_username = self._normalize_username(username)
        normalized_password = str(password or "").strip()
        if not normalized_password:
            raise ValueError("password is required")

        self._ensure_chap_parent_dir()
        lines = self._read_chap_secrets_lines()

        updated = False
        rewritten_lines: List[str] = []
        for raw_line in lines:
            parsed = self._parse_chap_entry(raw_line)
            if parsed and parsed["username"] == normalized_username:
                rewritten_lines.append(f'"{normalized_username}" * "{normalized_password}" *')
                updated = True
            else:
                rewritten_lines.append(raw_line)

        if not updated:
            rewritten_lines.append(f'"{normalized_username}" * "{normalized_password}" *')

        content = "\n".join(rewritten_lines).rstrip() + "\n"
        self.chap_secrets_path.write_text(content, encoding="utf-8")

        return {
            "success": True,
            "username": normalized_username,
            "updated": updated,
            "path": str(self.chap_secrets_path),
        }

    def remove_user_secret(self, username: str) -> Dict[str, Any]:
        normalized_username = self._normalize_username(username)
        if not self.chap_secrets_path.exists():
            return {"success": True, "removed": False, "username": normalized_username}

        lines = self._read_chap_secrets_lines()
        rewritten: List[str] = []
        removed = False
        for raw_line in lines:
            parsed = self._parse_chap_entry(raw_line)
            if parsed and parsed["username"] == normalized_username:
                removed = True
                continue
            rewritten.append(raw_line)

        self.chap_secrets_path.write_text("\n".join(rewritten).rstrip() + "\n", encoding="utf-8")
        return {"success": True, "removed": removed, "username": normalized_username}

    def ensure_user_credentials(self, username: str, password: Optional[str] = None) -> Dict[str, Any]:
        normalized_username = self._normalize_username(username)
        resolved_password = str(password or "").strip() or self.generate_ppp_password()
        result = self.upsert_user_secret(normalized_username, resolved_password)
        result["password"] = resolved_password
        return result

    def _collect_pppd_processes(self) -> List[Dict[str, Any]]:
        result = self._run_command(list(PPP_PS_COMMAND), check=False)
        if result.returncode != 0:
            return []

        processes: List[Dict[str, Any]] = []
        for raw_line in (result.stdout or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = re.match(r"^(\d+)\s+(.*)$", line)
            if not match:
                continue
            pid = int(match.group(1))
            args = match.group(2)
            if "pppd" not in args:
                continue

            protocol = "unknown"
            lowered = args.lower()
            if "pppol2tp" in lowered or "xl2tpd" in lowered or "l2tp" in lowered:
                protocol = "l2tp"

            interface_match = re.search(rf"\b({PPP_INTERFACE_PREFIX}\d+)\b", args)
            interface_name = interface_match.group(1) if interface_match else None

            processes.append(
                {
                    "pid": pid,
                    "args": args,
                    "protocol": protocol,
                    "ppp_interface": interface_name,
                }
            )
        return processes

    def _read_interface_bytes(self, interface_name: str) -> tuple[int, int]:
        result = self._run_command(["ip", "-s", "link", "show", interface_name], check=False)
        if result.returncode != 0:
            return 0, 0

        lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
        for idx, line in enumerate(lines):
            if line.startswith("RX:") and idx + 1 < len(lines):
                rx_fields = lines[idx + 1].split()
                tx_fields = lines[idx + 3].split() if idx + 3 < len(lines) and lines[idx + 2].startswith("TX:") else []
                rx_bytes = int(rx_fields[0]) if rx_fields and rx_fields[0].isdigit() else 0
                tx_bytes = int(tx_fields[0]) if tx_fields and tx_fields[0].isdigit() else 0
                return tx_bytes, rx_bytes
        return 0, 0

    @staticmethod
    def _parse_radattr_file(path: Path) -> Dict[str, str]:
        data: Dict[str, str] = {}
        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" not in raw_line:
                    continue
                key, value = raw_line.split("=", 1)
                data[key.strip()] = value.strip().strip('"')
        except Exception:
            return {}
        return data

    def get_active_sessions(self, protocol: Optional[str] = None) -> List[Dict[str, Any]]:
        protocol_filter = str(protocol or "").strip().lower()
        processes = self._collect_pppd_processes()

        sessions: List[Dict[str, Any]] = []
        seen = set()

        for process in processes:
            iface = process.get("ppp_interface")
            if not iface:
                continue
            radattr_path = Path(PPP_RADATTR_DIR) / f"radattr.{iface}"
            radattr_data = self._parse_radattr_file(radattr_path) if radattr_path.exists() else {}
            username = (
                radattr_data.get("User-Name")
                or radattr_data.get("USER_NAME")
                or radattr_data.get("UserName")
                or ""
            ).strip()

            if not username:
                # fallback: best-effort username detection from args (user <username>)
                args = str(process.get("args") or "")
                match = re.search(r"\buser\s+([^\s]+)", args)
                username = match.group(1).strip('"') if match else ""

            if not username:
                continue

            detected_protocol = str(process.get("protocol") or "unknown").lower()
            if protocol_filter and detected_protocol != protocol_filter:
                continue

            tx_bytes, rx_bytes = self._read_interface_bytes(iface)
            key = (username, iface, detected_protocol)
            if key in seen:
                continue
            seen.add(key)

            sessions.append(
                {
                    "username": username,
                    "protocol": detected_protocol,
                    "pid": int(process.get("pid") or 0),
                    "ppp_interface": iface,
                    "framed_ip": radattr_data.get("Framed-IP-Address") or radattr_data.get("FRAMED_IP_ADDRESS"),
                    "bytes_sent": tx_bytes,
                    "bytes_received": rx_bytes,
                    "source": "pppd",
                }
            )

        return sessions

    def get_traffic_usage(self, username: Optional[str] = None, protocol: Optional[str] = None) -> Dict[str, Any]:
        sessions = self.get_active_sessions(protocol=protocol)
        totals: Dict[str, Dict[str, int]] = {}

        for session in sessions:
            user = str(session.get("username") or "").strip()
            if not user:
                continue
            item = totals.setdefault(user, {"bytes_sent": 0, "bytes_received": 0, "connections": 0})
            item["bytes_sent"] += max(0, int(session.get("bytes_sent") or 0))
            item["bytes_received"] += max(0, int(session.get("bytes_received") or 0))
            item["connections"] += 1

        normalized_username = str(username or "").strip()
        if normalized_username:
            selected = totals.get(normalized_username, {"bytes_sent": 0, "bytes_received": 0, "connections": 0})
            return {
                "success": True,
                "username": normalized_username,
                "protocol": protocol,
                **selected,
            }

        return {
            "success": True,
            "protocol": protocol,
            "users": totals,
        }

    def disconnect_user(self, username: str, protocol: Optional[str] = None) -> Dict[str, Any]:
        normalized_username = self._normalize_username(username)
        protocol_filter = str(protocol or "").strip().lower()
        sessions = self.get_active_sessions(protocol=protocol_filter or None)

        target_pids = {
            int(session.get("pid") or 0)
            for session in sessions
            if str(session.get("username") or "").strip() == normalized_username and int(session.get("pid") or 0) > 0
        }

        if not target_pids:
            # fallback by process args match
            for process in self._collect_pppd_processes():
                args = str(process.get("args") or "")
                proc_protocol = str(process.get("protocol") or "unknown").lower()
                if protocol_filter and proc_protocol != protocol_filter:
                    continue
                if normalized_username in args:
                    pid = int(process.get("pid") or 0)
                    if pid > 0:
                        target_pids.add(pid)

        terminated: List[int] = []
        failed: List[int] = []
        for pid in sorted(target_pids):
            try:
                os.kill(pid, 15)
                terminated.append(pid)
            except Exception:
                failed.append(pid)

        return {
            "success": len(target_pids) == 0 or len(failed) == 0,
            "username": normalized_username,
            "protocol": protocol_filter or None,
            "terminated_pids": terminated,
            "failed_pids": failed,
            "message": "No active PPP session found"
            if not target_pids
            else (
                f"Disconnected {len(terminated)} PPP session(s)"
                if not failed
                else f"Disconnected {len(terminated)} session(s), failed on {len(failed)}"
            ),
        }
