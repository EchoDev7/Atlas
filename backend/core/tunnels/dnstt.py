from __future__ import annotations

import re
import shlex
import socket
import ssl
import subprocess
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import paramiko

from backend.core.tunnels.base import BaseTunnel


@dataclass
class CommandResult:
    success: bool
    command: str
    return_code: int | None
    stdout: str
    stderr: str
    node: str


class DNSTTTunnel(BaseTunnel):
    mode = "dnstt"

    def __init__(self, *, settings: object):
        super().__init__(settings=settings)
        self.repo_dir = "/opt/dnstt"
        self.server_bin = "/usr/local/bin/dnstt-server"
        self.client_bin = "/usr/local/bin/dnstt-client"

    def _is_relay_mode(self) -> bool:
        architecture = str(getattr(self.settings, "tunnel_architecture", "standalone") or "standalone").strip().lower()
        return architecture == "relay"

    def _resolver_candidates(self) -> list[str]:
        resolver_raw = str(getattr(self.settings, "dnstt_dns_resolver", "8.8.8.8") or "8.8.8.8").strip()
        values = [item.strip() for item in resolver_raw.split(",") if item and item.strip()]
        if not values:
            return ["8.8.8.8"]

        unique_values: list[str] = []
        seen = set()
        for value in values:
            normalized_key = value.lower()
            if normalized_key in seen:
                continue
            seen.add(normalized_key)
            unique_values.append(value)
        return unique_values

    def _normalize_doh_endpoint(self, candidate: str) -> str:
        trimmed = candidate.strip()
        if trimmed.startswith(("http://", "https://")):
            return trimmed
        return f"https://{trimmed}/dns-query"

    def _probe_url(self, endpoint: str, timeout_seconds: float = 2.0) -> bool:
        request = Request(endpoint, method="GET", headers={"Accept": "application/dns-message"})
        try:
            with urlopen(request, timeout=timeout_seconds, context=ssl._create_unverified_context()) as response:  # nosec B310
                _ = response.read(1)
            return True
        except HTTPError:
            # An HTTP response still proves endpoint reachability.
            return True
        except (URLError, ValueError, TimeoutError, socket.timeout):
            return False
        except Exception:
            return False

    def _probe_ip(self, ip_address: str, timeout_seconds: float = 2.0) -> bool:
        for port in (53, 443):
            try:
                with socket.create_connection((ip_address, port), timeout=timeout_seconds):
                    return True
            except (socket.timeout, OSError):
                continue
        return False

    def _select_healthy_doh_endpoint(self) -> tuple[str, list[dict]]:
        probe_report: list[dict] = []
        candidates = self._resolver_candidates()

        for candidate in candidates:
            selected_endpoint = self._normalize_doh_endpoint(candidate)
            parsed = urlparse(candidate)
            is_url = parsed.scheme in {"http", "https"} and bool(parsed.netloc)

            if is_url:
                healthy = self._probe_url(candidate)
            else:
                healthy = self._probe_ip(candidate)
                if not healthy:
                    healthy = self._probe_url(selected_endpoint)

            probe_report.append(
                {
                    "candidate": candidate,
                    "selected_doh": selected_endpoint,
                    "healthy": healthy,
                }
            )

            if healthy:
                return selected_endpoint, probe_report

        # Fallback for heavily filtered networks: still use first configured endpoint.
        return self._normalize_doh_endpoint(candidates[0]), probe_report

    def _ssh_target(self) -> tuple[str, int, str, str]:
        host = (getattr(self.settings, "foreign_server_ip", "") or "").strip()
        username = (getattr(self.settings, "foreign_ssh_user", "") or "").strip()
        password = getattr(self.settings, "foreign_ssh_password", "") or ""
        port = int(getattr(self.settings, "foreign_server_port", 22) or 22)
        if not host or not username or not password:
            raise RuntimeError("Relay mode requires foreign server IP, SSH user, and SSH password")
        return host, port, username, password

    def _run_local(self, command: str, timeout: int = 900) -> CommandResult:
        completed = subprocess.run(
            ["bash", "-lc", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        return CommandResult(
            success=completed.returncode == 0,
            command=command,
            return_code=completed.returncode,
            stdout=(completed.stdout or "").strip(),
            stderr=(completed.stderr or "").strip(),
            node="local",
        )

    def _run_remote(self, command: str, timeout: int = 900) -> CommandResult:
        host, port, username, password = self._ssh_target()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=20,
                auth_timeout=20,
                banner_timeout=20,
            )
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdout_text = (stdout.read() or b"").decode("utf-8", errors="replace").strip()
            stderr_text = (stderr.read() or b"").decode("utf-8", errors="replace").strip()
            return_code = int(stdout.channel.recv_exit_status())
            return CommandResult(
                success=return_code == 0,
                command=command,
                return_code=return_code,
                stdout=stdout_text,
                stderr=stderr_text,
                node="foreign",
            )
        finally:
            client.close()

    def _run_on_target(self, command: str, target: str, timeout: int = 900) -> CommandResult:
        if target == "foreign":
            return self._run_remote(command=command, timeout=timeout)
        return self._run_local(command=command, timeout=timeout)

    def _run_steps(self, *, target: str, steps: list[str], timeout: int = 900) -> dict:
        command_results: list[dict] = []
        for command in steps:
            result = self._run_on_target(command=command, target=target, timeout=timeout)
            command_results.append(
                {
                    "node": result.node,
                    "command": result.command,
                    "return_code": result.return_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )
            if not result.success:
                return {
                    "success": False,
                    "node": target,
                    "results": command_results,
                    "error": result.stderr or result.stdout or f"Command failed: {command}",
                }
        return {"success": True, "node": target, "results": command_results}

    def install_dependencies(self) -> dict:
        install_steps = [
            "apt-get update -y",
            "apt-get install -y golang-go git make build-essential",
            f"if [ ! -d {self.repo_dir} ]; then git clone https://github.com/tladesignz/dnstt {self.repo_dir}; else git -C {self.repo_dir} pull --ff-only; fi",
            f"cd {self.repo_dir} && go build -o dnstt-server ./dnstt-server",
            f"cd {self.repo_dir} && go build -o dnstt-client ./dnstt-client",
            f"install -m 0755 {self.repo_dir}/dnstt-server {self.server_bin}",
            f"install -m 0755 {self.repo_dir}/dnstt-client {self.client_bin}",
        ]

        if self._is_relay_mode():
            local_result = self._run_steps(target="local", steps=install_steps)
            if not local_result.get("success"):
                return {"success": False, "message": "Local DNSTT install failed", "local": local_result}
            foreign_result = self._run_steps(target="foreign", steps=install_steps)
            if not foreign_result.get("success"):
                return {"success": False, "message": "Foreign DNSTT install failed", "local": local_result, "foreign": foreign_result}
            return {"success": True, "message": "DNSTT dependencies installed on local and foreign nodes", "local": local_result, "foreign": foreign_result}

        local_result = self._run_steps(target="local", steps=install_steps)
        if not local_result.get("success"):
            return {"success": False, "message": "Local DNSTT install failed", "local": local_result}
        return {"success": True, "message": "DNSTT dependencies installed on local node", "local": local_result}

    def generate_keys(self) -> dict:
        target = "foreign" if self._is_relay_mode() else "local"
        command = f"cd {self.repo_dir} && ./dnstt-server -gen"
        result = self._run_on_target(command=command, target=target, timeout=120)
        if not result.success:
            return {
                "success": False,
                "message": "Failed to generate DNSTT keys",
                "node": target,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        combined = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
        pubkey = ""
        privkey = ""
        for line in combined.splitlines():
            normalized = line.strip()
            lower = normalized.lower()
            if "pub" in lower and ":" in normalized and not pubkey:
                pubkey = normalized.split(":", 1)[1].strip()
            if "priv" in lower and ":" in normalized and not privkey:
                privkey = normalized.split(":", 1)[1].strip()

        if not pubkey or not privkey:
            tokens = re.findall(r"[A-Za-z0-9+/=]{40,}", combined)
            if len(tokens) >= 2:
                pubkey = pubkey or tokens[0]
                privkey = privkey or tokens[1]

        if not pubkey or not privkey:
            return {
                "success": False,
                "message": "DNSTT key generation output could not be parsed",
                "node": target,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        return {
            "success": True,
            "message": "DNSTT keys generated successfully",
            "node": target,
            "dnstt_pubkey": pubkey,
            "dnstt_privkey": privkey,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def setup_server(self) -> dict:
        domain = (getattr(self.settings, "dnstt_domain", "") or "").strip()
        privkey = (getattr(self.settings, "dnstt_privkey", "") or "").strip()
        if not domain or not privkey:
            return {"success": False, "message": "DNSTT domain and private key are required for server setup"}

        domain_q = shlex.quote(domain)
        privkey_q = shlex.quote(privkey)
        service_steps = [
            "cat > /etc/systemd/system/dnstt-server.service <<'EOF'\n[Unit]\nDescription=DNSTT Server\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey {privkey} -domain {domain} 127.0.0.1:5300\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(privkey=privkey_q, domain=domain_q),
            "systemctl daemon-reload",
            "systemctl enable dnstt-server.service",
            "systemctl restart dnstt-server.service",
            "iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 || iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300",
        ]
        target = "foreign" if self._is_relay_mode() else "local"
        result = self._run_steps(target=target, steps=service_steps)
        return {
            "success": result.get("success", False),
            "message": "DNSTT server configured" if result.get("success") else "DNSTT server setup failed",
            "target": target,
            "details": result,
        }

    def setup_client(self) -> dict:
        domain = (getattr(self.settings, "dnstt_domain", "") or "").strip()
        pubkey = (getattr(self.settings, "dnstt_pubkey", "") or "").strip()
        if not domain or not pubkey:
            return {"success": False, "message": "DNSTT domain and public key are required for client setup"}

        domain_q = shlex.quote(domain)
        pubkey_q = shlex.quote(pubkey)
        doh_resolver, resolver_probe_report = self._select_healthy_doh_endpoint()
        doh_resolver_q = shlex.quote(doh_resolver)
        service_steps = [
            "cat > /etc/systemd/system/dnstt-client.service <<'EOF'\n[Unit]\nDescription=DNSTT Client\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/dnstt-client -doh {doh} -udp 127.0.0.1:5301 -pubkey {pubkey} -domain {domain} 127.0.0.1:1080\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(doh=doh_resolver_q, pubkey=pubkey_q, domain=domain_q),
            "systemctl daemon-reload",
            "systemctl enable dnstt-client.service",
            "systemctl restart dnstt-client.service",
        ]
        result = self._run_steps(target="local", steps=service_steps)
        return {
            "success": result.get("success", False),
            "message": "DNSTT client configured" if result.get("success") else "DNSTT client setup failed",
            "target": "local",
            "selected_doh_resolver": doh_resolver,
            "resolver_probe_report": resolver_probe_report,
            "details": result,
        }

    def setup_domestic(self) -> dict:
        return self.setup_client()

    def setup_foreign(self) -> dict:
        return self.setup_server()

    def start(self) -> dict:
        if self._is_relay_mode():
            foreign_result = self._run_steps(target="foreign", steps=["systemctl restart dnstt-server.service"])
            local_result = self._run_steps(target="local", steps=["systemctl restart dnstt-client.service"])
            success = bool(foreign_result.get("success") and local_result.get("success"))
            return {
                "success": success,
                "mode": self.mode,
                "message": "DNSTT services restarted" if success else "Failed to restart DNSTT services",
                "foreign": foreign_result,
                "local": local_result,
            }

        local_result = self._run_steps(target="local", steps=["systemctl restart dnstt-server.service", "systemctl restart dnstt-client.service"])
        return {
            "success": local_result.get("success", False),
            "mode": self.mode,
            "message": "DNSTT services restarted" if local_result.get("success") else "Failed to restart DNSTT services",
            "local": local_result,
        }

    def stop(self) -> dict:
        if self._is_relay_mode():
            foreign_result = self._run_steps(target="foreign", steps=["systemctl stop dnstt-server.service"])
            local_result = self._run_steps(target="local", steps=["systemctl stop dnstt-client.service"])
            success = bool(foreign_result.get("success") and local_result.get("success"))
            return {
                "success": success,
                "mode": self.mode,
                "message": "DNSTT services stopped" if success else "Failed to stop DNSTT services",
                "foreign": foreign_result,
                "local": local_result,
            }

        local_result = self._run_steps(target="local", steps=["systemctl stop dnstt-server.service", "systemctl stop dnstt-client.service"])
        return {
            "success": local_result.get("success", False),
            "mode": self.mode,
            "message": "DNSTT services stopped" if local_result.get("success") else "Failed to stop DNSTT services",
            "local": local_result,
        }
