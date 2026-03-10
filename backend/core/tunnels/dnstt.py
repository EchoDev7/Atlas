from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import shlex
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import paramiko
from sqlalchemy.orm import object_session

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
    KNOWN_STABLE_COMMIT = "eb4f41670ec77126e14199d223a280569b32cb30"

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

    def _resolver_strategy(self) -> str:
        value = str(getattr(self.settings, "dnstt_resolver_strategy", "failover") or "failover").strip().lower()
        if value in {"failover", "least-latency", "round-robin"}:
            return value
        return "failover"

    def _domain_candidates(self) -> list[str]:
        domains_raw = str(getattr(self.settings, "dnstt_domain", "") or "").strip()
        values = [item.strip() for item in domains_raw.split(",") if item and item.strip()]
        unique_values: list[str] = []
        seen = set()
        for value in values:
            normalized_key = value.lower().rstrip(".")
            if normalized_key in seen:
                continue
            seen.add(normalized_key)
            unique_values.append(value.rstrip("."))
        return unique_values

    def _active_domain(self) -> str:
        candidates = self._domain_candidates()
        active_domain = str(getattr(self.settings, "dnstt_active_domain", "") or "").strip().rstrip(".")
        if not candidates:
            return active_domain
        if active_domain:
            for candidate in candidates:
                if candidate.lower() == active_domain.lower():
                    return candidate
        return candidates[0]

    def _normalize_doh_endpoint(self, candidate: str) -> str:
        trimmed = candidate.strip()
        if trimmed.startswith(("http://", "https://")):
            return trimmed
        return f"https://{trimmed}/dns-query"

    def _probe_url(self, endpoint: str, timeout_seconds: float = 2.0) -> tuple[bool, float | None, str | None]:
        request = Request(endpoint, method="GET", headers={"Accept": "application/dns-message"})
        started_at = time.perf_counter()
        try:
            with urlopen(request, timeout=timeout_seconds, context=ssl._create_unverified_context()) as response:  # nosec B310
                _ = response.read(1)
            latency_ms = (time.perf_counter() - started_at) * 1000.0
            return True, latency_ms, None
        except HTTPError:
            # An HTTP response still proves endpoint reachability.
            latency_ms = (time.perf_counter() - started_at) * 1000.0
            return True, latency_ms, None
        except (URLError, ValueError, TimeoutError, socket.timeout):
            return False, None, "url_probe_failed"
        except Exception as exc:
            return False, None, str(exc)

    def _probe_ip(self, ip_address: str, timeout_seconds: float = 2.0) -> tuple[bool, float | None, str | None]:
        best_latency_ms: float | None = None
        last_error: str | None = None
        for port in (53, 443):
            started_at = time.perf_counter()
            try:
                with socket.create_connection((ip_address, port), timeout=timeout_seconds):
                    latency_ms = (time.perf_counter() - started_at) * 1000.0
                    if best_latency_ms is None or latency_ms < best_latency_ms:
                        best_latency_ms = latency_ms
            except (socket.timeout, OSError) as exc:
                last_error = str(exc) or "ip_probe_failed"
                continue
        if best_latency_ms is not None:
            return True, best_latency_ms, None
        return False, None, last_error or "ip_probe_failed"

    def _probe_resolver_candidates(self) -> tuple[list[dict], list[dict]]:
        probe_results: list[dict] = []
        ranked_healthy: list[dict] = []

        for candidate in self._resolver_candidates():
            selected_endpoint = self._normalize_doh_endpoint(candidate)
            parsed = urlparse(candidate)
            is_url = parsed.scheme in {"http", "https"} and bool(parsed.netloc)

            healthy = False
            latency_ms: float | None = None
            error: str | None = None

            if is_url:
                healthy, latency_ms, error = self._probe_url(candidate)
            else:
                healthy, latency_ms, error = self._probe_ip(candidate)
                if not healthy:
                    healthy, latency_ms, error = self._probe_url(selected_endpoint)

            probe_result = {
                "resolver": candidate,
                "selected_doh": selected_endpoint,
                "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
                "status": "healthy" if healthy else "failed",
                "error": error,
            }
            probe_results.append(probe_result)

            if healthy and latency_ms is not None:
                ranked_healthy.append(probe_result)

        ranked_healthy.sort(key=lambda item: item["latency_ms"])
        return probe_results, ranked_healthy

    def _select_healthy_doh_endpoint(self) -> tuple[str, dict]:
        probe_results, ranked_healthy = self._probe_resolver_candidates()
        fallback_candidates = self._resolver_candidates()
        selected_doh = ranked_healthy[0]["selected_doh"] if ranked_healthy else self._normalize_doh_endpoint(fallback_candidates[0])

        telemetry = {
            "selected_resolver": selected_doh,
            "last_update_timestamp": datetime.now(timezone.utc).isoformat(),
            "probe_results": probe_results,
        }
        return selected_doh, telemetry

    def _select_all_healthy_doh_endpoints(self) -> tuple[list[dict], dict]:
        probe_results, ranked_healthy = self._probe_resolver_candidates()
        fallback_candidates = self._resolver_candidates()
        selected_doh = ranked_healthy[0]["selected_doh"] if ranked_healthy else self._normalize_doh_endpoint(fallback_candidates[0])
        telemetry = {
            "selected_resolver": selected_doh,
            "last_update_timestamp": datetime.now(timezone.utc).isoformat(),
            "probe_results": probe_results,
            "healthy_resolvers": [item["selected_doh"] for item in ranked_healthy],
        }
        return ranked_healthy, telemetry

    def _persist_telemetry(self, telemetry: dict) -> None:
        if not hasattr(self.settings, "dnstt_telemetry"):
            return

        self.settings.dnstt_telemetry = telemetry
        session = object_session(self.settings)
        if session is None:
            return

        self.settings.updated_at = datetime.utcnow()
        session.add(self.settings)
        session.commit()
        session.refresh(self.settings)

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

    def _run_remote_with_client(self, command: str, ssh_client: paramiko.SSHClient, timeout: int = 900) -> CommandResult:
        _, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
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

    def _ensure_port_53_free(self, ssh_client: paramiko.SSHClient | None = None) -> dict:
        target = "foreign" if self._is_relay_mode() else "local"
        check_command = (
            "if ss -H -ulpn 2>/dev/null | awk '{print $5}' | grep -Eq '(^|.*:)53$'; then "
            "if ss -H -ulpn 2>/dev/null | grep -qi 'systemd-resolved' || "
            "lsof -nP -iUDP:53 2>/dev/null | grep -qi 'systemd-resolved'; then "
            "echo occupied_by_systemd_resolved; "
            "else echo occupied_by_other_process; fi; "
            "else echo free; fi"
        )

        if target == "foreign" and ssh_client is not None:
            check_result = self._run_remote_with_client(command=check_command, ssh_client=ssh_client, timeout=60)
        else:
            check_result = self._run_on_target(command=check_command, target=target, timeout=60)

        if not check_result.success:
            return {
                "success": False,
                "message": "Failed to inspect UDP port 53 state",
                "target": target,
                "details": {
                    "node": check_result.node,
                    "command": check_result.command,
                    "return_code": check_result.return_code,
                    "stdout": check_result.stdout,
                    "stderr": check_result.stderr,
                },
            }

        check_status = (check_result.stdout or "").strip().lower()
        if check_status == "free":
            return {
                "success": True,
                "message": "UDP port 53 is already free",
                "target": target,
                "details": {"check_status": check_status},
            }

        if check_status == "occupied_by_other_process":
            return {
                "success": False,
                "message": "UDP port 53 is occupied by a non-systemd-resolved process",
                "target": target,
                "details": {"check_status": check_status},
            }

        if check_status != "occupied_by_systemd_resolved":
            return {
                "success": False,
                "message": "Unable to determine UDP port 53 ownership safely",
                "target": target,
                "details": {"check_status": check_status},
            }

        safe_fix_steps = [
            "if grep -Eq '^[#[:space:]]*DNSStubListener=' /etc/systemd/resolved.conf; then "
            "sed -i -E \"s|^[#[:space:]]*DNSStubListener=.*|DNSStubListener=no|\" /etc/systemd/resolved.conf; "
            "else printf '\nDNSStubListener=no\n' >> /etc/systemd/resolved.conf; fi",
            "systemctl restart systemd-resolved",
            "rm -f /etc/resolv.conf && ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf",
        ]

        if target == "foreign" and ssh_client is not None:
            command_results: list[dict] = []
            for command in safe_fix_steps:
                step_result = self._run_remote_with_client(command=command, ssh_client=ssh_client, timeout=120)
                command_results.append(
                    {
                        "node": step_result.node,
                        "command": step_result.command,
                        "return_code": step_result.return_code,
                        "stdout": step_result.stdout,
                        "stderr": step_result.stderr,
                    }
                )
                if not step_result.success:
                    return {
                        "success": False,
                        "message": "Port 53 safe-fix failed",
                        "target": target,
                        "details": {
                            "check_status": check_status,
                            "results": command_results,
                        },
                    }
            return {
                "success": True,
                "message": "Port 53 was occupied by systemd-resolved and has been safely freed",
                "target": target,
                "details": {
                    "check_status": check_status,
                    "results": command_results,
                },
            }

        safe_fix_result = self._run_steps(target=target, steps=safe_fix_steps, timeout=120)
        return {
            "success": bool(safe_fix_result.get("success")),
            "message": "Port 53 was occupied by systemd-resolved and has been safely freed"
            if safe_fix_result.get("success")
            else "Port 53 safe-fix failed",
            "target": target,
            "details": {
                "check_status": check_status,
                "safe_fix": safe_fix_result,
            },
        }

    def install_dependencies(self) -> dict:
        install_steps = [
            "apt-get update -y",
            "apt-get install -y golang-go git make build-essential",
            f"if [ ! -d {self.repo_dir}/.git ]; then git clone https://www.bamsoftware.com/git/dnstt.git {self.repo_dir}; else git -C {self.repo_dir} remote set-url origin https://www.bamsoftware.com/git/dnstt.git && git -C {self.repo_dir} fetch --all --tags --force; fi",
            f"git -C {self.repo_dir} checkout {self.KNOWN_STABLE_COMMIT}",
            f"echo '[dnstt] source integrity verified via commit pinning: {self.KNOWN_STABLE_COMMIT}'",
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
        domain = self._active_domain()
        privkey = (getattr(self.settings, "dnstt_privkey", "") or "").strip()
        if not domain or not privkey:
            return {"success": False, "message": "DNSTT active domain and private key are required for server setup"}

        port_53_result = self._ensure_port_53_free()
        if not port_53_result.get("success"):
            return {
                "success": False,
                "message": "DNSTT server setup failed while preparing UDP port 53",
                "target": port_53_result.get("target"),
                "port_53": port_53_result,
            }

        domain_q = shlex.quote(domain)
        privkey_q = shlex.quote(privkey)
        service_steps = [
            "cat > /etc/systemd/system/dnstt-server.service <<'EOF'\n[Unit]\nDescription=DNSTT Server\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey {privkey} -domain {domain} 127.0.0.1:5300\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(privkey=privkey_q, domain=domain_q),
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
            "active_domain": domain,
            "port_53": port_53_result,
            "details": result,
        }

    def setup_client(self) -> dict:
        domain = self._active_domain()
        pubkey = (getattr(self.settings, "dnstt_pubkey", "") or "").strip()
        if not domain or not pubkey:
            return {"success": False, "message": "DNSTT active domain and public key are required for client setup"}

        strategy = self._resolver_strategy()
        if strategy == "round-robin":
            return self._setup_client_round_robin(domain=domain, pubkey=pubkey)
        if strategy == "least-latency":
            return self._setup_client_least_latency(domain=domain, pubkey=pubkey)
        return self._setup_client_failover(domain=domain, pubkey=pubkey)

    def _setup_client_failover(self, *, domain: str, pubkey: str) -> dict:
        domain_q = shlex.quote(domain)
        pubkey_q = shlex.quote(pubkey)
        doh_resolver, resolver_telemetry = self._select_healthy_doh_endpoint()
        resolver_telemetry["strategy"] = "failover"
        self._persist_telemetry(resolver_telemetry)
        doh_resolver_q = shlex.quote(doh_resolver)
        service_steps = [
            "for unit in /etc/systemd/system/dnstt-client-*.service; do [ -e \"$unit\" ] || continue; name=$(basename \"$unit\"); systemctl disable --now \"$name\" >/dev/null 2>&1 || true; rm -f \"$unit\"; done",
            "systemctl disable --now dnstt-optimizer.service >/dev/null 2>&1 || true",
            "rm -f /etc/systemd/system/dnstt-optimizer.service /usr/local/bin/dnstt-optimizer.py /var/lib/dnstt/current_resolver",
            "iptables -t nat -D OUTPUT -p udp --dport 5301 -j DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -F DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -X DNSTT_RR >/dev/null 2>&1 || true",
            "cat > /etc/systemd/system/dnstt-client.service <<'EOF'\n[Unit]\nDescription=DNSTT Client\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/dnstt-client -doh {doh} -udp 127.0.0.1:5301 -pubkey {pubkey} -domain {domain} 127.0.0.1:1080\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(doh=doh_resolver_q, pubkey=pubkey_q, domain=domain_q),
            "systemctl daemon-reload",
            "systemctl enable dnstt-client.service",
            "systemctl restart dnstt-client.service",
        ]
        result = self._run_steps(target="local", steps=service_steps)
        return {
            "success": result.get("success", False),
            "message": "DNSTT client configured" if result.get("success") else "DNSTT client setup failed",
            "target": "local",
            "strategy": "failover",
            "active_domain": domain,
            "selected_doh_resolver": doh_resolver,
            "resolver_probe_report": resolver_telemetry.get("probe_results", []),
            "dnstt_telemetry": resolver_telemetry,
            "details": result,
        }

    def _setup_client_round_robin(self, *, domain: str, pubkey: str) -> dict:
        domain_q = shlex.quote(domain)
        pubkey_q = shlex.quote(pubkey)
        healthy_resolvers, resolver_telemetry = self._select_all_healthy_doh_endpoints()
        if not healthy_resolvers:
            return {
                "success": False,
                "message": "DNSTT round-robin requires at least one healthy resolver",
                "target": "local",
                "strategy": "round-robin",
                "resolver_probe_report": resolver_telemetry.get("probe_results", []),
            }

        resolver_telemetry["strategy"] = "round-robin"
        self._persist_telemetry(resolver_telemetry)

        service_steps = [
            "systemctl disable --now dnstt-client.service >/dev/null 2>&1 || true",
            "systemctl disable --now dnstt-optimizer.service >/dev/null 2>&1 || true",
            "rm -f /etc/systemd/system/dnstt-optimizer.service /usr/local/bin/dnstt-optimizer.py /var/lib/dnstt/current_resolver",
            "for unit in /etc/systemd/system/dnstt-client-*.service; do [ -e \"$unit\" ] || continue; name=$(basename \"$unit\"); systemctl disable --now \"$name\" >/dev/null 2>&1 || true; rm -f \"$unit\"; done",
            "iptables -t nat -D OUTPUT -p udp --dport 5301 -j DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -F DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -X DNSTT_RR >/dev/null 2>&1 || true",
            "systemctl daemon-reload",
        ]

        instance_ports: list[int] = []
        for idx, resolver in enumerate(healthy_resolvers, start=1):
            local_udp_port = 9000 + idx
            instance_ports.append(local_udp_port)
            service_name = f"dnstt-client-{idx}.service"
            service_name_q = shlex.quote(service_name)
            doh_resolver_q = shlex.quote(resolver["selected_doh"])
            service_steps.append(
                "cat > /etc/systemd/system/{service_name} <<'EOF'\n[Unit]\nDescription=DNSTT Client Instance {idx}\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/dnstt-client -doh {doh} -udp 127.0.0.1:{port} -pubkey {pubkey} -domain {domain} 127.0.0.1:1080\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(
                    service_name=service_name,
                    idx=idx,
                    doh=doh_resolver_q,
                    port=local_udp_port,
                    pubkey=pubkey_q,
                    domain=domain_q,
                )
            )
            service_steps.append(f"systemctl enable {service_name_q}")
            service_steps.append(f"systemctl restart {service_name_q}")

        service_steps.append("iptables -t nat -N DNSTT_RR")
        strategy_len = len(instance_ports)
        for idx, local_udp_port in enumerate(instance_ports):
            service_steps.append(
                "iptables -t nat -A DNSTT_RR -p udp -m statistic --mode nth --every {every} --packet {packet} -j REDIRECT --to-ports {port}".format(
                    every=strategy_len,
                    packet=idx,
                    port=local_udp_port,
                )
            )
        service_steps.append(
            "iptables -t nat -A DNSTT_RR -p udp -j REDIRECT --to-ports {port}".format(port=instance_ports[0])
        )
        service_steps.append("iptables -t nat -A OUTPUT -p udp --dport 5301 -j DNSTT_RR")

        result = self._run_steps(target="local", steps=service_steps)
        return {
            "success": result.get("success", False),
            "message": "DNSTT round-robin client configured" if result.get("success") else "DNSTT round-robin setup failed",
            "target": "local",
            "strategy": "round-robin",
            "active_domain": domain,
            "selected_doh_resolver": healthy_resolvers[0]["selected_doh"],
            "healthy_resolvers": [item["selected_doh"] for item in healthy_resolvers],
            "local_udp_ports": instance_ports,
            "resolver_probe_report": resolver_telemetry.get("probe_results", []),
            "dnstt_telemetry": resolver_telemetry,
            "details": result,
        }

    def _setup_client_least_latency(self, *, domain: str, pubkey: str) -> dict:
        domain_q = shlex.quote(domain)
        pubkey_q = shlex.quote(pubkey)
        doh_resolver, resolver_telemetry = self._select_healthy_doh_endpoint()
        resolver_telemetry["strategy"] = "least-latency"
        self._persist_telemetry(resolver_telemetry)
        doh_resolver_q = shlex.quote(doh_resolver)
        optimizer_payload = {
            "domain": domain,
            "pubkey": pubkey,
            "resolvers": self._resolver_candidates(),
            "initial_doh": doh_resolver,
        }
        optimizer_script = """#!/usr/bin/env python3
import json
import shlex
import socket
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

CONFIG = json.loads(__ATLAS_OPTIMIZER_PAYLOAD__)
STATE_FILE = Path('/var/lib/dnstt/current_resolver')
SERVICE_PATH = Path('/etc/systemd/system/dnstt-client.service')
THRESHOLD = 0.8
INTERVAL_SECONDS = 180


def normalize_doh(candidate: str) -> str:
    candidate = (candidate or '').strip()
    if candidate.startswith(('http://', 'https://')):
        return candidate
    return f'https://{candidate}/dns-query'


def probe_url(endpoint: str, timeout_seconds: float = 2.0):
    request = Request(endpoint, method='GET', headers={'Accept': 'application/dns-message'})
    started_at = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
            _ = response.read(1)
        return True, (time.perf_counter() - started_at) * 1000.0
    except HTTPError:
        return True, (time.perf_counter() - started_at) * 1000.0
    except Exception:
        return False, None


def probe_ip(ip_address: str, timeout_seconds: float = 2.0):
    best_latency = None
    for port in (53, 443):
        started_at = time.perf_counter()
        try:
            with socket.create_connection((ip_address, port), timeout=timeout_seconds):
                latency = (time.perf_counter() - started_at) * 1000.0
            if best_latency is None or latency < best_latency:
                best_latency = latency
        except Exception:
            continue
    if best_latency is None:
        return False, None
    return True, best_latency


def probe_candidate(candidate: str):
    candidate = (candidate or '').strip()
    if not candidate:
        return False, None, None

    selected_doh = normalize_doh(candidate)
    parsed = urlparse(candidate)
    is_url = parsed.scheme in {'http', 'https'} and bool(parsed.netloc)
    if is_url:
        healthy, latency = probe_url(candidate)
    else:
        healthy, latency = probe_ip(candidate)
        if not healthy:
            healthy, latency = probe_url(selected_doh)
    return healthy, latency, selected_doh


def best_resolver():
    ranked = []
    for resolver in CONFIG.get('resolvers', []):
        healthy, latency, selected_doh = probe_candidate(resolver)
        if healthy and latency is not None and selected_doh:
            ranked.append((latency, selected_doh))
    ranked.sort(key=lambda item: item[0])
    return ranked[0] if ranked else (None, None)


def render_service(selected_doh: str) -> str:
    cmd = '/usr/local/bin/dnstt-client -doh {doh} -udp 127.0.0.1:5301 -pubkey {pubkey} -domain {domain} 127.0.0.1:1080'.format(
        doh=shlex.quote(selected_doh),
        pubkey=shlex.quote(CONFIG.get('pubkey', '')),
        domain=shlex.quote(CONFIG.get('domain', '')),
    )
    return '\n'.join([
        '[Unit]',
        'Description=DNSTT Client',
        'After=network.target',
        '',
        '[Service]',
        'Type=simple',
        f'ExecStart={cmd}',
        'Restart=always',
        'RestartSec=3',
        'NoNewPrivileges=true',
        'ProtectSystem=strict',
        'ProtectHome=true',
        'PrivateTmp=true',
        '',
        '[Install]',
        'WantedBy=multi-user.target',
        '',
    ])


def apply_new_resolver(selected_doh: str):
    SERVICE_PATH.write_text(render_service(selected_doh), encoding='utf-8')
    subprocess.run(['systemctl', 'daemon-reload'], check=False)
    subprocess.run(['systemctl', 'restart', 'dnstt-client.service'], check=False)
    STATE_FILE.write_text(selected_doh, encoding='utf-8')


def run():
    fallback = CONFIG.get('initial_doh') or normalize_doh((CONFIG.get('resolvers') or ['8.8.8.8'])[0])
    current = fallback
    if STATE_FILE.exists():
        persisted = STATE_FILE.read_text(encoding='utf-8', errors='ignore').strip()
        if persisted:
            current = persisted
    else:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(current, encoding='utf-8')

    while True:
        try:
            best_latency, best = best_resolver()
            current_ok, current_latency, _ = probe_candidate(current)
            if best and best != current:
                if (not current_ok) or current_latency is None or (best_latency is not None and best_latency <= current_latency * THRESHOLD):
                    apply_new_resolver(best)
                    current = best
        except Exception:
            pass
        time.sleep(INTERVAL_SECONDS)


if __name__ == '__main__':
    run()
"""
        optimizer_script = optimizer_script.replace("__ATLAS_OPTIMIZER_PAYLOAD__", repr(json.dumps(optimizer_payload)))
        service_steps = [
            "for unit in /etc/systemd/system/dnstt-client-*.service; do [ -e \"$unit\" ] || continue; name=$(basename \"$unit\"); systemctl disable --now \"$name\" >/dev/null 2>&1 || true; rm -f \"$unit\"; done",
            "iptables -t nat -D OUTPUT -p udp --dport 5301 -j DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -F DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -X DNSTT_RR >/dev/null 2>&1 || true",
            "cat > /etc/systemd/system/dnstt-client.service <<'EOF'\n[Unit]\nDescription=DNSTT Client\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/dnstt-client -doh {doh} -udp 127.0.0.1:5301 -pubkey {pubkey} -domain {domain} 127.0.0.1:1080\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(doh=doh_resolver_q, pubkey=pubkey_q, domain=domain_q),
            "mkdir -p /var/lib/dnstt",
            "cat > /usr/local/bin/dnstt-optimizer.py <<'PY'\n{script}\nPY".format(script=optimizer_script),
            "chmod 0755 /usr/local/bin/dnstt-optimizer.py",
            "cat > /etc/systemd/system/dnstt-optimizer.service <<'EOF'\n[Unit]\nDescription=DNSTT Least-Latency Optimizer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /usr/local/bin/dnstt-optimizer.py\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\nEOF",
            "echo {selected} > /var/lib/dnstt/current_resolver".format(selected=doh_resolver_q),
            "systemctl daemon-reload",
            "systemctl enable dnstt-client.service",
            "systemctl restart dnstt-client.service",
            "systemctl enable dnstt-optimizer.service",
            "systemctl restart dnstt-optimizer.service",
        ]
        result = self._run_steps(target="local", steps=service_steps)
        return {
            "success": result.get("success", False),
            "message": "DNSTT least-latency client configured" if result.get("success") else "DNSTT least-latency setup failed",
            "target": "local",
            "strategy": "least-latency",
            "active_domain": domain,
            "selected_doh_resolver": doh_resolver,
            "optimizer_service": "dnstt-optimizer.service",
            "optimizer_interval_seconds": 180,
            "optimizer_switch_threshold": "20% faster",
            "resolver_probe_report": resolver_telemetry.get("probe_results", []),
            "dnstt_telemetry": resolver_telemetry,
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
