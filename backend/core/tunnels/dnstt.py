from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
from pathlib import Path
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
    MIN_MTU = 50
    MAX_MTU = 1400

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

    def _duplication_mode(self) -> int:
        raw_value = getattr(self.settings, "dnstt_duplication_mode", 1)
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return 1
        return value if value in {1, 2, 3} else 1

    def _multiplexer_script_source_path(self) -> str:
        return str((Path(__file__).resolve().parent / "scripts" / "dnstt_multiplexer.py"))

    def _safe_int(self, raw_value: object, default: int, *, minimum: int, maximum: int) -> int:
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, value))

    def _mtu_mode(self) -> str:
        mode = str(getattr(self.settings, "dnstt_mtu_mode", "preset") or "preset").strip().lower()
        return mode if mode in {"preset", "adaptive"} else "preset"

    def _adaptive_per_resolver_enabled(self) -> bool:
        return bool(getattr(self.settings, "dnstt_adaptive_per_resolver", True))

    def _mtu_payload_bounds(self) -> tuple[int, int]:
        payload_min = self._safe_int(getattr(self.settings, "dnstt_mtu_upload_min", 472), 472, minimum=self.MIN_MTU, maximum=self.MAX_MTU)
        payload_max = self._safe_int(getattr(self.settings, "dnstt_mtu_upload_max", 1204), 1204, minimum=self.MIN_MTU, maximum=self.MAX_MTU)
        if payload_min > payload_max:
            payload_min, payload_max = payload_max, payload_min
        return payload_min, payload_max

    def _transport_retry_count(self) -> int:
        return self._safe_int(getattr(self.settings, "dnstt_transport_retry_count", 2), 2, minimum=0, maximum=10)

    def _transport_probe_timeout_seconds(self) -> float:
        timeout_ms = self._safe_int(
            getattr(self.settings, "dnstt_transport_probe_timeout_ms", 2000),
            2000,
            minimum=500,
            maximum=15000,
        )
        return timeout_ms / 1000.0

    def _transport_probe_workers(self) -> int:
        return self._safe_int(getattr(self.settings, "dnstt_transport_probe_workers", 2), 2, minimum=1, maximum=8)

    def _transport_switch_threshold_ratio(self) -> float:
        percent = self._safe_int(
            getattr(self.settings, "dnstt_transport_switch_threshold_percent", 20),
            20,
            minimum=5,
            maximum=80,
        )
        return (100 - percent) / 100.0

    def _mtu_candidates(self) -> list[int]:
        payload_min, payload_max = self._mtu_payload_bounds()
        mtu_min = max(self.MIN_MTU, min(self.MAX_MTU, payload_min))
        mtu_max = max(self.MIN_MTU, min(self.MAX_MTU, payload_max))
        if mtu_min > mtu_max:
            mtu_min, mtu_max = mtu_max, mtu_min

        baseline = [1400, 1320, 1232, 1200, 1100, 1000, 900, 800, 700, 600, 500, 450, 400, 350, 300, 250, 200, 150, 100, 75, 50]
        chosen: list[int] = []
        for candidate in baseline:
            if mtu_min <= candidate <= mtu_max:
                chosen.append(candidate)

        if not chosen:
            fallback = self._safe_int(self._mtu_value(), 1232, minimum=self.MIN_MTU, maximum=self.MAX_MTU)
            chosen = [fallback]

        chosen.append(self._safe_int(self._mtu_value(), 1232, minimum=self.MIN_MTU, maximum=self.MAX_MTU))
        unique_desc = sorted(set(chosen), reverse=True)
        return unique_desc

    def _probe_target_from_resolver(self, resolver_string: str) -> str:
        candidates = [item.strip() for item in str(resolver_string or "").split(",") if item and item.strip()]
        for candidate in candidates:
            parsed = urlparse(candidate)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                host = (parsed.hostname or "").strip()
                if host:
                    return host
                continue

            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                host_candidate = candidate.split("/", 1)[0].split(":", 1)[0].strip()
                if host_candidate:
                    return host_candidate
        return ""

    def _probe_mtu_for_target(self, probe_target: str, mtu_candidates: list[int]) -> int:
        if not probe_target:
            return self.MIN_MTU

        for mtu_value in mtu_candidates:
            payload_size = max(0, mtu_value)
            for _ in range(self._transport_retry_count() + 1):
                try:
                    completed = subprocess.run(
                        ["ping", "-c", "1", "-M", "do", "-s", str(payload_size), "-W", "2", probe_target],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=self._transport_probe_timeout_seconds() + 2.0,
                    )
                    if completed.returncode == 0:
                        return mtu_value
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    continue

        return self.MIN_MTU

    def _mtu_value(self) -> int:
        raw_value = getattr(self.settings, "dnstt_mtu", 1232)
        return self._safe_int(raw_value, 1232, minimum=self.MIN_MTU, maximum=self.MAX_MTU)

    def probe_optimal_mtu(self, resolver_list_string: str) -> int:
        probe_target = self._probe_target_from_resolver(resolver_list_string)
        mtu_candidates = self._mtu_candidates()
        return self._probe_mtu_for_target(probe_target, mtu_candidates)

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

    def _probe_url(self, endpoint: str, timeout_seconds: float | None = None) -> tuple[bool, float | None, str | None]:
        timeout_seconds = timeout_seconds or self._transport_probe_timeout_seconds()
        request = Request(endpoint, method="GET", headers={"Accept": "application/dns-message"})
        last_error = "url_probe_failed"
        for _ in range(self._transport_retry_count() + 1):
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
                last_error = "url_probe_failed"
                continue
            except Exception as exc:
                last_error = str(exc)
                continue
        return False, None, last_error

    def _probe_ip(self, ip_address: str, timeout_seconds: float | None = None) -> tuple[bool, float | None, str | None]:
        timeout_seconds = timeout_seconds or self._transport_probe_timeout_seconds()
        best_latency_ms: float | None = None
        last_error: str | None = None
        for _ in range(self._transport_retry_count() + 1):
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

    def _probe_resolver_candidate(self, candidate: str) -> dict:
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

        recommended_mtu = self._mtu_value()
        if healthy and self._mtu_mode() == "adaptive":
            probe_target = self._probe_target_from_resolver(candidate)
            recommended_mtu = self._probe_mtu_for_target(probe_target, self._mtu_candidates())

        return {
            "resolver": candidate,
            "selected_doh": selected_endpoint,
            "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
            "status": "healthy" if healthy else "failed",
            "error": error,
            "recommended_mtu": int(recommended_mtu),
        }

    def _probe_resolver_candidates(self) -> tuple[list[dict], list[dict]]:
        probe_results: list[dict] = []
        candidates = self._resolver_candidates()
        workers = min(self._transport_probe_workers(), max(1, len(candidates)))

        if workers <= 1:
            probe_results = [self._probe_resolver_candidate(candidate) for candidate in candidates]
        else:
            future_map = {}
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for index, candidate in enumerate(candidates):
                    future_map[executor.submit(self._probe_resolver_candidate, candidate)] = index
                ordered_results: list[dict | None] = [None] * len(candidates)
                for future in as_completed(future_map):
                    index = future_map[future]
                    try:
                        ordered_results[index] = future.result()
                    except Exception as exc:
                        selected = self._normalize_doh_endpoint(candidates[index])
                        ordered_results[index] = {
                            "resolver": candidates[index],
                            "selected_doh": selected,
                            "latency_ms": None,
                            "status": "failed",
                            "error": str(exc),
                            "recommended_mtu": int(self._mtu_value()),
                        }
                probe_results = [item for item in ordered_results if item is not None]

        ranked_healthy: list[dict] = [
            result for result in probe_results if result.get("status") == "healthy" and result.get("latency_ms") is not None
        ]

        ranked_healthy.sort(key=lambda item: item["latency_ms"])
        return probe_results, ranked_healthy

    def _selected_mtu_for_resolver(self, resolver_info: dict | None) -> int:
        if self._mtu_mode() != "adaptive":
            return self._mtu_value()
        if not self._adaptive_per_resolver_enabled():
            return self._mtu_value()
        if resolver_info is None:
            return self._mtu_value()
        return self._safe_int(resolver_info.get("recommended_mtu"), self._mtu_value(), minimum=self.MIN_MTU, maximum=self.MAX_MTU)

    def _client_reset_steps(self, *, remove_multiplexer_script: bool) -> list[str]:
        remove_parts = [
            "/etc/systemd/system/dnstt-optimizer.service",
            "/etc/systemd/system/dnstt-multiplexer.service",
            "/usr/local/bin/dnstt-optimizer.py",
            "/var/lib/dnstt/current_resolver",
        ]
        if remove_multiplexer_script:
            remove_parts.append("/usr/local/bin/dnstt_multiplexer.py")

        return [
            "systemctl disable --now dnstt-client.service >/dev/null 2>&1 || true",
            "systemctl disable --now dnstt-optimizer.service >/dev/null 2>&1 || true",
            "systemctl disable --now dnstt-multiplexer.service >/dev/null 2>&1 || true",
            f"rm -f {' '.join(remove_parts)}",
            "for unit in /etc/systemd/system/dnstt-client-*.service; do [ -e \"$unit\" ] || continue; name=$(basename \"$unit\"); systemctl disable --now \"$name\" >/dev/null 2>&1 || true; rm -f \"$unit\"; done",
            "iptables -t nat -D OUTPUT -p udp --dport 5301 -j DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -F DNSTT_RR >/dev/null 2>&1 || true",
            "iptables -t nat -X DNSTT_RR >/dev/null 2>&1 || true",
        ]

    def _client_service_unit_step(
        self,
        *,
        service_name: str,
        service_description: str,
        doh_q: str,
        pubkey_q: str,
        domain_q: str,
        mtu_q: str,
        local_udp_port: int,
    ) -> str:
        return (
            "cat > /etc/systemd/system/{service_name} <<'EOF'\n"
            "[Unit]\n"
            "Description={service_description}\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/usr/local/bin/dnstt-client -doh {doh} -udp 127.0.0.1:{port} -pubkey {pubkey} -domain {domain} -mtu {mtu} 127.0.0.1:1080\n"
            "Restart=always\n"
            "RestartSec=3\n"
            "NoNewPrivileges=true\n"
            "ProtectSystem=strict\n"
            "ProtectHome=true\n"
            "PrivateTmp=true\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
            "EOF"
        ).format(
            service_name=service_name,
            service_description=service_description,
            doh=doh_q,
            port=local_udp_port,
            pubkey=pubkey_q,
            domain=domain_q,
            mtu=mtu_q,
        )

    def _resolver_info_by_selected_doh(self, telemetry: dict, selected_doh: str) -> dict | None:
        selected = str(selected_doh or "").strip()
        if not selected:
            return None
        for probe in telemetry.get("probe_results", []) or []:
            if str(probe.get("selected_doh") or "").strip() == selected:
                return probe
        return None

    def _build_telemetry_analytics(self, history: list[dict]) -> dict:
        resolver_stats: dict[str, dict] = {}
        latency_values: list[float] = []
        histogram = {"lt_50": 0, "50_100": 0, "100_200": 0, "gte_200": 0}

        for snapshot in history:
            for probe in snapshot.get("probe_results", []) or []:
                resolver = str(probe.get("selected_doh") or probe.get("resolver") or "").strip()
                if not resolver:
                    continue
                if resolver not in resolver_stats:
                    resolver_stats[resolver] = {
                        "resolver": resolver,
                        "total_samples": 0,
                        "healthy_samples": 0,
                        "latency_samples": [],
                    }
                stat = resolver_stats[resolver]
                stat["total_samples"] += 1
                if probe.get("status") == "healthy":
                    stat["healthy_samples"] += 1

                latency = probe.get("latency_ms")
                if isinstance(latency, (int, float)):
                    latency_float = float(latency)
                    stat["latency_samples"].append(latency_float)
                    latency_values.append(latency_float)
                    if latency_float < 50:
                        histogram["lt_50"] += 1
                    elif latency_float < 100:
                        histogram["50_100"] += 1
                    elif latency_float < 200:
                        histogram["100_200"] += 1
                    else:
                        histogram["gte_200"] += 1

        resolver_kpis: list[dict] = []
        for resolver, stat in resolver_stats.items():
            samples = stat["latency_samples"]
            success_rate = (stat["healthy_samples"] / stat["total_samples"] * 100.0) if stat["total_samples"] else 0.0
            resolver_kpis.append(
                {
                    "resolver": resolver,
                    "success_rate_percent": round(success_rate, 2),
                    "avg_latency_ms": round(sum(samples) / len(samples), 2) if samples else None,
                    "min_latency_ms": round(min(samples), 2) if samples else None,
                    "max_latency_ms": round(max(samples), 2) if samples else None,
                    "sample_count": stat["total_samples"],
                }
            )

        resolver_kpis.sort(key=lambda item: (item["avg_latency_ms"] is None, item["avg_latency_ms"] or 10_000))

        recent_snapshots = history[-288:]
        switch_count = 0
        previous = None
        for snapshot in recent_snapshots:
            current = snapshot.get("selected_resolver")
            if current and previous and current != previous:
                switch_count += 1
            if current:
                previous = current

        return {
            "sample_count": len(history),
            "resolver_kpis": resolver_kpis,
            "latency_histogram": histogram,
            "overall_avg_latency_ms": round(sum(latency_values) / len(latency_values), 2) if latency_values else None,
            "resolver_switches_recent": switch_count,
        }

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

        existing_history = getattr(self.settings, "dnstt_telemetry_history", None)
        history: list[dict] = existing_history if isinstance(existing_history, list) else []
        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "selected_resolver": telemetry.get("selected_resolver"),
            "strategy": telemetry.get("strategy"),
            "probe_results": telemetry.get("probe_results", []),
        }
        history.append(snapshot)
        history = history[-300:]

        telemetry = {
            **telemetry,
            "analytics": self._build_telemetry_analytics(history),
        }

        self.settings.dnstt_telemetry = telemetry
        if hasattr(self.settings, "dnstt_telemetry_history"):
            self.settings.dnstt_telemetry_history = history
        session = object_session(self.settings)
        if session is None:
            return

        self.settings.updated_at = datetime.utcnow()
        session.add(self.settings)
        session.commit()
        session.refresh(self.settings)

    def collect_diagnostics(self) -> dict:
        local_commands = [
            ("service_state", "systemctl is-active dnstt-server.service dnstt-client.service dnstt-optimizer.service dnstt-multiplexer.service || true"),
            ("service_status", "systemctl --no-pager --full status dnstt-server.service dnstt-client.service dnstt-optimizer.service dnstt-multiplexer.service || true"),
            ("recent_logs", "journalctl --no-pager -n 120 -u dnstt-server.service -u dnstt-client.service -u dnstt-optimizer.service -u dnstt-multiplexer.service || true"),
            ("socket_ports", "ss -tulnp | grep -E '(:53|:5300|:5301|:9000|:1080)' || true"),
            ("nat_rules", "iptables -t nat -S | grep -E 'DNSTT|5300|5301|9000' || true"),
        ]

        diagnostics = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tunnel_architecture": "relay" if self._is_relay_mode() else "standalone",
            "local": {},
            "foreign": {},
            "telemetry": getattr(self.settings, "dnstt_telemetry", None),
        }

        for key, command in local_commands:
            result = self._run_on_target(command=command, target="local", timeout=30)
            diagnostics["local"][key] = {
                "success": result.success,
                "return_code": result.return_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        if self._is_relay_mode():
            foreign_commands = [
                ("service_state", "systemctl is-active dnstt-server.service || true"),
                ("service_status", "systemctl --no-pager --full status dnstt-server.service || true"),
                ("recent_logs", "journalctl --no-pager -n 80 -u dnstt-server.service || true"),
                ("socket_ports", "ss -tulnp | grep -E '(:53|:5300)' || true"),
                ("nat_rules", "iptables -t nat -S | grep -E '5300|PREROUTING' || true"),
            ]
            for key, command in foreign_commands:
                result = self._run_on_target(command=command, target="foreign", timeout=30)
                diagnostics["foreign"][key] = {
                    "success": result.success,
                    "return_code": result.return_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

        return diagnostics

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
            f"mkdir -p {self.repo_dir}/.atlas-build",
            f"cd {self.repo_dir} && go build -o .atlas-build/dnstt-server ./dnstt-server",
            f"cd {self.repo_dir} && go build -o .atlas-build/dnstt-client ./dnstt-client",
            f"install -m 0755 {self.repo_dir}/.atlas-build/dnstt-server {self.server_bin}",
            f"install -m 0755 {self.repo_dir}/.atlas-build/dnstt-client {self.client_bin}",
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
        command = (
            "tmp_priv=$(mktemp) && tmp_pub=$(mktemp) && "
            f"{self.server_bin} -gen-key -privkey-file \"$tmp_priv\" -pubkey-file \"$tmp_pub\" && "
            "printf 'priv: %s\\n' \"$(cat \"$tmp_priv\")\" && "
            "printf 'pub: %s\\n' \"$(cat \"$tmp_pub\")\" && "
            "rm -f \"$tmp_priv\" \"$tmp_pub\""
        )
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

    def generate_client_profile(self) -> dict:
        domain = self._active_domain()
        pubkey = (getattr(self.settings, "dnstt_pubkey", "") or "").strip()
        if not domain or not pubkey:
            return {
                "success": False,
                "message": "DNSTT active domain and public key are required to generate client profile",
            }

        configured_resolvers: list[str] = []
        seen = set()
        for resolver in self._resolver_candidates():
            selected = resolver.strip()
            key = selected.lower()
            if key in seen:
                continue
            seen.add(key)
            configured_resolvers.append(selected)

        profile = {
            "schema": "atlas.dnstt.client_profile.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": str(self.mode),
            "architecture": str(getattr(self.settings, "tunnel_architecture", "standalone") or "standalone"),
            "server": {
                "domain": domain,
                "pubkey": pubkey,
            },
            "transport": {
                "resolver_strategy": self._resolver_strategy(),
                "duplication_mode": self._duplication_mode(),
                "retry_count": self._transport_retry_count(),
                "probe_timeout_ms": self._safe_int(
                    getattr(self.settings, "dnstt_transport_probe_timeout_ms", 2000),
                    2000,
                    minimum=500,
                    maximum=15000,
                ),
                "switch_threshold_percent": self._safe_int(
                    getattr(self.settings, "dnstt_transport_switch_threshold_percent", 20),
                    20,
                    minimum=5,
                    maximum=80,
                ),
                "resolver_endpoints": {
                    "primary": configured_resolvers[0],
                    "fallback_chain": configured_resolvers[1:],
                    "all": configured_resolvers,
                },
                "doh_endpoints": {
                    "primary": configured_resolvers[0],
                    "fallback_chain": configured_resolvers[1:],
                    "all": configured_resolvers,
                },
            },
            "mtu": {
                "mode": self._mtu_mode(),
                "preset_value": self._mtu_value(),
                "adaptive_per_resolver": self._adaptive_per_resolver_enabled(),
                "adaptive_upload_min": self._safe_int(
                    getattr(self.settings, "dnstt_mtu_upload_min", 472),
                    472,
                    minimum=self.MIN_MTU,
                    maximum=self.MAX_MTU,
                ),
                "adaptive_upload_max": self._safe_int(
                    getattr(self.settings, "dnstt_mtu_upload_max", 1204),
                    1204,
                    minimum=self.MIN_MTU,
                    maximum=self.MAX_MTU,
                ),
                "adaptive_download_min": self._safe_int(
                    getattr(self.settings, "dnstt_mtu_download_min", 472),
                    472,
                    minimum=self.MIN_MTU,
                    maximum=self.MAX_MTU,
                ),
                "adaptive_download_max": self._safe_int(
                    getattr(self.settings, "dnstt_mtu_download_max", 1204),
                    1204,
                    minimum=self.MIN_MTU,
                    maximum=self.MAX_MTU,
                ),
            },
            "client_runtime": {
                "binary": self.client_bin,
                "local_udp_bind": "127.0.0.1:5301",
                "local_socks5_listen": "127.0.0.1:1080",
            },
        }
        return {
            "success": True,
            "message": "DNSTT client profile generated",
            "profile": profile,
        }

    def generate_http_injector_starter(self) -> dict:
        domain = self._active_domain()
        pubkey = (getattr(self.settings, "dnstt_pubkey", "") or "").strip()
        if not domain or not pubkey:
            return {
                "success": False,
                "message": "DNSTT active domain and public key are required to generate HTTP Injector starter",
            }

        resolver_list = self._resolver_candidates()
        configured_ssh_host = str(getattr(self.settings, "server_address", "") or "").strip()
        if not configured_ssh_host:
            configured_ssh_host = str(getattr(self.settings, "foreign_server_ip", "") or "").strip()
        configured_ssh_host = configured_ssh_host or "<set-in-app>"
        configured_ssh_port = self._safe_int(getattr(self.settings, "foreign_server_port", 22), 22, minimum=1, maximum=65535)
        configured_sni = domain

        starter = {
            "schema": "atlas.http_injector.starter.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "note": "This file is a starter template for HTTP Injector. Build and export the final encrypted .ehi inside the HTTP Injector app.",
            "dnstt_reference": {
                "domain": domain,
                "pubkey": pubkey,
                "resolver_endpoints": resolver_list,
                "mtu_mode": self._mtu_mode(),
                "mtu_preset_value": self._mtu_value(),
            },
            "documented_app_flow": [
                "Open HTTP Injector and choose tunnel type scenario below.",
                "Apply payload and connection options exactly as provided.",
                "Fill SSH/SSL credentials in app settings.",
                "Test connection, then use Export Config to create final .ehi.",
            ],
            "http_injector_input_catalog": {
                "sections": [
                    {
                        "name": "SSH Settings",
                        "fields": [
                            "Host",
                            "Port",
                            "Username",
                            "Password",
                        ],
                    },
                    {
                        "name": "Payload Settings",
                        "fields": [
                            "Enable Custom Payload",
                            "Payload Text",
                        ],
                    },
                    {
                        "name": "Remote Proxy",
                        "fields": [
                            "Use Remote Proxy",
                            "Proxy Host",
                            "Proxy Port",
                            "Proxy Username",
                            "Proxy Password",
                        ],
                    },
                    {
                        "name": "SSL/TLS Settings",
                        "fields": [
                            "Enable SSL/TLS",
                            "SNI Host",
                        ],
                    },
                ],
            },
            "scenarios": [
                {
                    "id": "ssh_custom_payload_direct",
                    "title": "Secure Shell (SSH) + Custom Payload + Direct",
                    "matches_http_injector_docs": True,
                    "tunnel_type": "Secure Shell (SSH)",
                    "connect_from": "None (Direct)",
                    "http_injector_mode": {
                        "tunnel_type": "SSH",
                        "connect_from": "Direct",
                    },
                    "injector_fields": {
                        "ssh_settings": {
                            "host": configured_ssh_host,
                            "port": configured_ssh_port,
                            "username": "<set-in-app>",
                            "password": "<set-in-app>",
                        },
                        "payload_settings": {
                            "enable_custom_payload": True,
                            "payload_templates": [
                                "CONNECT [host_port] [protocol][crlf]Host: [host][crlf]X-Online-Host: [host][crlf]X-Forward-Host: [host][crlf]Connection: Keep-Alive[crlf][crlf]",
                                "CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf]Connection: keep-alive[crlf][crlf]",
                            ],
                            "recommended_host_placeholder": domain,
                        },
                        "remote_proxy": {
                            "enabled": False,
                        },
                        "ssl_tls": {
                            "enabled": False,
                        },
                    },
                    "user_must_provide": [
                        "ssh_settings.username",
                        "ssh_settings.password",
                    ],
                },
                {
                    "id": "ssh_custom_payload_proxy",
                    "title": "Secure Shell (SSH) + Custom Payload + Proxy",
                    "matches_http_injector_docs": True,
                    "tunnel_type": "Secure Shell (SSH)",
                    "connect_from": "Proxy",
                    "http_injector_mode": {
                        "tunnel_type": "SSH",
                        "connect_from": "Proxy",
                    },
                    "injector_fields": {
                        "ssh_settings": {
                            "host": configured_ssh_host,
                            "port": configured_ssh_port,
                            "username": "<set-in-app>",
                            "password": "<set-in-app>",
                        },
                        "payload_settings": {
                            "enable_custom_payload": True,
                            "payload_templates": [
                                "CONNECT [host_port] [protocol][crlf]Host: [host][crlf]Proxy-Connection: Keep-Alive[crlf][crlf]",
                            ],
                            "recommended_host_placeholder": domain,
                        },
                        "remote_proxy": {
                            "enabled": True,
                            "host": "<set-in-app>",
                            "port": 8080,
                            "username": "<optional>",
                            "password": "<optional>",
                        },
                        "ssl_tls": {
                            "enabled": False,
                        },
                    },
                    "user_must_provide": [
                        "ssh_settings.username",
                        "ssh_settings.password",
                        "remote_proxy.host",
                    ],
                },
                {
                    "id": "ssh_ssl_sni",
                    "title": "SSH over SSL/TLS (SNI)",
                    "matches_http_injector_docs": True,
                    "tunnel_type": "Secure Shell (SSH)",
                    "connect_from": "SSL/TLS",
                    "http_injector_mode": {
                        "tunnel_type": "SSH",
                        "connect_from": "SSL/TLS",
                    },
                    "injector_fields": {
                        "ssh_settings": {
                            "host": configured_ssh_host,
                            "port": configured_ssh_port,
                            "username": "<set-in-app>",
                            "password": "<set-in-app>",
                        },
                        "payload_settings": {
                            "enable_custom_payload": False,
                        },
                        "remote_proxy": {
                            "enabled": False,
                        },
                        "ssl_tls": {
                            "enabled": True,
                            "sni_host": configured_sni,
                        },
                    },
                    "user_must_provide": [
                        "ssh_settings.username",
                        "ssh_settings.password",
                    ],
                    "notes": [
                        "Use when payload-based direct/proxy paths are unstable.",
                        "In high filtering environments, rotate SNI host and SSH endpoint when blocked.",
                    ],
                },
            ],
            "export_guidance": {
                "config_locking_options": [
                    "Lock config and prevent editing",
                    "Include payload",
                    "Include remote proxy auth (if used)",
                    "Include SNI (if used)",
                ],
                "final_step": "Use HTTP Injector Export Config to generate .ehi for end users.",
            },
        }
        return {
            "success": True,
            "message": "HTTP Injector starter generated",
            "starter": starter,
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
        mtu_q = shlex.quote(str(self._mtu_value()))
        service_steps = [
            "cat > /etc/systemd/system/dnstt-server.service <<'EOF'\n[Unit]\nDescription=DNSTT Server\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey {privkey} -domain {domain} -mtu {mtu} 127.0.0.1:5300\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(privkey=privkey_q, domain=domain_q, mtu=mtu_q),
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

        duplication_mode = self._duplication_mode()
        if duplication_mode > 1:
            return self._setup_client_duplication(domain=domain, pubkey=pubkey, duplication_mode=duplication_mode)

        strategy = self._resolver_strategy()
        if strategy == "round-robin":
            return self._setup_client_round_robin(domain=domain, pubkey=pubkey)
        if strategy == "least-latency":
            return self._setup_client_least_latency(domain=domain, pubkey=pubkey)
        return self._setup_client_failover(domain=domain, pubkey=pubkey)

    def _setup_client_duplication(self, *, domain: str, pubkey: str, duplication_mode: int) -> dict:
        domain_q = shlex.quote(domain)
        pubkey_q = shlex.quote(pubkey)
        healthy_resolvers, resolver_telemetry = self._select_all_healthy_doh_endpoints()
        selected_resolvers = healthy_resolvers[:duplication_mode]
        if len(selected_resolvers) < duplication_mode:
            return {
                "success": False,
                "message": f"DNSTT duplication mode {duplication_mode}x requires at least {duplication_mode} healthy DNS endpoints",
                "target": "local",
                "duplication_mode": duplication_mode,
                "resolver_probe_report": resolver_telemetry.get("probe_results", []),
            }

        resolver_telemetry["strategy"] = "duplication"
        resolver_telemetry["duplication_mode"] = duplication_mode
        self._persist_telemetry(resolver_telemetry)

        multiplexer_source_q = shlex.quote(self._multiplexer_script_source_path())
        service_steps = [
            *self._client_reset_steps(remove_multiplexer_script=False),
            "install -m 0755 {source} /usr/local/bin/dnstt_multiplexer.py".format(source=multiplexer_source_q),
        ]

        instance_ports: list[int] = []
        for idx, resolver in enumerate(selected_resolvers, start=1):
            local_udp_port = 9000 + idx
            instance_ports.append(local_udp_port)
            service_name = f"dnstt-client-{idx}.service"
            service_name_q = shlex.quote(service_name)
            doh_resolver_q = shlex.quote(resolver["selected_doh"])
            mtu_q = shlex.quote(str(self._selected_mtu_for_resolver(resolver)))
            service_steps.append(
                self._client_service_unit_step(
                    service_name=service_name,
                    service_description=f"DNSTT Client Duplication Instance {idx}",
                    doh_q=doh_resolver_q,
                    pubkey_q=pubkey_q,
                    domain_q=domain_q,
                    mtu_q=mtu_q,
                    local_udp_port=local_udp_port,
                )
            )
            service_steps.append(f"systemctl enable {service_name_q}")

        target_ports = ",".join(str(port) for port in instance_ports)
        target_ports_q = shlex.quote(target_ports)
        service_steps.append(
            "cat > /etc/systemd/system/dnstt-multiplexer.service <<'EOF'\n[Unit]\nDescription=DNSTT UDP Multiplexer\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /usr/local/bin/dnstt_multiplexer.py --listen-host 127.0.0.1 --listen-port 9000 --target-host 127.0.0.1 --target-ports {target_ports}\nRestart=always\nRestartSec=2\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\nEOF".format(target_ports=target_ports_q)
        )
        service_steps.extend(
            [
                "systemctl daemon-reload",
                "systemctl enable dnstt-multiplexer.service",
            ]
        )
        for idx in range(1, len(instance_ports) + 1):
            service_steps.append(f"systemctl restart dnstt-client-{idx}.service")
        service_steps.append("systemctl restart dnstt-multiplexer.service")

        result = self._run_steps(target="local", steps=service_steps)
        return {
            "success": result.get("success", False),
            "message": "DNSTT duplication mode configured" if result.get("success") else "DNSTT duplication mode setup failed",
            "target": "local",
            "strategy": "duplication",
            "duplication_mode": duplication_mode,
            "active_domain": domain,
            "healthy_resolvers": [item["selected_doh"] for item in selected_resolvers],
            "local_udp_ports": instance_ports,
            "multiplexer_port": 9000,
            "multiplexer_service": "dnstt-multiplexer.service",
            "resolver_probe_report": resolver_telemetry.get("probe_results", []),
            "dnstt_telemetry": resolver_telemetry,
            "details": result,
        }

    def _setup_client_failover(self, *, domain: str, pubkey: str) -> dict:
        domain_q = shlex.quote(domain)
        pubkey_q = shlex.quote(pubkey)
        doh_resolver, resolver_telemetry = self._select_healthy_doh_endpoint()
        resolver_telemetry["strategy"] = "failover"
        selected_resolver_info = self._resolver_info_by_selected_doh(resolver_telemetry, doh_resolver)
        mtu_q = shlex.quote(str(self._selected_mtu_for_resolver(selected_resolver_info)))
        self._persist_telemetry(resolver_telemetry)
        doh_resolver_q = shlex.quote(doh_resolver)
        service_steps = [
            *self._client_reset_steps(remove_multiplexer_script=True),
            self._client_service_unit_step(
                service_name="dnstt-client.service",
                service_description="DNSTT Client",
                doh_q=doh_resolver_q,
                pubkey_q=pubkey_q,
                domain_q=domain_q,
                mtu_q=mtu_q,
                local_udp_port=5301,
            ),
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
            *self._client_reset_steps(remove_multiplexer_script=True),
            "systemctl daemon-reload",
        ]

        instance_ports: list[int] = []
        for idx, resolver in enumerate(healthy_resolvers, start=1):
            local_udp_port = 9000 + idx
            instance_ports.append(local_udp_port)
            service_name = f"dnstt-client-{idx}.service"
            service_name_q = shlex.quote(service_name)
            doh_resolver_q = shlex.quote(resolver["selected_doh"])
            mtu_q = shlex.quote(str(self._selected_mtu_for_resolver(resolver)))
            service_steps.append(
                self._client_service_unit_step(
                    service_name=service_name,
                    service_description=f"DNSTT Client Instance {idx}",
                    doh_q=doh_resolver_q,
                    pubkey_q=pubkey_q,
                    domain_q=domain_q,
                    mtu_q=mtu_q,
                    local_udp_port=local_udp_port,
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
        selected_resolver_info = self._resolver_info_by_selected_doh(resolver_telemetry, doh_resolver)
        selected_mtu = self._selected_mtu_for_resolver(selected_resolver_info)
        mtu_q = shlex.quote(str(selected_mtu))
        self._persist_telemetry(resolver_telemetry)
        doh_resolver_q = shlex.quote(doh_resolver)
        resolver_mtu_map = {
            item["selected_doh"]: self._selected_mtu_for_resolver(item)
            for item in resolver_telemetry.get("probe_results", [])
            if item.get("selected_doh")
        }
        optimizer_payload = {
            "domain": domain,
            "pubkey": pubkey,
            "mtu": selected_mtu,
            "mtu_map": resolver_mtu_map,
            "resolvers": self._resolver_candidates(),
            "initial_doh": doh_resolver,
            "probe_timeout_seconds": self._transport_probe_timeout_seconds(),
            "switch_threshold_ratio": self._transport_switch_threshold_ratio(),
            "interval_seconds": 180,
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
THRESHOLD = float(CONFIG.get('switch_threshold_ratio', 0.8) or 0.8)
INTERVAL_SECONDS = int(CONFIG.get('interval_seconds', 180) or 180)
PROBE_TIMEOUT_SECONDS = float(CONFIG.get('probe_timeout_seconds', 2.0) or 2.0)


def normalize_doh(candidate: str) -> str:
    candidate = (candidate or '').strip()
    if candidate.startswith(('http://', 'https://')):
        return candidate
    return f'https://{candidate}/dns-query'


def probe_url(endpoint: str, timeout_seconds: float = PROBE_TIMEOUT_SECONDS):
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


def probe_ip(ip_address: str, timeout_seconds: float = PROBE_TIMEOUT_SECONDS):
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
    mtu_map = CONFIG.get('mtu_map') or {}
    mapped_mtu = mtu_map.get(selected_doh, CONFIG.get('mtu', 1232))
    cmd = '/usr/local/bin/dnstt-client -doh {doh} -udp 127.0.0.1:5301 -pubkey {pubkey} -domain {domain} -mtu {mtu} 127.0.0.1:1080'.format(
        doh=shlex.quote(selected_doh),
        pubkey=shlex.quote(CONFIG.get('pubkey', '')),
        domain=shlex.quote(CONFIG.get('domain', '')),
        mtu=shlex.quote(str(int(mapped_mtu or 1232))),
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
            *self._client_reset_steps(remove_multiplexer_script=True),
            self._client_service_unit_step(
                service_name="dnstt-client.service",
                service_description="DNSTT Client",
                doh_q=doh_resolver_q,
                pubkey_q=pubkey_q,
                domain_q=domain_q,
                mtu_q=mtu_q,
                local_udp_port=5301,
            ),
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
