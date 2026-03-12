# Atlas Policy-Based Routing (PBR) Manager
# Purpose: Isolate ingress protocols (e.g., OpenVPN, WireGuard) from egress tunnels (e.g., DNSTT) using iptables fwmark and iproute2 custom routing tables.

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class PBRManager:
    _RT_TABLES_PATH = Path("/etc/iproute2/rt_tables")
    _NAT_COMMENT = "ATLAS_PBR_PROXY"
    _MANGLE_COMMENT = "ATLAS_PBR_MARK"

    def _run(self, command: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check,
        )

    def _iptables_rule_exists(self, table: str, chain: str, spec: list[str]) -> bool:
        result = self._run(["iptables", "-t", table, "-C", chain, *spec])
        return result.returncode == 0

    def ensure_rt_table(self, table_id: int, table_name: str) -> bool:
        table_id_text = str(int(table_id))
        normalized_name = str(table_name).strip()
        if not normalized_name:
            raise ValueError("table_name must not be empty")

        if not self._RT_TABLES_PATH.exists():
            raise FileNotFoundError(f"{self._RT_TABLES_PATH} not found")

        raw_content = self._RT_TABLES_PATH.read_text(encoding="utf-8", errors="ignore")
        lines = raw_content.splitlines()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            current_id, current_name = parts[0], parts[1]
            if current_id == table_id_text and current_name == normalized_name:
                return False
            if current_id == table_id_text and current_name != normalized_name:
                logger.warning(
                    "rt_tables id conflict: id %s exists with name %s (requested %s)",
                    table_id_text,
                    current_name,
                    normalized_name,
                )
                return False
            if current_name == normalized_name and current_id != table_id_text:
                logger.warning(
                    "rt_tables name conflict: name %s exists with id %s (requested %s)",
                    normalized_name,
                    current_id,
                    table_id_text,
                )
                return False

        with self._RT_TABLES_PATH.open("a", encoding="utf-8") as fp:
            fp.write(f"{table_id_text} {normalized_name}\n")
        return True

    def add_ip_rule(self, fwmark: int, table_name: str) -> bool:
        normalized_table = str(table_name).strip()
        if not normalized_table:
            raise ValueError("table_name must not be empty")

        fwmark_value = int(fwmark)
        rule_dump = self._run(["ip", "rule", "show"])
        if rule_dump.returncode != 0:
            raise RuntimeError(f"failed to list ip rules: {rule_dump.stderr.strip()}")

        fwmark_hex = hex(fwmark_value)
        for line in (rule_dump.stdout or "").splitlines():
            normalized = line.strip().lower()
            if f"lookup {normalized_table.lower()}" not in normalized:
                continue
            if f"fwmark {fwmark_hex}" in normalized or f"fwmark {fwmark_value}" in normalized:
                return False

        add_result = self._run(["ip", "rule", "add", "fwmark", str(fwmark_value), "table", normalized_table])
        if add_result.returncode != 0:
            raise RuntimeError(f"failed to add ip rule: {add_result.stderr.strip() or add_result.stdout.strip()}")
        return True

    def mark_ingress_traffic(self, ingress_iface: str, fwmark: int) -> bool:
        iface = str(ingress_iface).strip()
        if not iface:
            raise ValueError("ingress_iface must not be empty")

        fwmark_value = str(int(fwmark))
        spec = [
            "-i",
            iface,
            "-m",
            "comment",
            "--comment",
            self._MANGLE_COMMENT,
            "-j",
            "MARK",
            "--set-mark",
            fwmark_value,
        ]
        if self._iptables_rule_exists("mangle", "PREROUTING", spec):
            return False

        add_result = self._run(["iptables", "-t", "mangle", "-A", "PREROUTING", *spec])
        if add_result.returncode != 0:
            raise RuntimeError(f"failed to add mangle mark rule: {add_result.stderr.strip() or add_result.stdout.strip()}")
        return True

    def link_ingress_to_local_proxy(self, ingress_iface: str, proxy_port: int, protocol: str = "tcp") -> bool:
        iface = str(ingress_iface).strip()
        if not iface:
            raise ValueError("ingress_iface must not be empty")

        proto = str(protocol).strip().lower()
        if proto not in {"tcp", "udp"}:
            raise ValueError("protocol must be 'tcp' or 'udp'")

        proxy_port_value = int(proxy_port)
        if proxy_port_value <= 0 or proxy_port_value > 65535:
            raise ValueError("proxy_port must be in 1..65535")

        spec = [
            "-i",
            iface,
            "-p",
            proto,
            "-m",
            "comment",
            "--comment",
            self._NAT_COMMENT,
            "-j",
            "REDIRECT",
            "--to-ports",
            str(proxy_port_value),
        ]
        if self._iptables_rule_exists("nat", "PREROUTING", spec):
            return False

        add_result = self._run(["iptables", "-t", "nat", "-A", "PREROUTING", *spec])
        if add_result.returncode != 0:
            raise RuntimeError(f"failed to add nat redirect rule: {add_result.stderr.strip() or add_result.stdout.strip()}")
        return True

    def flush_routing_rules(self) -> None:
        iptables_targets = [
            ("mangle", self._MANGLE_COMMENT),
            ("nat", self._NAT_COMMENT),
        ]
        for table, comment in iptables_targets:
            list_result = self._run(["iptables", "-t", table, "-S", "PREROUTING"])
            if list_result.returncode != 0:
                logger.warning(
                    "failed to list iptables %s PREROUTING during flush: %s",
                    table,
                    list_result.stderr.strip() or list_result.stdout.strip(),
                )
                continue
            for raw_line in (list_result.stdout or "").splitlines():
                line = raw_line.strip()
                if not line.startswith("-A PREROUTING "):
                    continue
                if f'--comment "{comment}"' not in line and f"--comment {comment}" not in line:
                    continue
                delete_tokens = line.split()
                delete_tokens[0] = "-D"
                _ = self._run(["iptables", "-t", table, *delete_tokens])

        rule_dump = self._run(["ip", "rule", "show"])
        if rule_dump.returncode != 0:
            logger.warning("failed to read ip rules during flush: %s", rule_dump.stderr.strip() or rule_dump.stdout.strip())
            return

        for line in (rule_dump.stdout or "").splitlines():
            normalized = line.strip().lower()
            if "lookup atlas" not in normalized:
                continue
            tokens = line.split()
            if "fwmark" not in tokens or "lookup" not in tokens:
                continue
            try:
                fwmark_value = tokens[tokens.index("fwmark") + 1]
                table_name = tokens[tokens.index("lookup") + 1]
            except (ValueError, IndexError):
                continue
            _ = self._run(["ip", "rule", "del", "fwmark", fwmark_value, "table", table_name])
