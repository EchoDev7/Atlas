# Atlas Policy-Based Routing (PBR) Manager
# Purpose: Isolate ingress protocols (e.g., OpenVPN, WireGuard) from selected egress paths using iptables fwmark and iproute2 custom routing tables.

from __future__ import annotations

import logging
import os
import re
import shlex
import socket
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy.orm import Session

from backend.core.config import (
    PBR_COMMENT_PREFIX,
    PBR_DEFAULT_DEST_CIDR,
    PBR_DEFAULT_NAT_COMMENT,
    PBR_DEFAULT_PROXY_PROTOCOL,
    PBR_DEFAULT_WAN_INTERFACE,
    PBR_LEGACY_DNS_REDIRECT_PORT,
    PBR_RT_TABLES_PATH,
    PBR_TABLE_PREFIX,
)
from backend.database import SessionLocal
from backend.models.general_settings import GeneralSettings
from backend.models.routing_rule import RoutingRule

logger = logging.getLogger(__name__)


class PBRManager:
    _RT_TABLES_PATH = Path(PBR_RT_TABLES_PATH)
    _TABLE_PREFIX = PBR_TABLE_PREFIX
    _COMMENT_PREFIX = PBR_COMMENT_PREFIX
    _DEFAULT_NAT_COMMENT = PBR_DEFAULT_NAT_COMMENT

    def __init__(self, db: Session | None = None):
        self._db = db

    @contextmanager
    def _session_scope(self) -> Iterator[Session]:
        if self._db is not None:
            yield self._db
            return
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

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

    def _sanitize_name(self, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9_]+", "_", value.strip().lower())
        normalized = re.sub(r"_+", "_", normalized).strip("_")
        return normalized or "rule"

    def _comment_for(self, kind: str, rule_name: str) -> str:
        return f"{self._COMMENT_PREFIX}:{kind}:{self._sanitize_name(rule_name)}"

    def _resolve_wan_interface(self, out_iface: str = PBR_DEFAULT_WAN_INTERFACE) -> str:
        fallback = str(out_iface or PBR_DEFAULT_WAN_INTERFACE).strip() or PBR_DEFAULT_WAN_INTERFACE
        try:
            with self._session_scope() as db:
                settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
            configured = str(getattr(settings, "wan_interface", "") or "").strip() if settings else ""
            return configured or fallback
        except Exception as exc:
            logger.warning("failed to resolve WAN interface from general_settings, using fallback %s: %s", fallback, exc)
            return fallback

    def _rule_table_name(self, rule: RoutingRule) -> str:
        explicit = str(rule.table_name or "").strip()
        if explicit:
            return explicit
        return f"{self._TABLE_PREFIX}_{self._sanitize_name(rule.rule_name)}"

    def _rule_table_id(self, rule: RoutingRule) -> int:
        if int(rule.table_id or 0) > 0:
            return int(rule.table_id)
        return int(rule.fwmark)

    def _is_tunnel_enabled(self) -> bool:
        try:
            with self._session_scope() as db:
                settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
            return bool(getattr(settings, "is_tunnel_enabled", False)) if settings else False
        except Exception as exc:
            logger.warning("failed to resolve tunnel toggle from general_settings: %s", exc)
            return False

    def _is_local_proxy_listener_ready(self, port: int, protocol: str) -> bool:
        proxy_port = int(port)
        if proxy_port <= 0 or proxy_port > 65535:
            return False

        normalized_protocol = str(protocol or PBR_DEFAULT_PROXY_PROTOCOL).strip().lower()
        if normalized_protocol not in {"tcp", "udp"}:
            return False

        if normalized_protocol == "tcp":
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.25):
                    return True
            except OSError:
                return False

        try:
            result = self._run(["ss", "-lun", f"sport = :{proxy_port}"])
        except FileNotFoundError:
            logger.warning("ss command is not available; cannot validate udp listener on port %s", proxy_port)
            return False
        if result.returncode != 0:
            logger.warning(
                "failed to probe udp listener for local proxy port %s: %s",
                proxy_port,
                result.stderr.strip() or result.stdout.strip(),
            )
            return False

        lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
        return len(lines) > 1

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

    def mark_ingress_traffic(
        self,
        ingress_iface: str,
        fwmark: int,
        rule_name: str = "default",
        dest_cidr: str = PBR_DEFAULT_DEST_CIDR,
    ) -> bool:
        iface = str(ingress_iface).strip()
        if not iface:
            raise ValueError("ingress_iface must not be empty")
        destination = str(dest_cidr or PBR_DEFAULT_DEST_CIDR).strip() or PBR_DEFAULT_DEST_CIDR

        fwmark_value = str(int(fwmark))
        comment = self._comment_for("mark", rule_name)
        spec = [
            "-i",
            iface,
            "-d",
            destination,
            "-m",
            "comment",
            "--comment",
            comment,
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

    def link_ingress_to_local_proxy(
        self,
        ingress_iface: str,
        proxy_port: int,
        protocol: str = PBR_DEFAULT_PROXY_PROTOCOL,
        rule_name: str = "default",
        dest_cidr: str = PBR_DEFAULT_DEST_CIDR,
    ) -> bool:
        iface = str(ingress_iface).strip()
        if not iface:
            raise ValueError("ingress_iface must not be empty")
        destination = str(dest_cidr or PBR_DEFAULT_DEST_CIDR).strip() or PBR_DEFAULT_DEST_CIDR

        proto = str(protocol).strip().lower()
        if proto not in {"tcp", "udp"}:
            raise ValueError("protocol must be 'tcp' or 'udp'")

        proxy_port_value = int(proxy_port)
        if proxy_port_value <= 0 or proxy_port_value > 65535:
            raise ValueError("proxy_port must be in 1..65535")

        comment = self._comment_for("redirect", rule_name)
        spec = [
            "-i",
            iface,
            "-d",
            destination,
            "-p",
            proto,
            "-m",
            "comment",
            "--comment",
            comment,
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

    def ensure_default_nat(self, out_iface: str = PBR_DEFAULT_WAN_INTERFACE) -> bool:
        wan_iface = self._resolve_wan_interface(out_iface=out_iface)
        spec = [
            "-o",
            wan_iface,
            "-m",
            "comment",
            "--comment",
            self._DEFAULT_NAT_COMMENT,
            "-j",
            "MASQUERADE",
        ]
        if self._iptables_rule_exists("nat", "POSTROUTING", spec):
            return False

        add_result = self._run(["iptables", "-t", "nat", "-A", "POSTROUTING", *spec])
        if add_result.returncode != 0:
            raise RuntimeError(
                f"failed to ensure default NAT masquerade on {wan_iface}: {add_result.stderr.strip() or add_result.stdout.strip()}"
            )
        return True

    def flush_routing_rules(self, out_iface: str = PBR_DEFAULT_WAN_INTERFACE) -> None:
        for table in ("mangle", "nat"):
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
                if self._COMMENT_PREFIX not in line:
                    continue
                delete_tokens = shlex.split(line)
                delete_tokens[0] = "-D"
                _ = self._run(["iptables", "-t", table, *delete_tokens])

        self._remove_legacy_dns_redirect_rules()

        rule_dump = self._run(["ip", "rule", "show"])
        if rule_dump.returncode != 0:
            logger.warning("failed to read ip rules during flush: %s", rule_dump.stderr.strip() or rule_dump.stdout.strip())
            return

        for line in (rule_dump.stdout or "").splitlines():
            normalized = line.strip().lower()
            if "lookup " not in normalized:
                continue
            tokens = line.split()
            if "fwmark" not in tokens or "lookup" not in tokens:
                continue
            try:
                fwmark_value = tokens[tokens.index("fwmark") + 1]
                table_name = tokens[tokens.index("lookup") + 1]
            except (ValueError, IndexError):
                continue
            if not str(table_name).lower().startswith(self._TABLE_PREFIX):
                continue
            _ = self._run(["ip", "rule", "del", "fwmark", fwmark_value, "table", table_name])

        _ = self.ensure_default_nat(out_iface=out_iface)

    def _remove_legacy_dns_redirect_rules(self) -> None:
        list_result = self._run(["iptables", "-t", "nat", "-S", "PREROUTING"])
        if list_result.returncode != 0:
            logger.warning(
                "failed to list nat PREROUTING while removing legacy DNS redirects: %s",
                list_result.stderr.strip() or list_result.stdout.strip(),
            )
            return

        for raw_line in (list_result.stdout or "").splitlines():
            line = raw_line.strip()
            if not line.startswith("-A PREROUTING "):
                continue

            tokens = shlex.split(line)
            normalized = " ".join(tokens).lower()
            if " --dport 53 " not in f" {normalized} ":
                continue
            if " -j redirect " not in f" {normalized} ":
                continue
            if f"--to-ports {PBR_LEGACY_DNS_REDIRECT_PORT}" not in normalized:
                continue

            tokens[0] = "-D"
            delete_result = self._run(["iptables", "-t", "nat", *tokens])
            if delete_result.returncode != 0:
                logger.warning(
                    "failed to delete legacy DNS redirect rule '%s': %s",
                    line,
                    delete_result.stderr.strip() or delete_result.stdout.strip(),
                )

    def _list_atlas_ip_rules(self) -> list[tuple[str, str]]:
        rule_dump = self._run(["ip", "rule", "show"])
        if rule_dump.returncode != 0:
            raise RuntimeError(f"failed to list ip rules: {rule_dump.stderr.strip() or rule_dump.stdout.strip()}")
        atlas_rules: list[tuple[str, str]] = []
        for line in (rule_dump.stdout or "").splitlines():
            normalized = line.strip().lower()
            if "lookup " not in normalized:
                continue
            tokens = line.split()
            if "fwmark" not in tokens or "lookup" not in tokens:
                continue
            try:
                fwmark_value = tokens[tokens.index("fwmark") + 1]
                table_name = tokens[tokens.index("lookup") + 1]
            except (ValueError, IndexError):
                continue
            if not str(table_name).lower().startswith(self._TABLE_PREFIX):
                continue
            atlas_rules.append((fwmark_value, table_name))
        return atlas_rules

    def _remove_all_atlas_ip_rules(self) -> None:
        for fwmark_value, table_name in self._list_atlas_ip_rules():
            _ = self._run(["ip", "rule", "del", "fwmark", fwmark_value, "table", table_name], check=False)

    def _restore_ip_rules_snapshot(self, snapshot: list[tuple[str, str]]) -> None:
        self._remove_all_atlas_ip_rules()
        for fwmark_value, table_name in snapshot:
            add_result = self._run(["ip", "rule", "add", "fwmark", fwmark_value, "table", table_name], check=False)
            if add_result.returncode != 0:
                logger.warning(
                    "failed to restore ip rule fwmark=%s table=%s: %s",
                    fwmark_value,
                    table_name,
                    add_result.stderr.strip() or add_result.stdout.strip(),
                )

    def _restore_iptables_snapshot(self, snapshot_path: Path) -> None:
        restore_result = self._run(["iptables-restore", str(snapshot_path)], check=False)
        if restore_result.returncode != 0:
            raise RuntimeError(
                f"failed to restore iptables snapshot: {restore_result.stderr.strip() or restore_result.stdout.strip()}"
            )

    def apply_all_active_rules(self) -> dict:
        snapshot_file: Path | None = None
        preexisting_atlas_ip_rules: list[tuple[str, str]] = self._list_atlas_ip_rules()
        applied: list[str] = []
        skipped: list[str] = []
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                prefix="atlas_iptables_",
                suffix=".backup",
                delete=False,
            ) as tmp_file:
                snapshot_file = Path(tmp_file.name)
            save_result = self._run(["iptables-save"], check=False)
            if save_result.returncode != 0:
                raise RuntimeError(
                    f"failed to snapshot iptables rules: {save_result.stderr.strip() or save_result.stdout.strip()}"
                )
            snapshot_file.write_text(save_result.stdout or "", encoding="utf-8")

            self.flush_routing_rules()

            if not self._is_tunnel_enabled():
                return {
                    "success": True,
                    "applied_rules": applied,
                    "skipped_rules": skipped,
                    "error_count": 0,
                    "errors": [],
                    "message": "Tunnel disabled: routing rules flushed and direct internet baseline restored",
                }

            with self._session_scope() as db:
                rules = (
                    db.query(RoutingRule)
                    .filter(RoutingRule.status == "active")
                    .order_by(RoutingRule.id.asc())
                    .all()
                )

            for rule in rules:
                try:
                    if not self._is_local_proxy_listener_ready(
                        int(rule.proxy_port),
                        str(rule.protocol or PBR_DEFAULT_PROXY_PROTOCOL),
                    ):
                        skipped.append(rule.rule_name)
                        logger.warning(
                            "skipping routing rule %s because local proxy listener is unavailable on %s/%s",
                            rule.rule_name,
                            int(rule.proxy_port),
                            str(rule.protocol or PBR_DEFAULT_PROXY_PROTOCOL).strip().lower(),
                        )
                        continue

                    table_name = self._rule_table_name(rule)
                    table_id = self._rule_table_id(rule)
                    self.ensure_rt_table(table_id, table_name)
                    self.add_ip_rule(int(rule.fwmark), table_name)
                    self.mark_ingress_traffic(
                        rule.ingress_iface,
                        int(rule.fwmark),
                        rule_name=rule.rule_name,
                        dest_cidr=str(rule.dest_cidr or PBR_DEFAULT_DEST_CIDR),
                    )
                    self.link_ingress_to_local_proxy(
                        rule.ingress_iface,
                        int(rule.proxy_port),
                        protocol=rule.protocol,
                        rule_name=rule.rule_name,
                        dest_cidr=str(rule.dest_cidr or PBR_DEFAULT_DEST_CIDR),
                    )
                    applied.append(rule.rule_name)
                except Exception as rule_exc:
                    logger.error(
                        "failed applying routing rule %s: %s",
                        rule.rule_name,
                        rule_exc,
                        extra={
                            "event_type": "firewall_rule_apply_failed",
                            "rule_name": str(rule.rule_name),
                            "error_message": str(rule_exc),
                        },
                    )
                    raise

            return {
                "success": True,
                "applied_rules": applied,
                "skipped_rules": skipped,
                "error_count": 0,
                "errors": [],
            }
        except Exception as exc:
            if snapshot_file is not None:
                try:
                    self._restore_iptables_snapshot(snapshot_file)
                except Exception as restore_exc:
                    logger.error(
                        "failed to restore iptables snapshot during rollback: %s",
                        restore_exc,
                        extra={
                            "event_type": "firewall_rollback_iptables_restore_failed",
                            "error_message": str(restore_exc),
                        },
                    )
            try:
                self._restore_ip_rules_snapshot(preexisting_atlas_ip_rules)
            except Exception as ip_rule_restore_exc:
                logger.error(
                    "failed to restore ip rule snapshot during rollback: %s",
                    ip_rule_restore_exc,
                    extra={
                        "event_type": "firewall_rollback_ip_rule_restore_failed",
                        "error_message": str(ip_rule_restore_exc),
                    },
                )
            logger.error(
                "routing rule transactional apply failed and rollback attempted: %s",
                exc,
                extra={
                    "event_type": "firewall_transaction_failed",
                    "error_message": str(exc),
                },
            )
            raise
        finally:
            if snapshot_file is not None:
                try:
                    os.unlink(snapshot_file)
                except FileNotFoundError:
                    pass
                except Exception as cleanup_exc:
                    logger.warning("failed to clean temporary iptables snapshot %s: %s", snapshot_file, cleanup_exc)
