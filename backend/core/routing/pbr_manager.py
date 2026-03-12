from __future__ import annotations

import logging
import subprocess


logger = logging.getLogger(__name__)


class PBRManager:
    _COMMENT_PREFIX = "ATLAS_PBR"
    _TABLE_PREFIX = "atlas_"

    def __init__(self, db=None):
        self.db = db

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def flush_routing_rules(self) -> None:
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
                delete_tokens = line.split()
                delete_tokens[0] = "-D"
                _ = self._run(["iptables", "-t", table, *delete_tokens])

        rule_dump = self._run(["ip", "rule", "show"])
        if rule_dump.returncode != 0:
            logger.warning(
                "failed to read ip rules during flush: %s",
                rule_dump.stderr.strip() or rule_dump.stdout.strip(),
            )
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
