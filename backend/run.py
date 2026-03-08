from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

import uvicorn

LETSENCRYPT_LIVE_DIR = Path("/etc/letsencrypt/live")
DEFAULT_HTTP_PORT = 8000


def _safe_int(value: Any, fallback: int) -> int:
    try:
        number = int(value)
        return number if number > 0 else fallback
    except (TypeError, ValueError):
        return fallback


def _load_general_settings(project_root: Path) -> dict[str, Any]:
    database_path = project_root / "data" / "atlas.db"
    if not database_path.is_file():
        print(f"[atlas-runner] Fallback reason: database file not found at '{database_path}'.")
        return {}

    try:
        connection = sqlite3.connect(database_path)
        try:
            cursor = connection.execute(
                """
                SELECT panel_domain, panel_https_port
                FROM general_settings
                WHERE TRIM(COALESCE(panel_domain, '')) != ''
                ORDER BY id DESC
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            if row is None:
                cursor = connection.execute(
                    """
                    SELECT panel_domain, panel_https_port
                    FROM general_settings
                    ORDER BY id DESC
                    LIMIT 1
                    """
                )
                row = cursor.fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        print(f"[atlas-runner] Fallback reason: failed to read general_settings from DB ({exc}).")
        return {}

    if not row:
        print("[atlas-runner] Fallback reason: general_settings row not found in database.")
        return {}

    panel_domain = (row[0] or "").strip()
    panel_https_port = row[1]
    print(
        "[atlas-runner] Loaded settings from DB: "
        f"panel_domain='{panel_domain or '<empty>'}', panel_https_port='{panel_https_port}'."
    )

    return {
        "panel_domain": panel_domain,
        "panel_https_port": panel_https_port,
    }


def _is_valid_domain_fragment(domain: str) -> bool:
    if not domain:
        return False
    return "/" not in domain and "\\" not in domain and ".." not in domain


def _resolve_ssl_paths(panel_domain: str) -> tuple[Path, Path] | tuple[None, None]:
    if not _is_valid_domain_fragment(panel_domain):
        if panel_domain:
            print(
                f"[atlas-runner] Fallback reason: panel_domain '{panel_domain}' is invalid for cert path resolution."
            )
        else:
            print("[atlas-runner] Fallback reason: panel_domain is empty in database.")
        return None, None

    cert_path = (LETSENCRYPT_LIVE_DIR / panel_domain / "fullchain.pem").resolve()
    key_path = (LETSENCRYPT_LIVE_DIR / panel_domain / "privkey.pem").resolve()

    cert_exists = cert_path.is_file()
    key_exists = key_path.is_file()
    if cert_exists and key_exists:
        return cert_path, key_path

    if not cert_exists:
        print(f"[atlas-runner] Fallback reason: SSL cert file not found: '{cert_path}'.")
    if not key_exists:
        print(f"[atlas-runner] Fallback reason: SSL key file not found: '{key_path}'.")
    return None, None


def run() -> None:
    project_root = Path(__file__).resolve().parent.parent
    settings = _load_general_settings(project_root)

    panel_domain = settings.get("panel_domain", "")
    cert_path, key_path = _resolve_ssl_paths(panel_domain)

    fallback_http_port = _safe_int(os.getenv("ATLAS_HTTP_PORT"), DEFAULT_HTTP_PORT)

    uvicorn_kwargs: dict[str, Any] = {
        "app": "backend.main:app",
        "host": "0.0.0.0",
        "reload": False,
    }

    if cert_path and key_path:
        https_port = _safe_int(settings.get("panel_https_port"), fallback_http_port)
        uvicorn_kwargs["port"] = https_port
        uvicorn_kwargs["ssl_certfile"] = str(cert_path)
        uvicorn_kwargs["ssl_keyfile"] = str(key_path)
        print(
            f"[atlas-runner] HTTPS mode enabled for domain '{panel_domain}' on port {https_port} "
            f"with cert '{cert_path}' and key '{key_path}'."
        )
    else:
        uvicorn_kwargs["port"] = fallback_http_port
        print(
            f"[atlas-runner] HTTP fallback mode enabled on port {fallback_http_port}. "
            "Launching without SSL arguments."
        )

    uvicorn.run(**uvicorn_kwargs)


if __name__ == "__main__":
    run()
