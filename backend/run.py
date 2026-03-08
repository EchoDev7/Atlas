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
        return {}

    try:
        connection = sqlite3.connect(database_path)
        try:
            cursor = connection.execute(
                "SELECT panel_domain, panel_https_port FROM general_settings ORDER BY id ASC LIMIT 1"
            )
            row = cursor.fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return {}

    if not row:
        return {}

    return {
        "panel_domain": (row[0] or "").strip(),
        "panel_https_port": row[1],
    }


def _is_valid_domain_fragment(domain: str) -> bool:
    if not domain:
        return False
    return "/" not in domain and "\\" not in domain and ".." not in domain


def _resolve_ssl_paths(panel_domain: str) -> tuple[Path, Path] | tuple[None, None]:
    if not _is_valid_domain_fragment(panel_domain):
        return None, None

    cert_path = LETSENCRYPT_LIVE_DIR / panel_domain / "fullchain.pem"
    key_path = LETSENCRYPT_LIVE_DIR / panel_domain / "privkey.pem"
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path
    return None, None


def run() -> None:
    project_root = Path(__file__).resolve().parent.parent
    settings = _load_general_settings(project_root)

    panel_domain = settings.get("panel_domain", "")
    cert_path, key_path = _resolve_ssl_paths(panel_domain)

    base_http_port = _safe_int(os.getenv("ATLAS_HTTP_PORT"), DEFAULT_HTTP_PORT)

    uvicorn_kwargs: dict[str, Any] = {
        "app": "backend.main:app",
        "host": "0.0.0.0",
        "reload": False,
    }

    if cert_path and key_path:
        https_port = _safe_int(settings.get("panel_https_port"), base_http_port)
        uvicorn_kwargs["port"] = https_port
        uvicorn_kwargs["ssl_certfile"] = str(cert_path)
        uvicorn_kwargs["ssl_keyfile"] = str(key_path)
        print(
            f"[atlas-runner] HTTPS mode enabled for domain '{panel_domain}' on port {https_port} "
            f"with cert '{cert_path}'."
        )
    else:
        uvicorn_kwargs["port"] = base_http_port
        print(
            f"[atlas-runner] HTTP fallback mode enabled on port {base_http_port}. "
            "SSL certificate not available or panel domain is not configured."
        )

    uvicorn.run(**uvicorn_kwargs)


if __name__ == "__main__":
    run()
