import json
import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import Request

from backend.database import SessionLocal
from backend.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def extract_client_ip(request: Request) -> str:
    forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or "unknown"

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def _serialize_details(details: Any) -> Optional[str]:
    if details is None:
        return None
    if isinstance(details, str):
        value = details.strip()
        return value or None

    try:
        return json.dumps(details, ensure_ascii=True, default=str)
    except Exception:
        return str(details)


def record_audit_event(
    *,
    action: str,
    success: bool,
    admin_username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Any = None,
) -> None:
    normalized_action = (action or "").strip()
    if not normalized_action:
        return

    db = SessionLocal()
    try:
        item = AuditLog(
            admin_username=(admin_username or "").strip() or None,
            action=normalized_action,
            resource_type=(resource_type or "").strip() or None,
            resource_id=(resource_id or "").strip() or None,
            ip_address=(ip_address or "").strip() or None,
            success=bool(success),
            details=_serialize_details(details),
            created_at=datetime.utcnow(),
        )
        db.add(item)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("Failed to persist audit event %s: %s", normalized_action, exc)
    finally:
        db.close()
