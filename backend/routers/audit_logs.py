from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.audit_log import AuditLog
from backend.models.user import Admin
from backend.schemas.audit_log import AuditLogItemResponse, AuditLogListResponse

router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@router.get("/audit", response_model=AuditLogListResponse)
def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    status: Literal["all", "success", "failed"] = Query("all"),
    action: Optional[str] = Query(None, max_length=128),
    ip_address: Optional[str] = Query(None, max_length=64),
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    offset = (page - 1) * page_size

    query = db.query(AuditLog)

    if status == "success":
        query = query.filter(AuditLog.success.is_(True))
    elif status == "failed":
        query = query.filter(AuditLog.success.is_(False))

    normalized_action = (action or "").strip()
    if normalized_action:
        query = query.filter(AuditLog.action.ilike(f"%{normalized_action}%"))

    normalized_ip = (ip_address or "").strip()
    if normalized_ip:
        query = query.filter(AuditLog.ip_address.ilike(f"%{normalized_ip}%"))

    total = query.count()
    records = (
        query.order_by(desc(AuditLog.created_at), desc(AuditLog.id))
        .offset(offset)
        .limit(page_size)
        .all()
    )

    items = [
        AuditLogItemResponse(
            id=item.id,
            created_at=item.created_at,
            ip_address=item.ip_address,
            action=item.action,
            resource_type=item.resource_type,
            resource_id=item.resource_id,
            success=item.success,
        )
        for item in records
    ]

    return AuditLogListResponse(logs=items, total=total, page=page, page_size=page_size)
