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
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    offset = (page - 1) * page_size

    query = db.query(AuditLog)
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
