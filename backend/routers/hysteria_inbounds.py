from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.hysteria_inbound import HysteriaInbound
from backend.models.user import Admin
from backend.schemas.hysteria_inbound import (
    HysteriaInboundCreate,
    HysteriaInboundResponse,
    HysteriaInboundUpdate,
)
from backend.utils.crypto_utils import generate_self_signed_cert

router = APIRouter(prefix="/hysteria-inbounds", tags=["Hysteria Inbounds"])


def _is_valid_port_format(port_value: str) -> bool:
    normalized = str(port_value or "").strip()
    if not normalized:
        return False
    if normalized.isdigit():
        port = int(normalized)
        return 1 <= port <= 65535
    if "-" not in normalized:
        return False
    parts = normalized.split("-", 1)
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return False
    start = int(parts[0])
    end = int(parts[1])
    return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end


@router.get("/", response_model=list[HysteriaInboundResponse])
async def list_hysteria_inbounds(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return db.query(HysteriaInbound).order_by(HysteriaInbound.id.asc()).all()


@router.post("/", response_model=HysteriaInboundResponse, status_code=status.HTTP_201_CREATED)
async def create_hysteria_inbound(
    payload: HysteriaInboundCreate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    duplicate_remark = db.query(HysteriaInbound).filter(HysteriaInbound.remark == payload.remark).first()
    if duplicate_remark:
        raise HTTPException(status_code=409, detail="Hysteria inbound remark already exists")

    payload_data = payload.model_dump()
    if not _is_valid_port_format(payload_data.get("port", "")):
        raise HTTPException(
            status_code=422,
            detail="Port must be a single port (443) or range (40000-50000)",
        )
    if payload.cert_mode == "self_signed":
        cert_pem, key_pem = generate_self_signed_cert()
        payload_data["cert_pem"] = cert_pem
        payload_data["key_pem"] = key_pem

    item = HysteriaInbound(**payload_data)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.patch("/{inbound_id}", response_model=HysteriaInboundResponse)
async def update_hysteria_inbound(
    inbound_id: int,
    payload: HysteriaInboundUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(HysteriaInbound).filter(HysteriaInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Hysteria inbound not found")

    updates = payload.model_dump(exclude_unset=True)

    next_remark = updates.get("remark")
    if next_remark is not None:
        duplicate_remark = (
            db.query(HysteriaInbound)
            .filter(HysteriaInbound.remark == next_remark, HysteriaInbound.id != inbound_id)
            .first()
        )
        if duplicate_remark:
            raise HTTPException(status_code=409, detail="Hysteria inbound remark already exists")

    next_port = updates.get("port")
    if next_port is not None and not _is_valid_port_format(next_port):
        raise HTTPException(
            status_code=422,
            detail="Port must be a single port (443) or range (40000-50000)",
        )

    next_cert_mode = updates.get("cert_mode", item.cert_mode)
    cert_mode_changed = "cert_mode" in updates and updates["cert_mode"] != item.cert_mode
    should_issue_self_signed = next_cert_mode == "self_signed" and (
        cert_mode_changed or not item.cert_pem or not item.key_pem
    )
    if should_issue_self_signed:
        cert_pem, key_pem = generate_self_signed_cert()
        updates["cert_pem"] = cert_pem
        updates["key_pem"] = key_pem
    elif next_cert_mode == "self_signed":
        updates.pop("cert_pem", None)
        updates.pop("key_pem", None)

    for field, value in updates.items():
        setattr(item, field, value)

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{inbound_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_hysteria_inbound(
    inbound_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(HysteriaInbound).filter(HysteriaInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Hysteria inbound not found")

    db.delete(item)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
