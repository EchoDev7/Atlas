from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.tuic_inbound import TuicInbound
from backend.models.user import Admin
from backend.schemas.tuic_inbound import TuicInboundCreate, TuicInboundResponse, TuicInboundUpdate
from backend.utils.crypto_utils import generate_self_signed_cert

router = APIRouter(prefix="/tuic-inbounds", tags=["TUIC Inbounds"])


@router.get("/", response_model=list[TuicInboundResponse])
async def list_tuic_inbounds(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return db.query(TuicInbound).order_by(TuicInbound.id.asc()).all()


@router.post("/", response_model=TuicInboundResponse, status_code=status.HTTP_201_CREATED)
async def create_tuic_inbound(
    payload: TuicInboundCreate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    duplicate_remark = db.query(TuicInbound).filter(TuicInbound.remark == payload.remark).first()
    if duplicate_remark:
        raise HTTPException(status_code=409, detail="TUIC inbound remark already exists")

    duplicate_port = db.query(TuicInbound).filter(TuicInbound.port == payload.port).first()
    if duplicate_port:
        raise HTTPException(status_code=409, detail="TUIC inbound port already exists")

    payload_data = payload.model_dump()
    payload_data["alpn"] = "h3"
    if payload.cert_mode == "self_signed":
        cert_pem, key_pem = generate_self_signed_cert()
        payload_data["cert_pem"] = cert_pem
        payload_data["key_pem"] = key_pem

    item = TuicInbound(**payload_data)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.patch("/{inbound_id}", response_model=TuicInboundResponse)
async def update_tuic_inbound(
    inbound_id: int,
    payload: TuicInboundUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(TuicInbound).filter(TuicInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="TUIC inbound not found")

    updates = payload.model_dump(exclude_unset=True)

    next_remark = updates.get("remark")
    if next_remark is not None:
        duplicate_remark = (
            db.query(TuicInbound).filter(TuicInbound.remark == next_remark, TuicInbound.id != inbound_id).first()
        )
        if duplicate_remark:
            raise HTTPException(status_code=409, detail="TUIC inbound remark already exists")

    next_port = updates.get("port")
    if next_port is not None:
        duplicate_port = db.query(TuicInbound).filter(TuicInbound.port == next_port, TuicInbound.id != inbound_id).first()
        if duplicate_port:
            raise HTTPException(status_code=409, detail="TUIC inbound port already exists")

    updates["alpn"] = "h3"

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
async def delete_tuic_inbound(
    inbound_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(TuicInbound).filter(TuicInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="TUIC inbound not found")

    db.delete(item)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
