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
