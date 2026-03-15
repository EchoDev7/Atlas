from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.user import Admin
from backend.models.vless_inbound import VlessInbound
from backend.schemas.vless_inbound import (
    VlessInboundCreate,
    VlessInboundResponse,
    VlessInboundUpdate,
)

router = APIRouter(prefix="/vless-inbounds", tags=["VLESS Inbounds"])


@router.get("/", response_model=list[VlessInboundResponse])
async def list_vless_inbounds(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return db.query(VlessInbound).order_by(VlessInbound.id.asc()).all()


@router.post("/", response_model=VlessInboundResponse, status_code=status.HTTP_201_CREATED)
async def create_vless_inbound(
    payload: VlessInboundCreate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    duplicate_remark = db.query(VlessInbound).filter(VlessInbound.remark == payload.remark).first()
    if duplicate_remark:
        raise HTTPException(status_code=409, detail="VLESS inbound remark already exists")

    duplicate_port = db.query(VlessInbound).filter(VlessInbound.port == payload.port).first()
    if duplicate_port:
        raise HTTPException(status_code=409, detail="VLESS inbound port already exists")

    item = VlessInbound(**payload.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.patch("/{inbound_id}", response_model=VlessInboundResponse)
async def update_vless_inbound(
    inbound_id: int,
    payload: VlessInboundUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(VlessInbound).filter(VlessInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="VLESS inbound not found")

    updates = payload.model_dump(exclude_unset=True)

    next_remark = updates.get("remark")
    if next_remark is not None:
        duplicate_remark = (
            db.query(VlessInbound)
            .filter(VlessInbound.remark == next_remark, VlessInbound.id != inbound_id)
            .first()
        )
        if duplicate_remark:
            raise HTTPException(status_code=409, detail="VLESS inbound remark already exists")

    next_port = updates.get("port")
    if next_port is not None:
        duplicate_port = (
            db.query(VlessInbound)
            .filter(VlessInbound.port == next_port, VlessInbound.id != inbound_id)
            .first()
        )
        if duplicate_port:
            raise HTTPException(status_code=409, detail="VLESS inbound port already exists")

    for field, value in updates.items():
        setattr(item, field, value)

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{inbound_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vless_inbound(
    inbound_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(VlessInbound).filter(VlessInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="VLESS inbound not found")

    db.delete(item)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
