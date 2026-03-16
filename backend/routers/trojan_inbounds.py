from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.trojan_inbound import TrojanInbound
from backend.models.user import Admin
from backend.schemas.trojan_inbound import (
    TrojanInboundCreate,
    TrojanInboundResponse,
    TrojanInboundUpdate,
)

router = APIRouter(prefix="/trojan-inbounds", tags=["Trojan Inbounds"])


@router.get("/", response_model=list[TrojanInboundResponse])
async def list_trojan_inbounds(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return db.query(TrojanInbound).order_by(TrojanInbound.id.asc()).all()


@router.post("/", response_model=TrojanInboundResponse, status_code=status.HTTP_201_CREATED)
async def create_trojan_inbound(
    payload: TrojanInboundCreate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    duplicate_remark = db.query(TrojanInbound).filter(TrojanInbound.remark == payload.remark).first()
    if duplicate_remark:
        raise HTTPException(status_code=409, detail="Trojan inbound remark already exists")

    duplicate_port = db.query(TrojanInbound).filter(TrojanInbound.port == payload.port).first()
    if duplicate_port:
        raise HTTPException(status_code=409, detail="Trojan inbound port already exists")

    item = TrojanInbound(**payload.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.patch("/{inbound_id}", response_model=TrojanInboundResponse)
async def update_trojan_inbound(
    inbound_id: int,
    payload: TrojanInboundUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(TrojanInbound).filter(TrojanInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Trojan inbound not found")

    updates = payload.model_dump(exclude_unset=True)

    next_remark = updates.get("remark")
    if next_remark is not None:
        duplicate_remark = (
            db.query(TrojanInbound)
            .filter(TrojanInbound.remark == next_remark, TrojanInbound.id != inbound_id)
            .first()
        )
        if duplicate_remark:
            raise HTTPException(status_code=409, detail="Trojan inbound remark already exists")

    next_port = updates.get("port")
    if next_port is not None:
        duplicate_port = (
            db.query(TrojanInbound)
            .filter(TrojanInbound.port == next_port, TrojanInbound.id != inbound_id)
            .first()
        )
        if duplicate_port:
            raise HTTPException(status_code=409, detail="Trojan inbound port already exists")

    for field, value in updates.items():
        setattr(item, field, value)

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{inbound_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_trojan_inbound(
    inbound_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(TrojanInbound).filter(TrojanInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Trojan inbound not found")

    db.delete(item)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
