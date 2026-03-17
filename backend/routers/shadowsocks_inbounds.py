from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.shadowsocks_inbound import ShadowsocksInbound
from backend.models.user import Admin
from backend.schemas.shadowsocks_inbound import (
    ShadowsocksInboundCreate,
    ShadowsocksMethod,
    ShadowsocksInboundResponse,
    ShadowsocksInboundUpdate,
)
from backend.utils.crypto_utils import generate_ss2022_psk

router = APIRouter(prefix="/shadowsocks-inbounds", tags=["Shadowsocks Inbounds"])


@router.get("/", response_model=list[ShadowsocksInboundResponse])
async def list_shadowsocks_inbounds(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return db.query(ShadowsocksInbound).order_by(ShadowsocksInbound.id.asc()).all()


@router.get("/generate-psk")
async def generate_shadowsocks_psk(
    method: ShadowsocksMethod = Query(..., description="Shadowsocks-2022 method"),
    current_user: Admin = Depends(get_current_user),
):
    _ = current_user
    try:
        return {"psk": generate_ss2022_psk(method)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/", response_model=ShadowsocksInboundResponse, status_code=status.HTTP_201_CREATED)
async def create_shadowsocks_inbound(
    payload: ShadowsocksInboundCreate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    duplicate_remark = db.query(ShadowsocksInbound).filter(ShadowsocksInbound.remark == payload.remark).first()
    if duplicate_remark:
        raise HTTPException(status_code=409, detail="Shadowsocks inbound remark already exists")

    duplicate_port = db.query(ShadowsocksInbound).filter(ShadowsocksInbound.port == payload.port).first()
    if duplicate_port:
        raise HTTPException(status_code=409, detail="Shadowsocks inbound port already exists. Please choose another port.")

    item = ShadowsocksInbound(**payload.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.patch("/{inbound_id}", response_model=ShadowsocksInboundResponse)
async def update_shadowsocks_inbound(
    inbound_id: int,
    payload: ShadowsocksInboundUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(ShadowsocksInbound).filter(ShadowsocksInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Shadowsocks inbound not found")

    updates = payload.model_dump(exclude_unset=True)

    next_remark = updates.get("remark")
    if next_remark is not None:
        duplicate_remark = (
            db.query(ShadowsocksInbound)
            .filter(ShadowsocksInbound.remark == next_remark, ShadowsocksInbound.id != inbound_id)
            .first()
        )
        if duplicate_remark:
            raise HTTPException(status_code=409, detail="Shadowsocks inbound remark already exists")

    next_port = updates.get("port")
    if next_port is not None:
        duplicate_port = (
            db.query(ShadowsocksInbound)
            .filter(ShadowsocksInbound.port == next_port, ShadowsocksInbound.id != inbound_id)
            .first()
        )
        if duplicate_port:
            raise HTTPException(status_code=409, detail="Shadowsocks inbound port already exists. Please choose another port.")

    for field, value in updates.items():
        setattr(item, field, value)

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{inbound_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_shadowsocks_inbound(
    inbound_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    item = db.query(ShadowsocksInbound).filter(ShadowsocksInbound.id == inbound_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Shadowsocks inbound not found")

    db.delete(item)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
