from typing import Any

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
from backend.utils.crypto_utils import generate_self_signed_cert

router = APIRouter(prefix="/trojan-inbounds", tags=["Trojan Inbounds"])


def _normalize_transport_settings(raw: Any, network: str) -> dict[str, Any]:
    source = raw if isinstance(raw, dict) else {}
    normalized: dict[str, Any] = {}

    if network in {"ws", "httpupgrade", "xhttp"}:
        normalized["path"] = str(source.get("path", "/") or "/").strip() or "/"
        normalized["host"] = str(source.get("host", "") or "").strip()
    if network == "httpupgrade":
        normalized["accept_proxy"] = bool(source.get("accept_proxy", False))
    if network == "grpc":
        normalized["service_name"] = str(source.get("service_name", "") or "").strip()
        normalized["multi_mode"] = bool(source.get("multi_mode", False))
    if network == "xhttp":
        normalized["mode"] = str(source.get("mode", "auto") or "auto").strip() or "auto"
        headers = source.get("headers", {})
        normalized["headers"] = headers if isinstance(headers, dict) else {}
        extra = source.get("extra")
        if isinstance(extra, (dict, list)):
            normalized["extra"] = extra

    return normalized


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

    payload_data = payload.model_dump()
    network = str(payload_data.get("network") or "tcp").strip().lower()
    payload_data["transport_settings"] = _normalize_transport_settings(payload_data.get("transport_settings"), network)
    if payload_data.get("cert_mode") == "self_signed":
        cert_pem, key_pem = generate_self_signed_cert()
        payload_data["cert_pem"] = cert_pem
        payload_data["key_pem"] = key_pem

    item = TrojanInbound(**payload_data)
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

    next_network = str(updates.get("network") or item.network or "tcp").strip().lower()
    transport_source = updates["transport_settings"] if "transport_settings" in updates else item.transport_settings
    updates["transport_settings"] = _normalize_transport_settings(transport_source, next_network)

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
