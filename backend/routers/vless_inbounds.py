from typing import Any

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


def _safe_int(value: Any, fallback: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback


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


def _normalize_tls_settings(raw: Any, security: str, sni: str) -> dict[str, Any] | None:
    if security not in {"tls", "reality"}:
        return None

    source = raw if isinstance(raw, dict) else {}
    alpn = str(source.get("alpn", "h2,http/1.1") or "h2,http/1.1").strip() or "h2,http/1.1"
    normalized_sni = (sni or "www.microsoft.com").strip() or "www.microsoft.com"

    if security == "tls":
        return {
            "server_name": str(source.get("server_name") or normalized_sni).strip() or normalized_sni,
            "alpn": alpn,
        }

    server_port = _safe_int(source.get("server_port"), 443)
    dest = str(source.get("dest") or f"{normalized_sni}:{server_port}").strip() or f"{normalized_sni}:{server_port}"
    return {
        "private_key": str(source.get("private_key", "") or "").strip(),
        "public_key": str(source.get("public_key", "") or "").strip(),
        "short_id": str(source.get("short_id", "") or "").strip(),
        "alpn": alpn,
        "server_port": server_port,
        "dest": dest,
    }


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

    payload_data = payload.model_dump()
    network = str(payload_data.get("network") or "tcp").strip().lower()
    security = str(payload_data.get("security") or "reality").strip().lower()
    sni = str(payload_data.get("sni") or "www.microsoft.com").strip() or "www.microsoft.com"
    payload_data["transport_settings"] = _normalize_transport_settings(payload_data.get("transport_settings"), network)
    payload_data["tls_settings"] = _normalize_tls_settings(payload_data.get("tls_settings"), security, sni)

    item = VlessInbound(**payload_data)
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

    next_network = str(updates.get("network") or item.network or "tcp").strip().lower()
    next_security = str(updates.get("security") or item.security or "reality").strip().lower()
    next_sni = str(updates.get("sni") or item.sni or "www.microsoft.com").strip() or "www.microsoft.com"

    transport_source = updates["transport_settings"] if "transport_settings" in updates else item.transport_settings
    tls_source = updates["tls_settings"] if "tls_settings" in updates else item.tls_settings
    updates["transport_settings"] = _normalize_transport_settings(transport_source, next_network)
    updates["tls_settings"] = _normalize_tls_settings(tls_source, next_security, next_sni)

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
