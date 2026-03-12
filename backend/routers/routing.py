import ipaddress
import os
import re
import socket
import subprocess
from datetime import datetime
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.core.routing.pbr_manager import PBRManager
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.routing_rule import RoutingRule
from backend.models.user import Admin
from backend.schemas.routing import RoutingRuleCreate, RoutingRuleResponse, RoutingRuleUpdate

router = APIRouter(prefix="/routing", tags=["Routing"])


def _normalize_table_name(rule_name: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", (rule_name or "").strip().lower())
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return f"atlas_pbr_{normalized or 'rule'}"


def _normalize_protocol(value: str) -> str:
    protocol = (value or "tcp").strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise HTTPException(status_code=400, detail="protocol must be 'tcp' or 'udp'")
    return protocol


def _normalize_status(value: str) -> str:
    rule_status = (value or "active").strip().lower()
    if rule_status not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="status must be 'active' or 'inactive'")
    return rule_status


def _normalize_dest_cidr(value: str | None) -> str:
    candidate = (value or "0.0.0.0/0").strip()
    if not candidate:
        candidate = "0.0.0.0/0"
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="dest_cidr must be a valid IP/CIDR") from exc
    return str(network)


def _next_available_fwmark(db: Session, start: int = 100) -> int:
    max_fwmark = db.query(func.max(RoutingRule.fwmark)).scalar()
    if max_fwmark is None:
        return int(start)
    return max(int(start), int(max_fwmark) + 1)


def _prettify_process_name(process_name: str | None, fallback: str = "Local Service") -> str:
    normalized = (process_name or "").strip().lower()
    if not normalized:
        return fallback
    if "dnstt" in normalized:
        return "DNSTT Server"
    if "sing-box" in normalized or "singbox" in normalized:
        return "Sing-box"
    if "xray" in normalized:
        return "Xray"
    if "v2ray" in normalized:
        return "V2Ray"
    if "openvpn" in normalized:
        return "OpenVPN"
    if "wireguard" in normalized or normalized.startswith("wg"):
        return "WireGuard"
    return process_name.strip() if process_name else fallback


def _collect_proxy_ports_with_psutil() -> list[dict[str, Any]]:
    try:
        import psutil  # type: ignore
    except Exception:
        return []

    options: dict[int, str] = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "LISTEN" or not conn.laddr:
            continue
        host = str(conn.laddr.ip or "")
        if host not in {"127.0.0.1", "0.0.0.0", "::1", "::", ""}:
            continue
        port = int(conn.laddr.port or 0)
        if port <= 0:
            continue
        process_name = None
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except Exception:
                process_name = None
        label = f"{port} ({_prettify_process_name(process_name)})"
        options[port] = label

    return [{"port": port, "label": options[port]} for port in sorted(options.keys())]


def _collect_proxy_ports_with_ss() -> list[dict[str, Any]]:
    result = subprocess.run(
        ["ss", "-ltnup"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []

    options: dict[int, str] = {}
    for line in (result.stdout or "").splitlines():
        normalized = line.strip()
        if not normalized or normalized.lower().startswith("netid"):
            continue

        parts = normalized.split()
        if len(parts) < 5:
            continue
        local_addr = parts[4]
        host = ""
        port = 0
        try:
            if local_addr.startswith("[") and "]:" in local_addr:
                host, port_text = local_addr.rsplit("]:", 1)
                host = host.lstrip("[")
            else:
                host, port_text = local_addr.rsplit(":", 1)
            port = int(port_text)
        except Exception:
            continue

        if host not in {"127.0.0.1", "0.0.0.0", "::1", "::", "*"}:
            continue
        if port <= 0:
            continue

        process_name = None
        users_match = re.search(r'users:\(\("([^"]+)"', normalized)
        if users_match:
            process_name = users_match.group(1)
        label = f"{port} ({_prettify_process_name(process_name)})"
        options[port] = label

    return [{"port": port, "label": options[port]} for port in sorted(options.keys())]


def _apply_runtime_or_rollback(db: Session) -> None:
    result = PBRManager(db=db).apply_all_active_rules()
    if not result.get("success"):
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "message": "routing rules saved but kernel apply failed",
                "errors": result.get("errors", []),
            },
        )


@router.get("/interfaces", response_model=List[str])
async def list_routing_interfaces(
    current_user: Admin = Depends(get_current_user),
):
    _ = current_user
    static_wildcards = ["any", "tun+", "wg+", "ppp+"]
    unified_interfaces = list(static_wildcards)
    seen = set(static_wildcards)

    try:
        live_interfaces = sorted(
            iface
            for iface in os.listdir("/sys/class/net/")
            if iface and iface != "lo"
        )
    except OSError:
        return unified_interfaces

    for iface in live_interfaces:
        if iface in seen:
            continue
        seen.add(iface)
        unified_interfaces.append(iface)

    return unified_interfaces


@router.get("/proxy-ports")
async def list_proxy_ports(
    current_user: Admin = Depends(get_current_user),
):
    _ = current_user
    options = _collect_proxy_ports_with_psutil()
    if not options:
        options = _collect_proxy_ports_with_ss()
    return options


@router.get("/next-fwmark")
async def get_next_fwmark(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return {"fwmark": _next_available_fwmark(db)}


@router.get("/rules", response_model=List[RoutingRuleResponse])
async def list_routing_rules(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return db.query(RoutingRule).order_by(RoutingRule.id.asc()).all()


@router.post("/rules/reapply")
async def reapply_routing_rules(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    try:
        result = PBRManager(db=db).apply_all_active_rules()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Failed to sync routing rules with kernel",
                "error": str(exc),
            },
        ) from exc

    if not result.get("success"):
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Failed to sync routing rules with kernel",
                "errors": result.get("errors", []),
                "applied_rules": result.get("applied_rules", []),
            },
        )

    return {
        "success": True,
        "message": "Routing rules synced with kernel successfully",
        "applied_rules": result.get("applied_rules", []),
    }


@router.get("/rules/{rule_id}", response_model=RoutingRuleResponse)
async def get_routing_rule(
    rule_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    rule = db.query(RoutingRule).filter(RoutingRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Routing rule not found")
    return rule


@router.post("/rules", response_model=RoutingRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_routing_rule(
    payload: RoutingRuleCreate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user

    existing_name = db.query(RoutingRule).filter(RoutingRule.rule_name == payload.rule_name).first()
    if existing_name:
        raise HTTPException(status_code=400, detail="rule_name already exists")

    existing_mark = db.query(RoutingRule).filter(RoutingRule.fwmark == payload.fwmark).first()
    if existing_mark:
        raise HTTPException(status_code=400, detail="fwmark already exists")

    protocol = _normalize_protocol(payload.protocol)
    rule_status = _normalize_status(payload.status)
    dest_cidr = _normalize_dest_cidr(payload.dest_cidr)
    description = (payload.description or "").strip() or None

    rule = RoutingRule(
        rule_name=payload.rule_name,
        ingress_iface=payload.ingress_iface,
        fwmark=int(payload.fwmark),
        proxy_port=int(payload.proxy_port),
        protocol=protocol,
        dest_cidr=dest_cidr,
        description=description,
        table_id=int(payload.fwmark),
        table_name=_normalize_table_name(payload.rule_name),
        status=rule_status,
    )
    db.add(rule)
    db.flush()

    _apply_runtime_or_rollback(db)
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/rules/{rule_id}", response_model=RoutingRuleResponse)
async def update_routing_rule(
    rule_id: int,
    payload: RoutingRuleUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    rule = db.query(RoutingRule).filter(RoutingRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Routing rule not found")

    duplicate_name = (
        db.query(RoutingRule)
        .filter(RoutingRule.rule_name == payload.rule_name)
        .filter(RoutingRule.id != rule_id)
        .first()
    )
    if duplicate_name:
        raise HTTPException(status_code=400, detail="rule_name already exists")

    duplicate_mark = (
        db.query(RoutingRule)
        .filter(RoutingRule.fwmark == payload.fwmark)
        .filter(RoutingRule.id != rule_id)
        .first()
    )
    if duplicate_mark:
        raise HTTPException(status_code=400, detail="fwmark already exists")

    rule.rule_name = payload.rule_name
    rule.ingress_iface = payload.ingress_iface
    rule.fwmark = int(payload.fwmark)
    rule.proxy_port = int(payload.proxy_port)
    rule.protocol = _normalize_protocol(payload.protocol)
    rule.dest_cidr = _normalize_dest_cidr(payload.dest_cidr)
    rule.description = (payload.description or "").strip() or None
    rule.status = _normalize_status(payload.status)
    rule.table_id = int(payload.fwmark)
    rule.table_name = _normalize_table_name(payload.rule_name)
    rule.updated_at = datetime.utcnow()

    db.flush()
    _apply_runtime_or_rollback(db)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_routing_rule(
    rule_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    rule = db.query(RoutingRule).filter(RoutingRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Routing rule not found")

    db.delete(rule)
    db.flush()

    _apply_runtime_or_rollback(db)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
