import re
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.core.routing.pbr_manager import PBRManager
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.routing_rule import RoutingRule
from backend.models.user import Admin
from backend.schemas.routing import RoutingRuleCreate, RoutingRuleResponse, RoutingRuleUpdate

router = APIRouter(prefix="/routing/rules", tags=["Routing"])


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


@router.get("", response_model=List[RoutingRuleResponse])
async def list_routing_rules(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return db.query(RoutingRule).order_by(RoutingRule.id.asc()).all()


@router.get("/{rule_id}", response_model=RoutingRuleResponse)
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


@router.post("", response_model=RoutingRuleResponse, status_code=status.HTTP_201_CREATED)
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

    rule = RoutingRule(
        rule_name=payload.rule_name,
        ingress_iface=payload.ingress_iface,
        fwmark=int(payload.fwmark),
        proxy_port=int(payload.proxy_port),
        protocol=protocol,
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


@router.put("/{rule_id}", response_model=RoutingRuleResponse)
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
    rule.status = _normalize_status(payload.status)
    rule.table_id = int(payload.fwmark)
    rule.table_name = _normalize_table_name(payload.rule_name)
    rule.updated_at = datetime.utcnow()

    db.flush()
    _apply_runtime_or_rollback(db)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
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
