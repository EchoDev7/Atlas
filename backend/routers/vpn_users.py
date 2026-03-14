# Atlas — VPN Users router (Phase 2 Enhancements)
# Multi-protocol user management with limits enforcement

from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, asc, desc, func, or_
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import logging

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.user import Admin
from backend.models.vpn_user import VPNUser, VPNConfig
from backend.schemas.vpn_user import (
    VPNUserCreate,
    VPNUserUpdate,
    VPNUserResponse,
    VPNUserDetailResponse,
    VPNUserListResponse,
    VPNUserCredentials,
    VPNConfigResponse,
    VPNConfigFileResponse,
    VPNConfigRevokeRequest,
    PasswordChangeRequest,
    PasswordResetResponse
)
from backend.services.scheduler_service import get_scheduler
from backend.services.protocols.registry import protocol_registry
from backend.models.general_settings import GeneralSettings
from backend.models.openvpn_settings import OpenVPNSettings
from backend.models.wireguard_settings import WireGuardSettings
from backend.core.config import IPSEC_DEFAULT_PSK, IPSEC_PSK_ENV_KEY
from backend.services.auth_service import get_password_hash
from backend.services.audit_service import extract_client_ip, record_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["VPN Users"])

# Initialize OpenVPN manager
openvpn_service = protocol_registry.get("openvpn")
wireguard_service = protocol_registry.get("wireguard")
l2tp_service = protocol_registry.get("l2tp")

# Fallback runtime accounting cache keyed by username.
# It captures the latest active-session counters to preserve traffic totals
# across reconnects if OpenVPN disconnect hooks fail to write usage.
_runtime_usage_cache: Dict[str, Dict[str, int]] = {}


def _get_or_create_general_settings(db: Session) -> GeneralSettings:
    settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    if settings:
        return settings
    settings = GeneralSettings()
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings


def _get_or_create_openvpn_settings(db: Session) -> OpenVPNSettings:
    settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
    if settings:
        return settings
    settings = OpenVPNSettings()
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings


def _validate_required_settings(db: Session) -> None:
    """Stage 1: The Gatekeeper - Validate required settings before config generation."""
    general = _get_or_create_general_settings(db)
    openvpn = _get_or_create_openvpn_settings(db)
    
    missing = openvpn_service.validate_readiness(general, openvpn)
    
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot generate config. Missing required fields: {', '.join(missing)}."
        )


def _sync_legacy_accounting_fields(user: VPNUser) -> None:
    """Keep legacy fields populated for backward compatibility."""
    if user.traffic_limit_bytes is not None:
        user.data_limit_gb = user.traffic_limit_bytes / float(1024 ** 3)
    elif user.data_limit_gb is not None:
        user.traffic_limit_bytes = int(float(user.data_limit_gb) * (1024 ** 3))

    if user.access_expires_at is not None:
        user.expiry_date = user.access_expires_at
    elif user.expiry_date is not None:
        user.access_expires_at = user.expiry_date

    user.max_devices = user.effective_max_concurrent_connections


def _sync_openvpn_auth_db_snapshot() -> None:
    """Best-effort sync of auth DB snapshot consumed by OpenVPN scripts."""
    try:
        sync_result = openvpn_service.sync_auth_database_snapshot()
        if not sync_result.get("success"):
            logger.warning("OpenVPN auth DB sync warning: %s", sync_result.get("message"))
    except Exception as exc:
        logger.warning("Failed to sync OpenVPN auth DB snapshot: %s", exc)


def _disconnect_user_across_protocols(username: str) -> Dict[str, Dict[str, Any]]:
    """Best-effort kill switch across supported runtime protocols."""
    openvpn_result = openvpn_service.stop_client(username)
    wireguard_result = wireguard_service.stop_client(username)
    l2tp_result = l2tp_service.stop_client(username)
    logger.warning(
        "Kill-switch executed for user=%s openvpn_success=%s wireguard_success=%s l2tp_success=%s",
        username,
        bool(openvpn_result.get("success")),
        bool(wireguard_result.get("success")),
        bool(l2tp_result.get("success")),
    )
    return {
        "openvpn": openvpn_result,
        "wireguard": wireguard_result,
        "l2tp": l2tp_result,
    }


def _resolve_ipsec_psk() -> str:
    return str(__import__("os").getenv(IPSEC_PSK_ENV_KEY) or IPSEC_DEFAULT_PSK)


def _get_wireguard_settings(db: Session) -> WireGuardSettings:
    settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
    if not settings:
        raise HTTPException(status_code=400, detail="WireGuard server settings are not configured")
    return settings


def _sync_wireguard_users_runtime(db: Session) -> None:
    sync_result = wireguard_service.sync_users_runtime(db)
    if not sync_result.get("success"):
        raise HTTPException(status_code=500, detail=sync_result.get("message", "Failed to synchronize WireGuard peers"))


def _reinject_existing_wireguard_peer(db: Session, username: str, public_key: str, allocated_ip: str) -> None:
    """Re-add an existing peer to live interface before full sync, without key regeneration."""
    reinject_result = wireguard_service.reinject_existing_peer(
        db=db,
        username=username,
        public_key=public_key,
        allocated_ip=allocated_ip,
    )
    if not reinject_result.get("success"):
        raise HTTPException(
            status_code=500,
            detail=f"Failed to re-inject WireGuard peer for {username}: {reinject_result.get('message', 'unknown error')}",
        )

    logger.info(
        "Re-injected existing WireGuard peer for user=%s on interface=%s allowed_ips=%s",
        username,
        reinject_result.get("interface_name"),
        reinject_result.get("allowed_ips"),
    )


def _ensure_wireguard_identity_for_user(db: Session, user: VPNUser) -> None:
    if (user.wg_private_key or "").strip() and (user.wg_public_key or "").strip() and (user.wg_allocated_ip or "").strip():
        return

    settings = _get_wireguard_settings(db)
    existing_ips = [
        str(ip_value)
        for (ip_value,) in db.query(VPNUser.wg_allocated_ip)
        .filter(VPNUser.id != user.id)
        .filter(VPNUser.wg_allocated_ip.isnot(None))
        .all()
    ]

    private_key, public_key, allocated_ip = wireguard_service.generate_user_identity(
        address_range=settings.address_range,
        existing_allocated_ips=existing_ips,
    )
    user.wg_private_key = private_key
    user.wg_public_key = public_key
    user.wg_allocated_ip = allocated_ip


def _ensure_wireguard_config_record(user: VPNUser, db: Session) -> VPNConfig:
    existing = next((c for c in user.configs if c.protocol == "wireguard" and c.is_active), None)
    if existing:
        existing.wireguard_public_key = user.wg_public_key
        existing.wireguard_allowed_ips = f"{user.wg_allocated_ip}/32" if user.wg_allocated_ip else None
        existing.updated_at = datetime.utcnow()
        return existing

    wireguard_config = VPNConfig(
        user_id=user.id,
        protocol="wireguard",
        wireguard_public_key=user.wg_public_key,
        wireguard_allowed_ips=f"{user.wg_allocated_ip}/32" if user.wg_allocated_ip else None,
        is_active=True,
    )
    db.add(wireguard_config)
    return wireguard_config


def _get_openvpn_runtime_stats() -> Tuple[Dict[str, Dict[str, int]], bool]:
    """Fetch live OpenVPN session stats grouped by username."""
    try:
        sessions = openvpn_service.get_active_sessions()
    except Exception as exc:
        logger.warning("Failed to read OpenVPN active sessions for user list: %s", exc)
        return {}, False

    stats: Dict[str, Dict[str, int]] = {}
    for session in sessions:
        username = str(session.get("username") or "").strip()
        if not username:
            continue

        item = stats.setdefault(
            username,
            {"connections": 0, "bytes_sent": 0, "bytes_received": 0},
        )
        item["connections"] += 1
        item["bytes_sent"] += max(0, int(session.get("bytes_sent") or 0))
        item["bytes_received"] += max(0, int(session.get("bytes_received") or 0))

    return stats, True


def _get_wireguard_online_usernames(db: Session, online_window_seconds: int = 90) -> Set[str]:
    """Return usernames currently online via WireGuard handshake telemetry."""
    try:
        return wireguard_service.get_online_usernames(db, online_window_seconds=online_window_seconds)
    except Exception as exc:
        logger.warning("Failed to read WireGuard runtime dump for user list: %s", exc)
        return set()


def _get_ppp_online_usernames() -> Set[str]:
    online: Set[str] = set()
    for service in (l2tp_service,):
        try:
            sessions = service.get_active_sessions()
        except Exception as exc:
            logger.warning("Failed to read PPP runtime for protocol %s: %s", service.protocol_name, exc)
            continue
        for session in sessions:
            username = str(session.get("username") or "").strip()
            if username:
                online.add(username)
    return online


def _get_ppp_runtime_stats() -> Dict[str, Dict[str, int]]:
    stats: Dict[str, Dict[str, int]] = {}
    for service in (l2tp_service,):
        try:
            sessions = service.get_active_sessions()
        except Exception as exc:
            logger.warning("Failed to read PPP sessions for protocol %s: %s", service.protocol_name, exc)
            continue
        for session in sessions:
            username = str(session.get("username") or "").strip()
            if not username:
                continue
            item = stats.setdefault(
                username,
                {"connections": 0, "bytes_sent": 0, "bytes_received": 0},
            )
            item["connections"] += 1
            item["bytes_sent"] += max(0, int(session.get("bytes_sent") or 0))
            item["bytes_received"] += max(0, int(session.get("bytes_received") or 0))
    return stats


def _apply_runtime_disconnect_fallback_accounting(
    db: Session,
    runtime_stats: Dict[str, Dict[str, int]],
    runtime_available: bool,
    current_page_users: List[VPNUser],
) -> None:
    """
    Persist previous live session counters when a reconnect/disconnect is observed.

    This is a defensive fallback for environments where client-disconnect hook
    accounting is not consistently written into SQLite.
    """
    if not runtime_available:
        return

    users_by_username: Dict[str, VPNUser] = {str(user.username): user for user in current_page_users}
    known_usernames = set(runtime_stats.keys()) | set(_runtime_usage_cache.keys())

    for username in known_usernames:
        live = runtime_stats.get(username, {})
        live_connections = max(0, int(live.get("connections") or 0))
        live_sent = max(0, int(live.get("bytes_sent") or 0))
        live_received = max(0, int(live.get("bytes_received") or 0))

        previous = _runtime_usage_cache.get(username)
        should_finalize_previous = False
        if previous and int(previous.get("connections") or 0) > 0:
            prev_sent = max(0, int(previous.get("bytes_sent") or 0))
            prev_received = max(0, int(previous.get("bytes_received") or 0))
            prev_connections = max(0, int(previous.get("connections") or 0))

            if live_connections == 0:
                should_finalize_previous = True
            elif (
                live_connections < prev_connections
                or live_sent < prev_sent
                or live_received < prev_received
            ):
                # Session counters dropped while user is still online: treat as reconnect.
                should_finalize_previous = True

        if should_finalize_previous and previous:
            user = users_by_username.get(username)
            if user is None:
                user = db.query(VPNUser).filter(VPNUser.username == username).first()

            if user is not None:
                prev_sent = max(0, int(previous.get("bytes_sent") or 0))
                prev_received = max(0, int(previous.get("bytes_received") or 0))
                base_sent = max(0, int(previous.get("base_sent") or 0))
                base_received = max(0, int(previous.get("base_received") or 0))

                expected_sent = base_sent + prev_sent
                expected_received = base_received + prev_received
                current_sent = max(0, int(user.total_bytes_sent or 0))
                current_received = max(0, int(user.total_bytes_received or 0))

                # If hook accounting already applied, these deltas will be zero.
                missing_sent = max(0, expected_sent - current_sent)
                missing_received = max(0, expected_received - current_received)

                if missing_sent or missing_received:
                    user.total_bytes_sent = current_sent + missing_sent
                    user.total_bytes_received = current_received + missing_received
                    accumulated_total = max(0, int(user.traffic_used_bytes or 0)) + missing_sent + missing_received
                    user.traffic_used_bytes = max(
                        accumulated_total,
                        int(user.total_bytes_sent or 0) + int(user.total_bytes_received or 0),
                    )
                    user.updated_at = datetime.utcnow()

        if live_connections > 0:
            user_for_baseline = users_by_username.get(username)
            if user_for_baseline is None:
                user_for_baseline = db.query(VPNUser).filter(VPNUser.username == username).first()

            if previous is None or should_finalize_previous:
                base_sent = max(0, int(getattr(user_for_baseline, "total_bytes_sent", 0) or 0))
                base_received = max(0, int(getattr(user_for_baseline, "total_bytes_received", 0) or 0))
            else:
                base_sent = max(0, int(previous.get("base_sent") or 0))
                base_received = max(0, int(previous.get("base_received") or 0))

            _runtime_usage_cache[username] = {
                "connections": live_connections,
                "bytes_sent": live_sent,
                "bytes_received": live_received,
                "base_sent": base_sent,
                "base_received": base_received,
            }
        else:
            _runtime_usage_cache.pop(username, None)

    db.flush()


def _apply_runtime_metrics_to_user_dict(
    user_dict: Dict[str, Any],
    runtime_stats: Dict[str, Dict[str, int]],
    runtime_available: bool,
    wireguard_online_usernames: Optional[Set[str]] = None,
    ppp_online_usernames: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Overlay live session/traffic metrics on top of persisted DB values."""
    wireguard_online = set(wireguard_online_usernames or set())
    ppp_online = set(ppp_online_usernames or set())
    username = str(user_dict.get("username") or "").strip()
    is_wireguard_online = username in wireguard_online
    is_ppp_online = username in ppp_online

    if not runtime_available:
        is_openvpn_online = False
        persisted_online = int(user_dict.get("current_connections") or 0) > 0
        user_dict["openvpn_online"] = is_openvpn_online
        user_dict["wireguard_online"] = is_wireguard_online
        user_dict["ppp_online"] = is_ppp_online
        user_dict["is_online"] = bool(persisted_online or is_wireguard_online or is_ppp_online)
        return user_dict

    user_stats = runtime_stats.get(username, {})
    live_connections = max(0, int(user_stats.get("connections") or 0))
    live_sent = max(0, int(user_stats.get("bytes_sent") or 0))
    live_received = max(0, int(user_stats.get("bytes_received") or 0))
    is_openvpn_online = live_connections > 0

    db_sent = max(0, int(user_dict.get("total_bytes_sent") or 0))
    db_received = max(0, int(user_dict.get("total_bytes_received") or 0))

    total_sent = db_sent + live_sent
    total_received = db_received + live_received
    effective_total_bytes = max(
        max(0, int(user_dict.get("traffic_used_bytes") or 0)),
        total_sent + total_received,
    )

    persisted_connections = max(0, int(user_dict.get("current_connections") or 0))
    effective_connections = max(live_connections, persisted_connections)
    user_dict["current_connections"] = effective_connections
    user_dict["openvpn_online"] = is_openvpn_online
    user_dict["wireguard_online"] = is_wireguard_online
    user_dict["ppp_online"] = is_ppp_online
    user_dict["is_online"] = bool(effective_connections > 0 or is_wireguard_online or is_ppp_online)
    user_dict["total_bytes_sent"] = total_sent
    user_dict["total_bytes_received"] = total_received
    user_dict["traffic_used_bytes"] = effective_total_bytes
    user_dict["total_gb_used"] = effective_total_bytes / float(1024 ** 3)

    limit_bytes = user_dict.get("traffic_limit_bytes")
    if limit_bytes in {None, 0}:
        user_dict["data_usage_percentage"] = 0.0
    else:
        user_dict["data_usage_percentage"] = min(100.0, (effective_total_bytes / float(limit_bytes)) * 100)

    max_connections = max(1, int(user_dict.get("max_concurrent_connections") or 1))
    user_dict["is_connection_limit_exceeded"] = effective_connections > max_connections

    return user_dict


@router.get("", response_model=VPNUserListResponse)
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    search: str = Query("", max_length=100),
    status_filter: str = Query("all", pattern="^(all|active|expired|data_limited|disabled)$"),
    sort_by: str = Query("created_at", pattern="^(created_at|username|expiry_date|traffic_used)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of VPN users with pagination, search, filters, and sorting."""
    _ = current_user
    now = datetime.utcnow()

    query = db.query(VPNUser)

    search_term = search.strip()
    if search_term:
        query = query.filter(VPNUser.username.ilike(f"%{search_term}%"))

    expiry_expr = func.coalesce(VPNUser.access_expires_at, VPNUser.expiry_date)
    traffic_limit_expr = func.coalesce(
        VPNUser.traffic_limit_bytes,
        VPNUser.data_limit_gb * float(1024 ** 3),
    )
    traffic_used_expr = func.coalesce(
        VPNUser.traffic_used_bytes,
        VPNUser.total_bytes_sent + VPNUser.total_bytes_received,
        0,
    )

    expired_condition = or_(
        VPNUser.is_expired.is_(True),
        and_(expiry_expr.isnot(None), expiry_expr < now),
    )
    data_limited_condition = or_(
        VPNUser.is_data_limit_exceeded.is_(True),
        and_(
            traffic_limit_expr.isnot(None),
            traffic_limit_expr > 0,
            traffic_used_expr >= traffic_limit_expr,
        ),
    )

    if status_filter == "active":
        query = query.filter(
            VPNUser.is_enabled.is_(True),
            ~expired_condition,
            ~data_limited_condition,
        )
    elif status_filter == "expired":
        query = query.filter(expired_condition)
    elif status_filter == "data_limited":
        query = query.filter(data_limited_condition)
    elif status_filter == "disabled":
        query = query.filter(VPNUser.is_enabled.is_(False))

    sort_ascending = sort_order == "asc"
    if sort_by == "expiry_date":
        query = query.order_by(
            asc(expiry_expr.is_(None)),
            asc(expiry_expr) if sort_ascending else desc(expiry_expr),
            asc(VPNUser.username),
        )
    elif sort_by == "traffic_used":
        query = query.order_by(
            asc(traffic_used_expr) if sort_ascending else desc(traffic_used_expr),
            asc(VPNUser.username),
        )
    elif sort_by == "username":
        query = query.order_by(asc(VPNUser.username) if sort_ascending else desc(VPNUser.username))
    else:
        query = query.order_by(asc(VPNUser.created_at) if sort_ascending else desc(VPNUser.created_at))

    total = query.count()
    users = query.offset(skip).limit(limit).all()
    runtime_stats, runtime_available = _get_openvpn_runtime_stats()
    ppp_runtime_stats = _get_ppp_runtime_stats()
    for username, ppp_item in ppp_runtime_stats.items():
        merged = runtime_stats.setdefault(
            username,
            {"connections": 0, "bytes_sent": 0, "bytes_received": 0},
        )
        merged["connections"] += max(0, int(ppp_item.get("connections") or 0))
        merged["bytes_sent"] += max(0, int(ppp_item.get("bytes_sent") or 0))
        merged["bytes_received"] += max(0, int(ppp_item.get("bytes_received") or 0))
    wireguard_online_usernames = _get_wireguard_online_usernames(db)
    ppp_online_usernames = _get_ppp_online_usernames()
    _apply_runtime_disconnect_fallback_accounting(db, runtime_stats, runtime_available, users)
    
    user_responses = []
    for user in users:
        user_dict = VPNUserResponse.from_orm(user).dict()
        user_dict = _apply_runtime_metrics_to_user_dict(
            user_dict,
            runtime_stats,
            runtime_available,
            wireguard_online_usernames=wireguard_online_usernames,
            ppp_online_usernames=ppp_online_usernames,
        )
        user_responses.append(VPNUserResponse(**user_dict))
    
    return VPNUserListResponse(
        users=user_responses,
        total=total,
        page=skip // limit + 1,
        page_size=limit
    )


@router.get("/runtime")
async def list_users_runtime(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fast runtime snapshot for live users page refresh (online + traffic)."""
    users = db.query(VPNUser).all()
    runtime_stats, runtime_available = _get_openvpn_runtime_stats()
    ppp_runtime_stats = _get_ppp_runtime_stats()
    for username, ppp_item in ppp_runtime_stats.items():
        merged = runtime_stats.setdefault(
            username,
            {"connections": 0, "bytes_sent": 0, "bytes_received": 0},
        )
        merged["connections"] += max(0, int(ppp_item.get("connections") or 0))
        merged["bytes_sent"] += max(0, int(ppp_item.get("bytes_sent") or 0))
        merged["bytes_received"] += max(0, int(ppp_item.get("bytes_received") or 0))
    wireguard_online_usernames = _get_wireguard_online_usernames(db)
    ppp_online_usernames = _get_ppp_online_usernames()
    _apply_runtime_disconnect_fallback_accounting(db, runtime_stats, runtime_available, users)

    runtime_users: List[Dict[str, Any]] = []
    for user in users:
        stats = runtime_stats.get(str(user.username), {})
        live_connections = max(0, int(stats.get("connections") or 0))
        live_sent = max(0, int(stats.get("bytes_sent") or 0))
        live_received = max(0, int(stats.get("bytes_received") or 0))

        db_sent = max(0, int(user.total_bytes_sent or 0))
        db_received = max(0, int(user.total_bytes_received or 0))
        total_sent = db_sent + live_sent
        total_received = db_received + live_received
        effective_total_bytes = max(
            max(0, int(user.traffic_used_bytes or 0)),
            total_sent + total_received,
        )

        limit_bytes = user.effective_traffic_limit_bytes
        if limit_bytes in {None, 0}:
            data_usage_percentage = 0.0
        else:
            data_usage_percentage = min(100.0, (effective_total_bytes / float(limit_bytes)) * 100)

        persisted_connections = max(0, int(user.current_connections or 0))
        effective_connections = max(live_connections, persisted_connections)
        is_openvpn_online = live_connections > 0
        is_wireguard_online = str(user.username or "").strip() in wireguard_online_usernames
        is_ppp_online = str(user.username or "").strip() in ppp_online_usernames

        runtime_users.append(
            {
                "id": user.id,
                "username": user.username,
                "current_connections": effective_connections,
                "openvpn_online": bool(is_openvpn_online),
                "wireguard_online": bool(is_wireguard_online),
                "ppp_online": bool(is_ppp_online),
                "is_online": bool(effective_connections > 0 or is_wireguard_online or is_ppp_online),
                "total_bytes_sent": total_sent,
                "total_bytes_received": total_received,
                "traffic_used_bytes": effective_total_bytes,
                "total_gb_used": effective_total_bytes / float(1024 ** 3),
                "data_usage_percentage": data_usage_percentage,
                "is_data_limit_exceeded": bool(limit_bytes is not None and effective_total_bytes >= limit_bytes),
                "updated_at": datetime.utcnow().isoformat(),
            }
        )

    return {
        "runtime_available": runtime_available,
        "generated_at": datetime.utcnow().isoformat(),
        "users": runtime_users,
    }


@router.get("/{user_id}", response_model=VPNUserDetailResponse)
async def get_user(
    user_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific user"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    runtime_stats, runtime_available = _get_openvpn_runtime_stats()
    ppp_runtime_stats = _get_ppp_runtime_stats()
    for username, ppp_item in ppp_runtime_stats.items():
        merged = runtime_stats.setdefault(
            username,
            {"connections": 0, "bytes_sent": 0, "bytes_received": 0},
        )
        merged["connections"] += max(0, int(ppp_item.get("connections") or 0))
        merged["bytes_sent"] += max(0, int(ppp_item.get("bytes_sent") or 0))
        merged["bytes_received"] += max(0, int(ppp_item.get("bytes_received") or 0))
    wireguard_online_usernames = _get_wireguard_online_usernames(db)
    ppp_online_usernames = _get_ppp_online_usernames()
    _apply_runtime_disconnect_fallback_accounting(db, runtime_stats, runtime_available, [user])
    user_dict = VPNUserDetailResponse.from_orm(user).dict()
    user_dict = _apply_runtime_metrics_to_user_dict(
        user_dict,
        runtime_stats,
        runtime_available,
        wireguard_online_usernames=wireguard_online_usernames,
        ppp_online_usernames=ppp_online_usernames,
    )
    return VPNUserDetailResponse(**user_dict)


@router.post("/{user_id}/disconnect")
async def disconnect_user_sessions(
    user_id: int,
    protocol: str = "openvpn",
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disconnect active sessions for a user using the selected protocol plugin."""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        manager = protocol_registry.get(protocol)
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Unsupported protocol: {protocol}")

    result = manager.kill_user(user.username)
    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("message") or "Failed to disconnect user")

    user.refresh_limit_flags(datetime.utcnow())
    user.updated_at = datetime.utcnow()
    try:
        if protocol == "wireguard":
            _sync_wireguard_users_runtime(db)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to synchronize protocol revocation: {exc}") from exc
    _sync_openvpn_auth_db_snapshot()

    logger.info(
        "User %s disconnected via %s by admin %s",
        user.username,
        protocol,
        current_user.username,
    )

    return {
        "success": True,
        "user_id": user.id,
        "username": user.username,
        "protocol": protocol,
        "message": result.get("message") or f"Disconnected active sessions for {user.username}",
    }


@router.post("", response_model=VPNUserCredentials, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: VPNUserCreate,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new VPN user with optional OpenVPN config.
    Username and password are auto-generated if not provided.
    """
    # Generate username if not provided
    username = user_data.username
    if not username:
        # Generate random username
        while True:
            username = VPNUser.generate_random_username()
            existing = db.query(VPNUser).filter(VPNUser.username == username).first()
            if not existing:
                break
    else:
        # Check if username already exists
        existing = db.query(VPNUser).filter(VPNUser.username == username).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
    
    # Generate password if not provided
    plain_password = user_data.password
    if not plain_password:
        plain_password = VPNUser.generate_secure_password()
    
    # Hash password
    hashed_password = get_password_hash(plain_password)
    enable_openvpn = bool(user_data.enable_openvpn)
    enable_wireguard = bool(user_data.enable_wireguard)
    enable_l2tp = bool(user_data.enable_l2tp)
    ppp_password = str(user_data.ppp_password or "").strip() or plain_password
    
    # Create user
    new_user = VPNUser(
        username=username,
        password=hashed_password,
        description=user_data.description,
        data_limit_gb=user_data.data_limit_gb,
        traffic_limit_bytes=user_data.traffic_limit_bytes,
        traffic_used_bytes=user_data.traffic_used_bytes,
        expiry_date=user_data.expiry_date,
        access_start_at=user_data.access_start_at,
        access_expires_at=user_data.access_expires_at,
        max_devices=user_data.max_devices,
        max_concurrent_connections=user_data.max_concurrent_connections,
        enable_openvpn=enable_openvpn,
        enable_l2tp=enable_l2tp,
        ppp_password=ppp_password,
        created_by=current_user.id
    )
    _sync_legacy_accounting_fields(new_user)
    new_user.refresh_limit_flags(datetime.utcnow())
    
    db.add(new_user)
    db.flush()  # Get user ID
    
    # Unified user architecture with selective protocol generation.
    try:
        if enable_openvpn:
            cert_result = openvpn_service.create_client_certificate(username)
            cert_success = bool(cert_result.get("success"))
            if not cert_success:
                cert_path = str(cert_result.get("cert_path") or "").strip()
                key_path = str(cert_result.get("key_path") or "").strip()
                cert_success = bool(cert_path and key_path and Path(cert_path).exists() and Path(key_path).exists())

            if not cert_success:
                cert_error = cert_result.get("message") or "unknown error"
                raise HTTPException(status_code=500, detail=f"OpenVPN certificate provisioning failed for '{username}': {cert_error}")

            openvpn_config = VPNConfig(
                user_id=new_user.id,
                protocol="openvpn",
                certificate_cn=username,
                certificate_issued_at=datetime.utcnow(),
                is_active=True,
            )
            db.add(openvpn_config)

        if enable_wireguard:
            _ensure_wireguard_identity_for_user(db, new_user)
            _ensure_wireguard_config_record(new_user, db)
            _sync_wireguard_users_runtime(db)

        if enable_l2tp:
            l2tp_config = VPNConfig(
                user_id=new_user.id,
                protocol="l2tp",
                is_active=True,
            )
            db.add(l2tp_config)
            l2tp_result = l2tp_service.start_client(db, username)
            if not l2tp_result.get("success"):
                raise HTTPException(status_code=500, detail=l2tp_result.get("message") or "L2TP provisioning failed")

    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        logger.error("Error creating unified VPN artifacts: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to provision VPN user artifacts: {exc}") from exc
    
    db.commit()
    _sync_openvpn_auth_db_snapshot()
    db.refresh(new_user)

    record_audit_event(
        action="vpn_user_created",
        success=True,
        admin_username=current_user.username,
        resource_type="vpn_user",
        resource_id=str(new_user.id),
        ip_address=extract_client_ip(request),
        details={"username": new_user.username},
    )
    
    logger.info(f"User {username} created by admin {current_user.username}")
    
    return VPNUserCredentials(
        username=username,
        password=plain_password,
        ppp_password=ppp_password if enable_l2tp else None,
        ipsec_psk=_resolve_ipsec_psk() if enable_l2tp else None,
        enabled_protocols=[
            protocol
            for protocol, enabled in (
                ("openvpn", enable_openvpn),
                ("wireguard", enable_wireguard),
                ("l2tp", enable_l2tp),
            )
            if enabled
        ],
    )


@router.patch("/{user_id}", response_model=VPNUserResponse)
async def update_user(
    user_id: int,
    user_data: VPNUserUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user information"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    was_active_before = bool(user.is_active)
    previous_wg_public_key = (user.wg_public_key or "").strip()
    previous_wg_allocated_ip = (user.wg_allocated_ip or "").strip()

    # Guard rails for conflicting payloads
    if user_data.notes is not None and user_data.description is not None and user_data.notes != user_data.description:
        raise HTTPException(status_code=400, detail="Provide either notes or description, not conflicting values")
    
    # Update fields
    if user_data.description is not None:
        user.description = user_data.description
    if user_data.notes is not None:
        user.notes = user_data.notes
    if user_data.new_password:
        user.password = get_password_hash(user_data.new_password)
    if user_data.data_limit_gb is not None:
        user.data_limit_gb = user_data.data_limit_gb
        user.traffic_limit_bytes = int(float(user_data.data_limit_gb) * (1024 ** 3))
    if user_data.add_data_gb is not None:
        current_limit_bytes = int(user.traffic_limit_bytes or 0)
        user.traffic_limit_bytes = current_limit_bytes + int(float(user_data.add_data_gb) * (1024 ** 3))
    if user_data.traffic_limit_bytes is not None:
        user.traffic_limit_bytes = user_data.traffic_limit_bytes
    if user_data.add_traffic_bytes is not None:
        user.traffic_limit_bytes = int(user.traffic_limit_bytes or 0) + int(user_data.add_traffic_bytes)
    if user_data.traffic_used_bytes is not None:
        user.traffic_used_bytes = user_data.traffic_used_bytes
    if user_data.expiry_date is not None:
        user.expiry_date = user_data.expiry_date
        user.access_expires_at = user_data.expiry_date
    if user_data.access_start_at is not None:
        user.access_start_at = user_data.access_start_at
    if user_data.access_expires_at is not None:
        user.access_expires_at = user_data.access_expires_at
    if user_data.max_devices is not None:
        user.max_devices = user_data.max_devices
        user.max_concurrent_connections = user_data.max_devices
    if user_data.max_concurrent_connections is not None:
        user.max_concurrent_connections = user_data.max_concurrent_connections
    if user_data.current_connections is not None:
        user.current_connections = user_data.current_connections
    if user_data.extend_days is not None:
        base_date = (
            user.access_expires_at
            if user.access_expires_at and user.access_expires_at > datetime.utcnow()
            else datetime.utcnow()
        )
        user.access_expires_at = base_date + timedelta(days=user_data.extend_days)
    if user_data.is_enabled is not None:
        user.is_enabled = user_data.is_enabled
        if user_data.is_enabled:
            # Re-enable user
            user.disabled_at = None
            user.disabled_reason = None
        else:
            user.disabled_at = datetime.utcnow()
            user.disabled_reason = user.disabled_reason or "Disabled by admin"
            user.current_connections = 0

            kill_results = _disconnect_user_across_protocols(user.username)
            if not (
                kill_results["openvpn"].get("success")
                or kill_results["wireguard"].get("success")
                or kill_results["l2tp"].get("success")
            ):
                logger.warning(
                    "Disable-path kill-switch could not disconnect any protocol for %s",
                    user.username,
                )

            has_openvpn_config = any(config.protocol == "openvpn" for config in user.configs)
            if has_openvpn_config:
                revoke_result = openvpn_service.revoke_client_certificate(user.username)
                if not revoke_result.get("success"):
                    logger.warning(
                        "OpenVPN certificate revoke skipped for disabled user %s: %s",
                        user.username,
                        revoke_result.get("message"),
                    )

    _sync_legacy_accounting_fields(user)
    user.refresh_limit_flags(datetime.utcnow())
    
    user.updated_at = datetime.utcnow()

    should_resync_wireguard = bool(
        user.is_active
        and (
            user.has_wireguard
            or (user.wg_public_key or "").strip()
        )
    )

    db.commit()
    _sync_openvpn_auth_db_snapshot()
    db.refresh(user)

    if should_resync_wireguard:
        try:
            if (not was_active_before) and user.is_active and previous_wg_public_key and previous_wg_allocated_ip:
                _reinject_existing_wireguard_peer(
                    db=db,
                    username=user.username,
                    public_key=previous_wg_public_key,
                    allocated_ip=previous_wg_allocated_ip,
                )
            _sync_wireguard_users_runtime(db)
            db.commit()
        except HTTPException:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"User updated but failed to re-sync WireGuard state: {exc}") from exc

    logger.info(f"User {user.username} updated by admin {current_user.username}")
    
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a user and all associated configs"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    username = user.username
    
    # Revoke OpenVPN certificate/CRL when any OpenVPN config exists for the user.
    if any(config.protocol == "openvpn" for config in user.configs):
        try:
            _disconnect_user_across_protocols(username)
            revoke_result = openvpn_service.revoke_client_certificate(username)
            if not revoke_result.get("success"):
                logger.warning("OpenVPN revoke skipped during delete for %s: %s", username, revoke_result.get("message"))
        except Exception as e:
            logger.error(f"Error revoking certificate for {username}: {e}")
    else:
        _disconnect_user_across_protocols(username)
    
    db.delete(user)
    try:
        db.flush()
        _sync_wireguard_users_runtime(db)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to synchronize WireGuard peers after delete: {exc}") from exc
    _sync_openvpn_auth_db_snapshot()

    record_audit_event(
        action="vpn_user_deleted",
        success=True,
        admin_username=current_user.username,
        resource_type="vpn_user",
        resource_id=str(user_id),
        ip_address=extract_client_ip(request),
        details={"username": username},
    )
    
    logger.info(f"User {username} deleted by admin {current_user.username}")
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{user_id}/configs/{protocol}/download")
async def download_config(
    user_id: int,
    protocol: str,
    server_address: Optional[str] = None,
    os: Optional[str] = None,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download VPN config file for a specific protocol"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if protocol == "openvpn":
        try:
            config = next((c for c in user.configs if c.protocol == "openvpn" and c.is_active), None)
            if not config:
                raise HTTPException(status_code=404, detail="OpenVPN is not enabled for this user")

            # Pre-flight validation of required settings
            _validate_required_settings(db)

            # Generate config with username/password auth
            config_content = openvpn_service.generate_client_config(
                user.username,
                os_type=os or "default"
            )

            if not config_content:
                raise HTTPException(status_code=500, detail="Failed to generate config")
            
            return Response(
                content=config_content,
                media_type="application/x-openvpn-profile",
                headers={
                    "Content-Disposition": f"attachment; filename={(f'{user.username}_{os}' if os else user.username)}.ovpn"
                }
            )
        except Exception as e:
            if isinstance(e, HTTPException):
                raise
            logger.error(f"Error generating OpenVPN config: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to generate config: {str(e)}")
    
    if protocol == "wireguard":
        try:
            if not (user.wg_private_key and user.wg_public_key and user.wg_allocated_ip):
                raise HTTPException(status_code=404, detail="WireGuard is not enabled for this user")
            config_content = wireguard_service.build_client_config_for_user(db, user)
            return Response(
                content=config_content,
                media_type="text/plain",
                headers={
                    "Content-Disposition": f"attachment; filename={user.username}.conf"
                },
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Error generating WireGuard config for user %s: %s", user.username, exc)
            raise HTTPException(status_code=500, detail=f"Failed to generate WireGuard config: {exc}") from exc

    if protocol == "l2tp":
        config = next((c for c in user.configs if c.protocol == protocol and c.is_active), None)
        if not config:
            raise HTTPException(status_code=404, detail="L2TP is not enabled for this user")

        server_host = (_get_or_create_general_settings(db).server_address or "SERVER_IP_OR_DOMAIN").strip()
        ppp_password = str(user.ppp_password or "").strip() or "(not-set)"
        content = "\n".join(
            [
                f"Server Address: {server_host}",
                "VPN Type: L2TP/IPsec with pre-shared key (PSK)",
                f"Username: {user.username}",
                f"Password: {ppp_password}",
                f"Pre-Shared Key: {_resolve_ipsec_psk()}",
                "* Note: Leave ports as default. No extra app required.",
            ]
        ) + "\n"
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={user.username}_{protocol}.txt"},
        )

    raise HTTPException(status_code=400, detail=f"Protocol {protocol} not yet supported")


@router.get("/{user_id}/configs/{protocol}", response_model=VPNConfigFileResponse)
async def get_config(
    user_id: int,
    protocol: str,
    include_qr: bool = False,
    server_address: Optional[str] = None,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get VPN config with optional QR code"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    config = next((c for c in user.configs if c.protocol == protocol and c.is_active), None)
    
    if protocol == "openvpn":
        try:
            if not config:
                raise HTTPException(status_code=404, detail="OpenVPN is not enabled for this user")

            # Pre-flight validation of required settings
            _validate_required_settings(db)
            
            config_content = openvpn_service.generate_client_config(
                user.username
            )
            config_content += "\nauth-user-pass\n"
            
            qr_code = None
            if include_qr:
                qr_code = openvpn_service.generate_qr_code(config_content)
            
            return VPNConfigFileResponse(
                username=user.username,
                protocol=protocol,
                config_content=config_content,
                qr_code=qr_code,
                created_at=datetime.utcnow()
            )
        except Exception as e:
            logger.error(f"Error generating config: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to generate config: {str(e)}")

    if protocol == "wireguard":
        try:
            if not (user.wg_private_key and user.wg_public_key and user.wg_allocated_ip):
                raise HTTPException(status_code=404, detail="WireGuard is not enabled for this user")
            config_content = wireguard_service.build_client_config_for_user(db, user)
            return VPNConfigFileResponse(
                username=user.username,
                protocol=protocol,
                config_content=config_content,
                qr_code=None,
                created_at=datetime.utcnow(),
            )
        except Exception as exc:
            logger.error("Error generating WireGuard config payload for user %s: %s", user.username, exc)
            raise HTTPException(status_code=500, detail=f"Failed to generate WireGuard config: {exc}") from exc

    if protocol == "l2tp":
        if not config:
            raise HTTPException(status_code=404, detail="L2TP is not enabled for this user")

        server_host = (_get_or_create_general_settings(db).server_address or "SERVER_IP_OR_DOMAIN").strip()
        ppp_password = str(user.ppp_password or "").strip() or "(not-set)"
        config_content = "\n".join(
            [
                f"Server Address: {server_host}",
                "VPN Type: L2TP/IPsec with pre-shared key (PSK)",
                f"Username: {user.username}",
                f"Password: {ppp_password}",
                f"Pre-Shared Key: {_resolve_ipsec_psk()}",
                "* Note: Leave ports as default. No extra app required.",
            ]
        )
        return VPNConfigFileResponse(
            username=user.username,
            protocol=protocol,
            config_content=config_content,
            qr_code=None,
            created_at=datetime.utcnow(),
        )

    raise HTTPException(status_code=400, detail=f"Protocol {protocol} not yet supported")


@router.post("/{user_id}/configs/{protocol}/revoke", response_model=VPNUserResponse)
async def revoke_config(
    user_id: int,
    protocol: str,
    revoke_data: VPNConfigRevokeRequest,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a specific protocol config for a user"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    config = next((c for c in user.configs if c.protocol == protocol and c.is_active), None)
    if not config:
        raise HTTPException(status_code=404, detail=f"No active {protocol} config found")
    
    if protocol == "openvpn":
        try:
            _disconnect_user_across_protocols(user.username)
            revoke_result = openvpn_service.revoke_client_certificate(user.username)
            if not revoke_result.get("success"):
                logger.error(f"Failed to revoke certificate: {revoke_result.get('message', 'unknown error')}")
        except Exception as e:
            logger.error(f"Error revoking certificate: {e}")

    if protocol == "wireguard":
        user.wg_private_key = None
        user.wg_public_key = None
        user.wg_allocated_ip = None
    if protocol == "l2tp":
        _disconnect_user_across_protocols(user.username)
    
    config.is_active = False
    config.revoked_at = datetime.utcnow()
    config.revoked_reason = revoke_data.reason or "Revoked by admin"

    try:
        if protocol == "wireguard":
            _sync_wireguard_users_runtime(db)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to synchronize protocol revocation: {exc}") from exc

    _sync_openvpn_auth_db_snapshot()
    db.refresh(user)
    
    logger.info(f"{protocol} config revoked for user {user.username}")
    
    return user


@router.post("/{user_id}/password/reset", response_model=PasswordResetResponse)
async def reset_password(
    user_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Reset user password to a new random password"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate new password
    new_password = VPNUser.generate_secure_password()
    user.password = get_password_hash(new_password)
    user.updated_at = datetime.utcnow()
    
    db.commit()
    _sync_openvpn_auth_db_snapshot()
    
    logger.info(f"Password reset for user {user.username} by admin {current_user.username}")
    
    return PasswordResetResponse(
        username=user.username,
        new_password=new_password
    )


@router.post("/{user_id}/password/change", response_model=VPNUserResponse)
async def change_password(
    user_id: int,
    password_data: PasswordChangeRequest,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password to a specific value"""
    user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.password = get_password_hash(password_data.new_password)
    user.updated_at = datetime.utcnow()
    
    db.commit()
    _sync_openvpn_auth_db_snapshot()
    db.refresh(user)
    
    logger.info(f"Password changed for user {user.username} by admin {current_user.username}")
    
    return user


@router.get("/{user_id}/limits/check")
async def check_user_limits(
    user_id: int,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manually check if user has violated any limits"""
    scheduler = get_scheduler()
    return await scheduler.check_user_limits(user_id, db)
