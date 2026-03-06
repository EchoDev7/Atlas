from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.core.openvpn import OpenVPNManager
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.general_settings import GeneralSettings
from backend.models.user import Admin
from backend.models.vpn_user import VPNUser

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
openvpn_manager = OpenVPNManager()


def _is_user_expired(user: VPNUser, now: datetime) -> bool:
    expiry = user.effective_access_expires_at
    if not expiry:
        return False
    now_naive = now.replace(tzinfo=None) if now.tzinfo else now
    expiry_naive = expiry.replace(tzinfo=None) if expiry.tzinfo else expiry
    return now_naive > expiry_naive


def _is_data_limit_exceeded(user: VPNUser) -> bool:
    limit_bytes = user.effective_traffic_limit_bytes
    if limit_bytes in (None, 0):
        return False
    return int(user.total_bytes or 0) >= int(limit_bytes)


@router.get("/overview")
def get_dashboard_overview(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _ = current_user
    now = datetime.utcnow()

    try:
        users = db.query(VPNUser).all()
        total_users = len(users)

        expired_users = 0
        limit_exceeded_users = 0
        disabled_users = 0
        total_traffic_bytes = 0
        alert_items: list[dict[str, str]] = []

        for user in users:
            total_traffic_bytes += int(user.total_bytes or 0)

            user_is_expired = _is_user_expired(user, now) or bool(user.is_expired)
            user_limit_exceeded = _is_data_limit_exceeded(user) or bool(user.is_data_limit_exceeded)
            user_disabled = not bool(user.is_enabled)

            if user_is_expired:
                expired_users += 1
                alert_items.append(
                    {
                        "username": user.username,
                        "type": "expired",
                        "message": f"User '{user.username}' is expired.",
                    }
                )
            if user_limit_exceeded:
                limit_exceeded_users += 1
                alert_items.append(
                    {
                        "username": user.username,
                        "type": "data_limit",
                        "message": f"User '{user.username}' exceeded traffic limit.",
                    }
                )
            if user_disabled:
                disabled_users += 1

        service_status = openvpn_manager.get_service_status()
        runtime_health = openvpn_manager.get_runtime_health()

        db_health = {"ok": True, "message": "Database reachable"}
        try:
            db.execute(text("SELECT 1"))
        except Exception as exc:
            db_health = {"ok": False, "message": str(exc)}

        general_settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
        global_settings_snapshot = {
            "server_address": (general_settings.server_address or "") if general_settings else "",
            "panel_domain": (general_settings.panel_domain or "") if general_settings else "",
            "force_https": bool(general_settings.force_https) if general_settings else False,
            "global_ipv6_support": bool(general_settings.global_ipv6_support) if general_settings else False,
            "system_timezone": (general_settings.system_timezone or "UTC") if general_settings else "UTC",
        }

        active_users = max(0, total_users - expired_users - limit_exceeded_users - disabled_users)

        return {
            "generated_at": now.isoformat() + "Z",
            "totals": {
                "total_users": total_users,
                "active_users": active_users,
                "expired_users": expired_users,
                "limit_exceeded_users": limit_exceeded_users,
                "disabled_users": disabled_users,
            },
            "live": {
                "online_users": int(runtime_health.get("runtime_summary", {}).get("online_users", 0)),
                "active_sessions": int(runtime_health.get("runtime_summary", {}).get("active_sessions", 0)),
                "openvpn_runtime_healthy": bool(runtime_health.get("healthy", False)),
            },
            "traffic": {
                "total_traffic_bytes": int(total_traffic_bytes),
                "live_total_bytes": int(runtime_health.get("runtime_summary", {}).get("total_bytes", 0)),
            },
            "system_health": {
                "openvpn": {
                    "is_active": bool(service_status.get("is_active", False)),
                    "is_enabled": bool(service_status.get("is_enabled", False)),
                    "message": service_status.get("message"),
                },
                "database": db_health,
            },
            "global": global_settings_snapshot,
            "alerts": {
                "total": len(alert_items),
                "items": alert_items[:12],
            },
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to build dashboard overview: {str(exc)}",
        )
