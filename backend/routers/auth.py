from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List
from backend.database import SessionLocal, get_db
from backend.models.general_settings import GeneralSettings
from backend.models.user import Admin
from backend.schemas.user import (
    LoginRequest,
    Token,
    AdminResponse,
    AdminPasswordChangeRequest,
    AdminPasswordChangeResponse,
)
from backend.services.auth_service import (
    verify_password,
    create_access_token,
    get_password_hash,
    is_default_admin_password_hash,
)
from backend.services.audit_service import extract_client_ip, record_audit_event
from backend.dependencies import get_current_user
from backend.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

_LOGIN_RATE_LIMIT_WINDOW = timedelta(minutes=15)
_LOGIN_RATE_LIMIT_BLOCK = timedelta(minutes=15)
_LOGIN_RATE_LIMIT_MAX_FAILURES = 5
_LOGIN_RATE_LIMIT_MIN_FAILURES = 1
_LOGIN_RATE_LIMIT_MAX_FAILURES_BOUND = 20
_LOGIN_RATE_LIMIT_MIN_BLOCK_MINUTES = 1
_LOGIN_RATE_LIMIT_MAX_BLOCK_MINUTES = 1440
_login_attempts_by_ip: Dict[str, Dict[str, Any]] = {}
_login_attempts_lock = Lock()


def _safe_rate_limit_config_from_db() -> tuple[int, timedelta]:
    max_failures = _LOGIN_RATE_LIMIT_MAX_FAILURES
    block_duration = _LOGIN_RATE_LIMIT_BLOCK

    db = SessionLocal()
    try:
        general = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
        if not general:
            return max_failures, block_duration

        configured_failures = int(general.login_max_failed_attempts or _LOGIN_RATE_LIMIT_MAX_FAILURES)
        configured_block_minutes = int(general.login_block_duration_minutes or int(_LOGIN_RATE_LIMIT_BLOCK.total_seconds() // 60))

        max_failures = min(_LOGIN_RATE_LIMIT_MAX_FAILURES_BOUND, max(_LOGIN_RATE_LIMIT_MIN_FAILURES, configured_failures))
        configured_block_minutes = min(_LOGIN_RATE_LIMIT_MAX_BLOCK_MINUTES, max(_LOGIN_RATE_LIMIT_MIN_BLOCK_MINUTES, configured_block_minutes))
        block_duration = timedelta(minutes=configured_block_minutes)
    except Exception:
        pass
    finally:
        db.close()

    return max_failures, block_duration


def _prune_failures(failures: List[datetime], now: datetime) -> List[datetime]:
    threshold = now - _LOGIN_RATE_LIMIT_WINDOW
    return [item for item in failures if item >= threshold]


def _enforce_login_rate_limit(ip: str, now: datetime) -> None:
    with _login_attempts_lock:
        data = _login_attempts_by_ip.setdefault(ip, {"failures": [], "blocked_until": None})
        blocked_until = data.get("blocked_until")

        if blocked_until and now < blocked_until:
            remaining_seconds = max(1, int((blocked_until - now).total_seconds()))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Try again in {remaining_seconds} seconds.",
            )

        data["blocked_until"] = None
        data["failures"] = _prune_failures(list(data.get("failures") or []), now)


def _record_login_failure(ip: str, now: datetime, max_failures: int, block_duration: timedelta) -> None:
    with _login_attempts_lock:
        data = _login_attempts_by_ip.setdefault(ip, {"failures": [], "blocked_until": None})
        failures = _prune_failures(list(data.get("failures") or []), now)
        failures.append(now)
        data["failures"] = failures

        if len(failures) >= max_failures:
            data["blocked_until"] = now + block_duration
            data["failures"] = []


def _clear_login_failures(ip: str) -> None:
    with _login_attempts_lock:
        _login_attempts_by_ip.pop(ip, None)


def _requires_admin_password_change(user: Admin) -> bool:
    if not user or user.username != settings.ADMIN_USERNAME:
        return False
    return is_default_admin_password_hash(user.hashed_password)


def _authenticate_and_issue_token(login_data: LoginRequest, db: Session) -> Dict[str, Any]:
    user = db.query(Admin).filter(Admin.username == login_data.username).first()

    if not user:
        if login_data.username == settings.ADMIN_USERNAME and login_data.password == settings.ADMIN_PASSWORD:
            hashed_password = get_password_hash(settings.ADMIN_PASSWORD)
            user = Admin(
                username=settings.ADMIN_USERNAME,
                hashed_password=hashed_password,
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    user.last_login = datetime.utcnow()
    db.commit()

    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "requires_password_change": _requires_admin_password_change(user),
    }


def _login_with_rate_limit(login_data: LoginRequest, request: Request, db: Session) -> Dict[str, Any]:
    client_ip = extract_client_ip(request)
    now = datetime.utcnow()
    max_failures, block_duration = _safe_rate_limit_config_from_db()
    try:
        _enforce_login_rate_limit(client_ip, now)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            record_audit_event(
                action="admin_login_blocked_rate_limit",
                success=False,
                admin_username=login_data.username,
                resource_type="auth",
                ip_address=client_ip,
                details={"reason": "rate_limited", "message": exc.detail},
            )
        raise

    try:
        token_payload = _authenticate_and_issue_token(login_data, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _record_login_failure(client_ip, now, max_failures=max_failures, block_duration=block_duration)
            record_audit_event(
                action="admin_login_failed",
                success=False,
                admin_username=login_data.username,
                resource_type="auth",
                ip_address=client_ip,
                details={"reason": "invalid_credentials"},
            )
        raise

    _clear_login_failures(client_ip)
    record_audit_event(
        action="admin_login_success",
        success=True,
        admin_username=login_data.username,
        resource_type="auth",
        ip_address=client_ip,
    )
    return token_payload


@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return _login_with_rate_limit(login_data, request, db)


@router.post("/token", response_model=Token)
def issue_token(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return _login_with_rate_limit(login_data, request, db)


@router.get("/me", response_model=AdminResponse)
def get_current_admin(current_user: Admin = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "requires_password_change": _requires_admin_password_change(current_user),
        "created_at": current_user.created_at,
        "last_login": current_user.last_login,
    }


@router.post("/change-password", response_model=AdminPasswordChangeResponse)
def change_admin_password(
    payload: AdminPasswordChangeRequest,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    client_ip = extract_client_ip(request)
    if not verify_password(payload.current_password, current_user.hashed_password):
        record_audit_event(
            action="admin_password_change_failed",
            success=False,
            admin_username=current_user.username,
            resource_type="auth",
            ip_address=client_ip,
            details={"reason": "invalid_current_password"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if payload.current_password == payload.new_password:
        record_audit_event(
            action="admin_password_change_failed",
            success=False,
            admin_username=current_user.username,
            resource_type="auth",
            ip_address=client_ip,
            details={"reason": "new_password_same_as_current"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    current_user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    record_audit_event(
        action="admin_password_changed",
        success=True,
        admin_username=current_user.username,
        resource_type="auth",
        ip_address=client_ip,
    )

    return {
        "success": True,
        "message": "Admin password updated successfully",
    }
