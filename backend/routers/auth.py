from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List
from backend.database import get_db
from backend.models.user import Admin
from backend.schemas.user import (
    LoginRequest,
    Token,
    AdminResponse,
    AdminPasswordChangeRequest,
    AdminPasswordChangeResponse,
)
from backend.services.auth_service import verify_password, create_access_token, get_password_hash
from backend.dependencies import get_current_user
from backend.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

_LOGIN_RATE_LIMIT_WINDOW = timedelta(minutes=15)
_LOGIN_RATE_LIMIT_BLOCK = timedelta(minutes=15)
_LOGIN_RATE_LIMIT_MAX_FAILURES = 5
_login_attempts_by_ip: Dict[str, Dict[str, Any]] = {}
_login_attempts_lock = Lock()


def _get_client_ip(request: Request) -> str:
    forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or "unknown"
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


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


def _record_login_failure(ip: str, now: datetime) -> None:
    with _login_attempts_lock:
        data = _login_attempts_by_ip.setdefault(ip, {"failures": [], "blocked_until": None})
        failures = _prune_failures(list(data.get("failures") or []), now)
        failures.append(now)
        data["failures"] = failures

        if len(failures) >= _LOGIN_RATE_LIMIT_MAX_FAILURES:
            data["blocked_until"] = now + _LOGIN_RATE_LIMIT_BLOCK
            data["failures"] = []


def _clear_login_failures(ip: str) -> None:
    with _login_attempts_lock:
        _login_attempts_by_ip.pop(ip, None)


def _authenticate_and_issue_token(login_data: LoginRequest, db: Session) -> Dict[str, str]:
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
    return {"access_token": access_token, "token_type": "bearer"}


def _login_with_rate_limit(login_data: LoginRequest, request: Request, db: Session) -> Dict[str, str]:
    client_ip = _get_client_ip(request)
    now = datetime.utcnow()
    _enforce_login_rate_limit(client_ip, now)

    try:
        token_payload = _authenticate_and_issue_token(login_data, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _record_login_failure(client_ip, now)
        raise

    _clear_login_failures(client_ip)
    return token_payload


@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return _login_with_rate_limit(login_data, request, db)


@router.post("/token", response_model=Token)
def issue_token(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return _login_with_rate_limit(login_data, request, db)


@router.get("/me", response_model=AdminResponse)
def get_current_admin(current_user: Admin = Depends(get_current_user)):
    return current_user


@router.post("/change-password", response_model=AdminPasswordChangeResponse)
def change_admin_password(
    payload: AdminPasswordChangeRequest,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    current_user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    return {
        "success": True,
        "message": "Admin password updated successfully",
    }
