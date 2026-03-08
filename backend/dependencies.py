import ipaddress

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.general_settings import GeneralSettings
from backend.services.auth_service import decode_access_token
from backend.services.audit_service import extract_client_ip, record_audit_event
from backend.models.user import Admin

security = HTTPBearer()


def _parse_admin_allowed_ips(raw_value: str) -> list[str]:
    normalized = (raw_value or "").replace("\n", ",")
    return [item.strip() for item in normalized.split(",") if item.strip()]


def _is_ip_allowed_by_policy(client_ip: str, allowed_entries: list[str]) -> bool:
    if not allowed_entries:
        return True

    if any(item in {"*", "0.0.0.0/0", "::/0"} for item in allowed_entries):
        return True

    try:
        parsed_client_ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for item in allowed_entries:
        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if parsed_client_ip in network:
                return True
            continue

        try:
            if parsed_client_ip == ipaddress.ip_address(item):
                return True
        except ValueError:
            if item == client_ip:
                return True

    return False


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> Admin:
    token = credentials.credentials
    username = decode_access_token(token)
    
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(Admin).filter(Admin.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    client_ip = extract_client_ip(request)
    general_settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    allowed_entries = _parse_admin_allowed_ips(general_settings.admin_allowed_ips if general_settings else "")
    if allowed_entries and not _is_ip_allowed_by_policy(client_ip, allowed_entries):
        record_audit_event(
            action="admin_access_denied_ip_policy",
            success=False,
            admin_username=user.username,
            resource_type="auth",
            ip_address=client_ip,
            details={"reason": "ip_not_allowed", "allowed_entries": allowed_entries},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied from this IP address",
        )

    return user
