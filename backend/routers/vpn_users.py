# Atlas — VPN Users router (Phase 2 Enhancements)
# Multi-protocol user management with limits enforcement

from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import logging
import random

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
from backend.core.openvpn import OpenVPNManager, validate_openvpn_readiness
from backend.services.scheduler_service import get_scheduler
from backend.services.protocols.registry import protocol_registry
from backend.models.general_settings import GeneralSettings
from backend.models.openvpn_settings import OpenVPNSettings
from backend.services.auth_service import get_password_hash

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["VPN Users"])

# Initialize OpenVPN manager
openvpn_manager = OpenVPNManager()


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
    
    missing = validate_openvpn_readiness(general, openvpn)
    
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


@router.get("", response_model=VPNUserListResponse)
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of all VPN users with pagination"""
    users = db.query(VPNUser).offset(skip).limit(limit).all()
    total = db.query(VPNUser).count()
    
    # Mock is_online status for testing (30% chance of being online)
    user_responses = []
    for user in users:
        user_dict = VPNUserResponse.from_orm(user).dict()
        user_dict['is_online'] = random.random() < 0.3 and user.is_active
        user_responses.append(VPNUserResponse(**user_dict))
    
    return VPNUserListResponse(
        users=user_responses,
        total=total,
        page=skip // limit + 1,
        page_size=limit
    )


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
    
    return user


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

    user.current_connections = 0
    user.is_connection_limit_exceeded = False
    user.updated_at = datetime.utcnow()
    db.commit()

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
        created_by=current_user.id
    )
    _sync_legacy_accounting_fields(new_user)
    new_user.refresh_limit_flags(datetime.utcnow())
    
    db.add(new_user)
    db.flush()  # Get user ID
    
    # Create OpenVPN config if requested
    if user_data.create_openvpn:
        try:
            # Create certificate
            cert_result = openvpn_manager.create_client_certificate(username)

            if cert_result.get("success"):
                # Create config record
                openvpn_config = VPNConfig(
                    user_id=new_user.id,
                    protocol="openvpn",
                    certificate_cn=username,
                    certificate_issued_at=datetime.utcnow()
                )
                db.add(openvpn_config)
                logger.info(f"OpenVPN config created for user {username}")
            else:
                logger.warning(
                    f"Failed to create OpenVPN certificate for {username}: {cert_result.get('message', 'unknown error')}"
                )
        
        except Exception as e:
            logger.error(f"Error creating OpenVPN config: {e}")
    
    db.commit()
    db.refresh(new_user)
    
    logger.info(f"User {username} created by admin {current_user.username}")
    
    return VPNUserCredentials(
        username=username,
        password=plain_password
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

            has_openvpn_config = any(config.protocol == "openvpn" for config in user.configs)
            if has_openvpn_config:
                revoke_result = openvpn_manager.revoke_client_certificate(user.username)
                if not revoke_result.get("success"):
                    logger.warning(
                        "OpenVPN certificate revoke skipped for disabled user %s: %s",
                        user.username,
                        revoke_result.get("message"),
                    )

    _sync_legacy_accounting_fields(user)
    user.refresh_limit_flags(datetime.utcnow())
    
    user.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(user)
    
    logger.info(f"User {user.username} updated by admin {current_user.username}")
    
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
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
            revoke_result = openvpn_manager.revoke_client_certificate(username)
            if not revoke_result.get("success"):
                logger.warning("OpenVPN revoke skipped during delete for %s: %s", username, revoke_result.get("message"))
        except Exception as e:
            logger.error(f"Error revoking certificate for {username}: {e}")
    
    db.delete(user)
    db.commit()
    
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
            # Pre-flight validation of required settings
            _validate_required_settings(db)
            
            # Find existing active OpenVPN config; auto-provision if missing
            config = next((c for c in user.configs if c.protocol == "openvpn" and c.is_active), None)
            created_missing_config = False
            if not config:
                cert_result = openvpn_manager.create_client_certificate(user.username)
                if cert_result.get("success"):
                    created_missing_config = True
                else:
                    logger.warning(
                        f"Auto-provision certificate step failed for {user.username}: {cert_result.get('message', 'unknown error')}"
                    )

            # Generate config with username/password auth
            config_content = openvpn_manager.generate_client_config(
                user.username,
                os_type=os or "default"
            )

            if not config_content:
                raise HTTPException(status_code=500, detail="Failed to generate config")

            # Persist a missing OpenVPN config row only after successful config generation
            if created_missing_config:
                config = VPNConfig(
                    user_id=user.id,
                    protocol="openvpn",
                    certificate_cn=user.username,
                    certificate_issued_at=datetime.utcnow(),
                    is_active=True
                )
                db.add(config)
                db.commit()
                db.refresh(user)
            
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
            raise HTTPException(status_code=500, detail="Failed to generate config")
    
    else:
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
    if not config:
        raise HTTPException(status_code=404, detail=f"No active {protocol} config found")
    
    if protocol == "openvpn":
        try:
            # Pre-flight validation of required settings
            _validate_required_settings(db)
            
            config_content = openvpn_manager.generate_client_config(
                user.username
            )
            config_content += "\nauth-user-pass\n"
            
            qr_code = None
            if include_qr:
                qr_code = openvpn_manager.generate_qr_code(config_content)
            
            return VPNConfigFileResponse(
                username=user.username,
                protocol=protocol,
                config_content=config_content,
                qr_code=qr_code,
                created_at=datetime.utcnow()
            )
        except Exception as e:
            logger.error(f"Error generating config: {e}")
            raise HTTPException(status_code=500, detail="Failed to generate config")
    
    else:
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
            revoke_result = openvpn_manager.revoke_client_certificate(user.username)
            if not revoke_result.get("success"):
                logger.error(f"Failed to revoke certificate: {revoke_result.get('message', 'unknown error')}")
        except Exception as e:
            logger.error(f"Error revoking certificate: {e}")
    
    config.is_active = False
    config.revoked_at = datetime.utcnow()
    config.revoked_reason = revoke_data.reason or "Revoked by admin"
    
    db.commit()
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
