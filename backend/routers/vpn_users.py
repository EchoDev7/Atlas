# Atlas — VPN Users router (Phase 2 Enhancements)
# Multi-protocol user management with limits enforcement

from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import logging
import random
from passlib.context import CryptContext

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
from backend.models.general_settings import GeneralSettings
from backend.models.openvpn_settings import OpenVPNSettings

logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
    hashed_password = pwd_context.hash(plain_password)
    
    # Create user
    new_user = VPNUser(
        username=username,
        password=hashed_password,
        description=user_data.description,
        data_limit_gb=user_data.data_limit_gb,
        expiry_date=user_data.expiry_date,
        max_devices=user_data.max_devices,
        created_by=current_user.id
    )
    
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
        user.password = pwd_context.hash(user_data.new_password)
    if user_data.data_limit_gb is not None:
        user.data_limit_gb = user_data.data_limit_gb
        user.is_data_limit_exceeded = False  # Reset flag when limit is updated
    if user_data.add_data_gb is not None:
        current_limit = user.data_limit_gb or 0
        user.data_limit_gb = current_limit + user_data.add_data_gb
        user.is_data_limit_exceeded = False
    if user_data.expiry_date is not None:
        user.expiry_date = user_data.expiry_date
        user.is_expired = False  # Reset flag when date is updated
    if user_data.max_devices is not None:
        user.max_devices = user_data.max_devices
    if user_data.extend_days is not None:
        base_date = user.expiry_date if user.expiry_date and user.expiry_date > datetime.utcnow() else datetime.utcnow()
        user.expiry_date = base_date + timedelta(days=user_data.extend_days)
        user.is_expired = False
    if user_data.is_enabled is not None:
        user.is_enabled = user_data.is_enabled
        if user_data.is_enabled:
            # Re-enable user
            user.disabled_at = None
            user.disabled_reason = None
        else:
            user.disabled_at = datetime.utcnow()
            user.disabled_reason = user.disabled_reason or "Disabled by admin"
    
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
    
    # Revoke OpenVPN certificates if any
    for config in user.configs:
        if config.protocol == "openvpn" and config.is_active:
            try:
                openvpn_manager.revoke_client_certificate(username)
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
                server_address or "vpn.example.com",
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
            
            # Add auth-user-pass directive
            config_content += "\nauth-user-pass\n"
            
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
                user.username,
                server_address or "vpn.example.com"
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
    user.password = pwd_context.hash(new_password)
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
    
    user.password = pwd_context.hash(password_data.new_password)
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
