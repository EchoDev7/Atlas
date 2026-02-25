# Atlas — OpenVPN router (Phase 2)
# OpenVPN management API endpoints with authentication

from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import List, Optional, Tuple
from datetime import datetime
import logging

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.user import Admin
from backend.models.openvpn_settings import OpenVPNSettings
from backend.models.vpn_client import VPNClient, VPNClientStatus
from backend.schemas.vpn_client import (
    VPNClientCreate,
    VPNClientUpdate,
    VPNClientResponse,
    VPNClientDetailResponse,
    VPNClientConfigResponse,
    VPNClientRevokeRequest,
    VPNServiceStatusResponse,
    VPNServiceControlRequest,
    VPNClientListResponse
)
from backend.core.openvpn import OpenVPNManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/openvpn", tags=["OpenVPN Management"])

# Initialize OpenVPN manager
openvpn_manager = OpenVPNManager()


def _get_transport_settings(db: Session) -> Tuple[int, str]:
    settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
    if not settings:
        return 1194, "udp"
    return settings.port, settings.protocol


@router.get("/clients", response_model=VPNClientListResponse)
def list_clients(
    page: int = 1,
    page_size: int = 50,
    status_filter: Optional[VPNClientStatus] = None,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    List all VPN clients with pagination and filtering.
    Requires authentication.
    """
    try:
        query = db.query(VPNClient)
        
        # Apply status filter if provided
        if status_filter:
            query = query.filter(VPNClient.status == status_filter)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * page_size
        clients = query.order_by(VPNClient.created_at.desc()).offset(offset).limit(page_size).all()
        
        return VPNClientListResponse(
            total=total,
            clients=clients,
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error(f"Failed to list clients: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve clients: {str(e)}"
        )


@router.get("/clients/{client_id}", response_model=VPNClientDetailResponse)
def get_client(
    client_id: int,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    Get detailed information about a specific VPN client.
    Requires authentication.
    """
    client = db.query(VPNClient).filter(VPNClient.id == client_id).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with ID {client_id} not found"
        )
    
    return client


@router.post("/clients", response_model=VPNClientDetailResponse, status_code=status.HTTP_201_CREATED)
def create_client(
    client_data: VPNClientCreate,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    Create a new VPN client with certificate generation.
    Requires authentication.
    """
    try:
        # Check if client name already exists
        existing = db.query(VPNClient).filter(VPNClient.name == client_data.name).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Client with name '{client_data.name}' already exists"
            )
        
        # Create client certificate using OpenVPN manager
        cert_result = openvpn_manager.create_client_certificate(client_data.name)
        
        if not cert_result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Certificate creation failed: {cert_result.get('message')}"
            )
        
        # Create database record
        new_client = VPNClient(
            name=client_data.name,
            email=client_data.email,
            description=client_data.description,
            protocol=client_data.protocol,
            max_connections=client_data.max_connections,
            certificate_cn=client_data.name,
            certificate_issued_at=datetime.utcnow(),
            status=VPNClientStatus.ACTIVE,
            created_by=current_user.id,
            is_enabled=True
        )
        
        db.add(new_client)
        db.commit()
        db.refresh(new_client)
        
        logger.info(f"Client '{client_data.name}' created successfully by admin '{current_user.username}'")
        
        return new_client
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create client: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create client: {str(e)}"
        )


@router.patch("/clients/{client_id}", response_model=VPNClientDetailResponse)
def update_client(
    client_id: int,
    client_data: VPNClientUpdate,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    Update VPN client information.
    Requires authentication.
    """
    client = db.query(VPNClient).filter(VPNClient.id == client_id).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with ID {client_id} not found"
        )
    
    try:
        # Update only provided fields
        update_data = client_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(client, field, value)
        
        client.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(client)
        
        logger.info(f"Client '{client.name}' updated by admin '{current_user.username}'")
        
        return client
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update client: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update client: {str(e)}"
        )


@router.post("/clients/{client_id}/revoke", response_model=VPNClientDetailResponse)
def revoke_client(
    client_id: int,
    revoke_data: VPNClientRevokeRequest,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    Revoke VPN client certificate.
    Requires authentication.
    """
    client = db.query(VPNClient).filter(VPNClient.id == client_id).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with ID {client_id} not found"
        )
    
    if client.status == VPNClientStatus.REVOKED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Client '{client.name}' is already revoked"
        )
    
    try:
        # Revoke certificate using OpenVPN manager
        revoke_result = openvpn_manager.revoke_client_certificate(client.name)
        
        if not revoke_result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Certificate revocation failed: {revoke_result.get('message')}"
            )
        
        # Update database record
        client.status = VPNClientStatus.REVOKED
        client.revoked_at = datetime.utcnow()
        client.revoked_reason = revoke_data.reason
        client.is_enabled = False
        client.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(client)
        
        logger.info(f"Client '{client.name}' revoked by admin '{current_user.username}'")
        
        return client
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to revoke client: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke client: {str(e)}"
        )


@router.delete("/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_client(
    client_id: int,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    Delete VPN client (soft delete - revokes certificate first).
    Requires authentication.
    """
    client = db.query(VPNClient).filter(VPNClient.id == client_id).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with ID {client_id} not found"
        )
    
    try:
        # Revoke certificate if not already revoked
        if client.status != VPNClientStatus.REVOKED:
            revoke_result = openvpn_manager.revoke_client_certificate(client.name)
            if not revoke_result.get("success"):
                logger.warning(f"Certificate revocation failed during delete: {revoke_result.get('message')}")
        
        # Delete from database
        db.delete(client)
        db.commit()
        
        logger.info(f"Client '{client.name}' deleted by admin '{current_user.username}'")
        
        return Response(status_code=status.HTTP_204_NO_CONTENT)
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete client: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete client: {str(e)}"
        )


@router.get("/clients/{client_id}/config", response_model=VPNClientConfigResponse)
def get_client_config(
    client_id: int,
    include_qr: bool = False,
    server_address: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    Generate and download .ovpn configuration file for client.
    Optionally includes QR code for mobile clients.
    Requires authentication.
    """
    client = db.query(VPNClient).filter(VPNClient.id == client_id).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with ID {client_id} not found"
        )
    
    if client.status != VPNClientStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot generate config for {client.status.value} client"
        )
    
    try:
        server_port, protocol = _get_transport_settings(db)

        # Generate .ovpn configuration
        config_content = openvpn_manager.generate_client_config(
            client_name=client.name,
            server_address=server_address,
            server_port=server_port,
            protocol=protocol,
        )
        
        if not config_content:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate configuration file"
            )
        
        # Generate QR code if requested
        qr_code = None
        if include_qr:
            qr_code = openvpn_manager.generate_qr_code(config_content)
        
        return VPNClientConfigResponse(
            client_name=client.name,
            config_content=config_content,
            qr_code=qr_code
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate configuration: {str(e)}"
        )


@router.get("/clients/{client_id}/config/download")
def download_client_config(
    client_id: int,
    server_address: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Admin = Depends(get_current_user)
):
    """
    Download .ovpn configuration file.
    Requires authentication.
    """
    client = db.query(VPNClient).filter(VPNClient.id == client_id).first()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with ID {client_id} not found"
        )
    
    try:
        server_port, protocol = _get_transport_settings(db)

        config_content = openvpn_manager.generate_client_config(
            client_name=client.name,
            server_address=server_address,
            server_port=server_port,
            protocol=protocol,
        )
        
        if not config_content:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate configuration file"
            )
        
        return Response(
            content=config_content,
            media_type="application/x-openvpn-profile",
            headers={
                "Content-Disposition": f"attachment; filename={client.name}.ovpn"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download configuration: {str(e)}"
        )


@router.get("/service/status", response_model=VPNServiceStatusResponse)
def get_service_status(
    current_user: Admin = Depends(get_current_user)
):
    """
    Get OpenVPN service status.
    Requires authentication.
    """
    try:
        status_result = openvpn_manager.get_service_status()
        
        if not status_result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get service status: {status_result.get('message')}"
            )
        
        return VPNServiceStatusResponse(
            service_name=status_result.get("service_name"),
            is_active=status_result.get("is_active", False),
            is_enabled=status_result.get("is_enabled", False),
            is_mock=status_result.get("is_mock", False),
            status_output=status_result.get("status_output")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get service status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get service status: {str(e)}"
        )


@router.post("/service/control")
def control_service(
    control_data: VPNServiceControlRequest,
    current_user: Admin = Depends(get_current_user)
):
    """
    Control OpenVPN service (start/stop/restart/enable/disable).
    Requires authentication.
    """
    try:
        control_result = openvpn_manager.control_service(control_data.action)
        
        if not control_result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Service control failed: {control_result.get('message')}"
            )
        
        logger.info(f"Service action '{control_data.action}' executed by admin '{current_user.username}'")
        
        return {
            "success": True,
            "action": control_data.action,
            "message": control_result.get("message"),
            "is_mock": control_result.get("is_mock", False)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to control service: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to control service: {str(e)}"
        )
