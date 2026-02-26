from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.core.obfuscation_manager import ObfuscationManager
from backend.core.openvpn import OpenVPNManager
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.general_settings import GeneralSettings
from backend.models.openvpn_settings import OpenVPNSettings
from backend.models.user import Admin
from backend.schemas.general_settings import (
    GeneralSettingsResponse,
    GeneralSettingsUpdate,
)
from backend.schemas.openvpn_settings import OpenVPNSettingsResponse, OpenVPNSettingsUpdate

router = APIRouter(prefix="/settings", tags=["Server Settings"])
openvpn_manager = OpenVPNManager()
obfuscation_manager = ObfuscationManager()


def _get_or_create_openvpn_settings(db: Session) -> OpenVPNSettings:
    settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
    if settings:
        return settings

    settings = OpenVPNSettings()
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings


def _get_or_create_general_settings(db: Session) -> GeneralSettings:
    settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    if settings:
        return settings

    settings = GeneralSettings()
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings


def _to_response(settings: OpenVPNSettings) -> OpenVPNSettingsResponse:
    ciphers = [
        cipher.strip()
        for cipher in (settings.data_ciphers or "").split(":")
        if cipher and cipher.strip()
    ]
    if not ciphers:
        ciphers = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]

    return OpenVPNSettingsResponse(
        id=settings.id,
        port=settings.port,
        protocol=settings.protocol,
        device_type=settings.device_type,
        topology=settings.topology,
        ipv4_network=settings.ipv4_network,
        ipv4_netmask=settings.ipv4_netmask,
        ipv6_network=settings.ipv6_network,
        ipv6_prefix=settings.ipv6_prefix,
        max_clients=settings.max_clients,
        client_to_client=settings.client_to_client,
        redirect_gateway=settings.redirect_gateway,
        primary_dns=settings.primary_dns,
        secondary_dns=settings.secondary_dns,
        block_outside_dns=settings.block_outside_dns,
        push_custom_routes=settings.push_custom_routes,
        data_ciphers=ciphers,
        tls_version_min=settings.tls_version_min,
        tls_mode=settings.tls_mode,
        auth_digest=settings.auth_digest,
        reneg_sec=settings.reneg_sec,
        tun_mtu=settings.tun_mtu,
        mssfix=settings.mssfix,
        sndbuf=settings.sndbuf,
        rcvbuf=settings.rcvbuf,
        fast_io=settings.fast_io,
        tcp_nodelay=settings.tcp_nodelay,
        explicit_exit_notify=settings.explicit_exit_notify,
        keepalive_ping=settings.keepalive_ping,
        keepalive_timeout=settings.keepalive_timeout,
        inactive_timeout=settings.inactive_timeout,
        management_port=settings.management_port,
        verbosity=settings.verbosity,
        custom_directives=settings.custom_directives,
        advanced_client_push=settings.advanced_client_push,
        obfuscation_mode=settings.obfuscation_mode,
        proxy_server=settings.proxy_server,
        proxy_address=settings.proxy_address,
        proxy_port=settings.proxy_port,
        spoofed_host=settings.spoofed_host,
        socks_server=settings.socks_server,
        socks_port=settings.socks_port,
        stunnel_port=settings.stunnel_port,
        sni_domain=settings.sni_domain,
        cdn_domain=settings.cdn_domain,
        ws_path=settings.ws_path,
        ws_port=settings.ws_port,
        created_at=settings.created_at,
        updated_at=settings.updated_at,
    )


def _to_general_response(settings: GeneralSettings) -> GeneralSettingsResponse:
    return GeneralSettingsResponse(
        id=settings.id,
        server_address=settings.server_address,
        public_ipv4_address=settings.public_ipv4_address,
        public_ipv6_address=settings.public_ipv6_address,
        global_ipv6_support=settings.global_ipv6_support,
        wan_interface=settings.wan_interface,
        admin_allowed_ips=settings.admin_allowed_ips,
        panel_domain=settings.panel_domain,
        panel_https_port=settings.panel_https_port,
        subscription_domain=settings.subscription_domain,
        subscription_https_port=settings.subscription_https_port,
        ssl_mode=settings.ssl_mode,
        letsencrypt_email=settings.letsencrypt_email,
        force_https=settings.force_https,
        auto_renew_ssl=settings.auto_renew_ssl,
        custom_ssl_certificate=settings.custom_ssl_certificate,
        custom_ssl_private_key=settings.custom_ssl_private_key,
        system_timezone=settings.system_timezone,
        ntp_server=settings.ntp_server,
        created_at=settings.created_at,
        updated_at=settings.updated_at,
    )


@router.get("/general", response_model=GeneralSettingsResponse)
def get_general_settings(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    return _to_general_response(settings)


@router.patch("/general", response_model=GeneralSettingsResponse)
def update_general_settings(
    payload: GeneralSettingsUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)

    previous_ipv6_support = settings.global_ipv6_support
    previous_timezone = settings.system_timezone
    previous_panel_port = settings.panel_https_port
    previous_subscription_port = settings.subscription_https_port

    if payload.panel_https_port == payload.subscription_https_port:
        raise HTTPException(
            status_code=400,
            detail="Panel HTTPS Port and Subscription HTTPS Port must be different",
        )

    settings.public_ipv4_address = payload.public_ipv4_address
    settings.server_address = payload.server_address
    settings.public_ipv6_address = payload.public_ipv6_address
    settings.global_ipv6_support = payload.global_ipv6_support
    settings.wan_interface = payload.wan_interface
    settings.admin_allowed_ips = payload.admin_allowed_ips
    settings.panel_domain = payload.panel_domain or ""
    settings.panel_https_port = payload.panel_https_port
    settings.subscription_domain = payload.subscription_domain or ""
    settings.subscription_https_port = payload.subscription_https_port
    settings.ssl_mode = payload.ssl_mode
    settings.letsencrypt_email = payload.letsencrypt_email or None
    settings.force_https = payload.force_https
    settings.auto_renew_ssl = payload.auto_renew_ssl
    settings.custom_ssl_certificate = payload.custom_ssl_certificate
    settings.custom_ssl_private_key = payload.custom_ssl_private_key
    settings.system_timezone = payload.system_timezone
    settings.ntp_server = payload.ntp_server
    settings.updated_at = datetime.utcnow()

    sync_result = openvpn_manager.sync_system_general_settings(
        old_global_ipv6_support=previous_ipv6_support,
        new_global_ipv6_support=settings.global_ipv6_support,
        old_timezone=previous_timezone,
        new_timezone=settings.system_timezone,
        old_panel_https_port=previous_panel_port,
        new_panel_https_port=settings.panel_https_port,
        old_subscription_https_port=previous_subscription_port,
        new_subscription_https_port=settings.subscription_https_port,
    )
    if not sync_result.get("success"):
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=sync_result.get("message", "Failed to apply general system settings"),
        )

    db.commit()
    db.refresh(settings)
    return _to_general_response(settings)


@router.post("/ssl/issue")
def issue_ssl_certificate(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)

    if settings.panel_https_port == settings.subscription_https_port:
        raise HTTPException(
            status_code=400,
            detail="Panel HTTPS Port and Subscription HTTPS Port must be different",
        )

    if settings.ssl_mode != "auto":
        raise HTTPException(
            status_code=400,
            detail="SSL mode must be set to Auto (Let's Encrypt) before issuing certificates",
        )

    letsencrypt_email = (settings.letsencrypt_email or "").strip()
    if not letsencrypt_email:
        raise HTTPException(
            status_code=400,
            detail="Let's Encrypt email is required when SSL mode is Auto (Let's Encrypt)",
        )

    panel_domain = (settings.panel_domain or "").strip()
    subscription_domain = (settings.subscription_domain or "").strip()
    if not panel_domain and not subscription_domain:
        raise HTTPException(
            status_code=400,
            detail="At least one domain is required to issue SSL certificates",
        )

    def sse_stream():
        try:
            for line in openvpn_manager.stream_ssl_issue_logs(
                panel_domain=panel_domain,
                subscription_domain=subscription_domain,
                email=letsencrypt_email,
            ):
                sanitized = str(line).replace("\n", " ").strip()
                if sanitized:
                    yield f"data: {sanitized}\n\n"
            yield "data: >>> Stream completed.\n\n"
        except Exception as exc:
            yield f"data: >>> Error: {str(exc)}\n\n"

    return StreamingResponse(
        sse_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/openvpn", response_model=OpenVPNSettingsResponse)
def get_openvpn_settings(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_openvpn_settings(db)
    return _to_response(settings)


@router.patch("/openvpn", response_model=OpenVPNSettingsResponse)
def update_openvpn_settings(
    payload: OpenVPNSettingsUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_openvpn_settings(db)

    previous_port = settings.port
    previous_protocol = settings.protocol
    previous_obfuscation_mode = settings.obfuscation_mode
    previous_proxy_port = settings.proxy_port

    settings.port = payload.port
    settings.protocol = payload.protocol
    settings.device_type = payload.device_type
    settings.topology = payload.topology
    settings.ipv4_network = payload.ipv4_network
    settings.ipv4_netmask = payload.ipv4_netmask
    settings.ipv6_network = payload.ipv6_network
    settings.ipv6_prefix = payload.ipv6_prefix
    settings.ipv4_pool = f"{payload.ipv4_network} {payload.ipv4_netmask}".strip()
    settings.ipv6_pool = (
        f"{payload.ipv6_network}/{payload.ipv6_prefix}"
        if payload.ipv6_network and payload.ipv6_prefix is not None
        else None
    )
    settings.max_clients = payload.max_clients
    settings.client_to_client = payload.client_to_client

    settings.redirect_gateway = payload.redirect_gateway
    settings.primary_dns = payload.primary_dns
    settings.secondary_dns = payload.secondary_dns
    settings.block_outside_dns = payload.block_outside_dns
    settings.push_custom_routes = payload.push_custom_routes

    settings.data_ciphers = ":".join(payload.data_ciphers)
    settings.tls_version_min = payload.tls_version_min
    settings.tls_mode = payload.tls_mode
    settings.auth_digest = payload.auth_digest
    settings.reneg_sec = payload.reneg_sec

    settings.tun_mtu = payload.tun_mtu
    settings.mssfix = payload.mssfix
    settings.sndbuf = payload.sndbuf
    settings.rcvbuf = payload.rcvbuf
    settings.fast_io = payload.fast_io
    settings.tcp_nodelay = payload.tcp_nodelay
    settings.explicit_exit_notify = payload.explicit_exit_notify

    settings.keepalive_ping = payload.keepalive_ping
    settings.keepalive_timeout = payload.keepalive_timeout
    settings.inactive_timeout = payload.inactive_timeout
    settings.management_port = payload.management_port
    settings.verbosity = payload.verbosity

    settings.custom_directives = payload.custom_directives.strip() if payload.custom_directives else None
    settings.advanced_client_push = payload.advanced_client_push.strip() if payload.advanced_client_push else None
    
    # OS-Specific Custom Directives
    settings.custom_ios = payload.custom_ios.strip() if payload.custom_ios else None
    settings.custom_android = payload.custom_android.strip() if payload.custom_android else None
    settings.custom_windows = payload.custom_windows.strip() if payload.custom_windows else None
    settings.custom_mac = payload.custom_mac.strip() if payload.custom_mac else None
    
    settings.obfuscation_mode = payload.obfuscation_mode
    settings.proxy_server = payload.proxy_server
    settings.proxy_address = payload.proxy_address
    settings.proxy_port = payload.proxy_port
    settings.spoofed_host = payload.spoofed_host
    settings.socks_server = payload.socks_server
    settings.socks_port = payload.socks_port
    settings.stunnel_port = payload.stunnel_port
    settings.sni_domain = payload.sni_domain
    settings.cdn_domain = payload.cdn_domain
    settings.ws_path = payload.ws_path
    settings.ws_port = payload.ws_port
    settings.updated_at = datetime.utcnow()

    automation_result = obfuscation_manager.apply_mode_automation(
        previous_mode=previous_obfuscation_mode,
        previous_proxy_port=previous_proxy_port,
        settings=settings,
    )
    if not automation_result.get("success"):
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=automation_result.get("message", "Failed to apply obfuscation OS automation"),
        )

    firewall_result = openvpn_manager.sync_firewall_for_transport_change(
        old_port=previous_port,
        old_protocol=previous_protocol,
        new_port=settings.port,
        new_protocol=settings.protocol,
    )
    if not firewall_result.get("success"):
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=firewall_result.get("message", "Failed to update firewall rules"),
        )

    db.commit()
    db.refresh(settings)

    try:
        generation_result = openvpn_manager.generate_server_config(
            {
                "port": settings.port,
                "protocol": settings.protocol,
                "device_type": settings.device_type,
                "topology": settings.topology,
                "ipv4_network": settings.ipv4_network,
                "ipv4_netmask": settings.ipv4_netmask,
                "ipv4_pool": settings.ipv4_pool,
                "ipv6_network": settings.ipv6_network,
                "ipv6_prefix": settings.ipv6_prefix,
                "max_clients": settings.max_clients,
                "client_to_client": settings.client_to_client,
                "redirect_gateway": settings.redirect_gateway,
                "primary_dns": settings.primary_dns,
                "secondary_dns": settings.secondary_dns,
                "block_outside_dns": settings.block_outside_dns,
                "push_custom_routes": settings.push_custom_routes,
                "data_ciphers": settings.data_ciphers,
                "tls_version_min": settings.tls_version_min,
                "tls_mode": settings.tls_mode,
                "auth_digest": settings.auth_digest,
                "reneg_sec": settings.reneg_sec,
                "tun_mtu": settings.tun_mtu,
                "mssfix": settings.mssfix,
                "sndbuf": settings.sndbuf,
                "rcvbuf": settings.rcvbuf,
                "fast_io": settings.fast_io,
                "tcp_nodelay": settings.tcp_nodelay,
                "explicit_exit_notify": settings.explicit_exit_notify,
                "keepalive_ping": settings.keepalive_ping,
                "keepalive_timeout": settings.keepalive_timeout,
                "inactive_timeout": settings.inactive_timeout,
                "management_port": settings.management_port,
                "verbosity": settings.verbosity,
                "custom_directives": settings.custom_directives,
                "advanced_client_push": settings.advanced_client_push,
                "obfuscation_mode": settings.obfuscation_mode,
                "proxy_server": settings.proxy_server,
                "proxy_address": settings.proxy_address,
                "proxy_port": settings.proxy_port,
                "spoofed_host": settings.spoofed_host,
                "socks_server": settings.socks_server,
                "socks_port": settings.socks_port,
                "stunnel_port": settings.stunnel_port,
                "sni_domain": settings.sni_domain,
                "cdn_domain": settings.cdn_domain,
                "ws_path": settings.ws_path,
                "ws_port": settings.ws_port,
            }
        )
        if not generation_result.get("success"):
            raise HTTPException(
                status_code=500,
                detail=generation_result.get("message", "Failed to generate server configuration"),
            )
    except ValueError as ve:
        # Validation errors from generate_server_config (missing fields)
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Failed to generate server configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate server configuration")

    service_restart_result = openvpn_manager.control_service("restart")
    if not service_restart_result.get("success"):
        raise HTTPException(
            status_code=500,
            detail=service_restart_result.get("message", "Failed to restart OpenVPN service"),
        )

    return _to_response(settings)
