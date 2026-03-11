from datetime import datetime
import ipaddress
import logging
from pathlib import Path
import re
import shutil
import socket
import subprocess

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.core.tunnels.manager import TunnelManager
from backend.core.obfuscation_manager import ObfuscationManager
from backend.core.openvpn import OpenVPNManager
from backend.core.wireguard import WireGuardManager
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.general_settings import GeneralSettings
from backend.models.openvpn_settings import OpenVPNSettings
from backend.models.wireguard_settings import WireGuardSettings
from backend.models.user import Admin
from backend.schemas.general_settings import (
    GeneralSettingsResponse,
    GeneralSettingsUpdate,
    SSLCertificateIssueRequest,
)
from backend.schemas.openvpn_settings import OpenVPNSettingsResponse, OpenVPNSettingsUpdate
from backend.schemas.wireguard_settings import WireGuardSettingsResponse, WireGuardSettingsUpdate
from backend.services.audit_service import extract_client_ip, record_audit_event

router = APIRouter(prefix="/settings", tags=["Server Settings"])
openvpn_manager = OpenVPNManager()
obfuscation_manager = ObfuscationManager()
wireguard_manager = WireGuardManager()
tunnel_manager = TunnelManager()
logger = logging.getLogger(__name__)
RESOLVED_DROPIN_DIR = Path("/etc/systemd/resolved.conf.d")
ATLAS_DNS_DROPIN_FILE = RESOLVED_DROPIN_DIR / "atlas-dns.conf"


def _command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _detect_global_ip_from_interface(wan_interface: str, family: int) -> str | None:
    interface = (wan_interface or "").strip()
    if not interface:
        return None

    ip_flag = "-4" if family == 4 else "-6"
    token_prefix = "inet " if family == 4 else "inet6 "

    if not _command_exists("ip"):
        logger.warning("ip command is not available. Skipping interface IP detection.")
        return None

    try:
        result = subprocess.run(
            ["ip", ip_flag, "addr", "show", "dev", interface, "scope", "global"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped.startswith(token_prefix):
                continue

            parts = stripped.split()
            if len(parts) < 2:
                continue

            candidate = parts[1].strip().split("/")[0].strip()
            if not candidate:
                continue

            try:
                parsed_ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue

            if parsed_ip.version != family:
                continue
            if family == 6 and parsed_ip.is_link_local:
                continue

            return candidate
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        logger.warning("ip command not found while detecting interface IP.")
        return None
    except Exception:
        return None

    return None


def _detect_public_ipv4(wan_interface: str | None = None) -> str:
    wan_interface = (wan_interface or "").strip() or _detect_wan_interface()
    detected = _detect_global_ip_from_interface(wan_interface, family=4)
    return detected or "N/A"


def _detect_ipv6_from_interface(wan_interface: str) -> str | None:
    return _detect_global_ip_from_interface(wan_interface, family=6)


def _detect_public_ipv6(wan_interface: str | None = None) -> str:
    if not socket.has_ipv6:
        return "Not Configured"

    resolved_wan = (wan_interface or "").strip() or _detect_wan_interface()
    local_ipv6 = _detect_ipv6_from_interface(resolved_wan)
    if local_ipv6:
        return local_ipv6

    return "Not Configured"


def _detect_wan_interface() -> str:
    if not _command_exists("ip"):
        logger.warning("ip command is not available. Falling back to default WAN interface eth0.")
        return "eth0"

    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        logger.warning("ip command not found while detecting WAN interface. Using eth0.")
    except Exception:
        pass
    return "eth0"


def _extract_dns_ips(raw_text: str) -> list[str]:
    results: list[str] = []
    for line in (raw_text or "").splitlines():
        normalized_line = line.strip()
        if not normalized_line:
            continue

        tokens = normalized_line.split()
        for token in tokens:
            candidate = token.strip().strip(",;[]()")
            if not candidate:
                continue
            try:
                parsed_ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue

            if parsed_ip.version not in (4, 6):
                continue
            if candidate not in results:
                results.append(candidate)
    return results


def _read_dns_from_resolvectl_dns(wan_interface: str) -> list[str]:
    if not _command_exists("resolvectl"):
        logger.warning("resolvectl is not available. Skipping resolvectl dns lookup.")
        return []

    try:
        result = subprocess.run(
            ["resolvectl", "dns", wan_interface],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return _extract_dns_ips(result.stdout)
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        logger.warning("resolvectl command not found during DNS lookup.")
    except Exception:
        pass
    return []


def _read_dns_from_atlas_dropin() -> list[str]:
    try:
        if not ATLAS_DNS_DROPIN_FILE.exists():
            return []

        raw_content = ATLAS_DNS_DROPIN_FILE.read_text(encoding="utf-8", errors="ignore")
        dns_lines: list[str] = []
        for line in raw_content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            if stripped.lower().startswith("dns="):
                dns_lines.append(stripped.split("=", 1)[1].strip())

        if not dns_lines:
            return []

        return _extract_dns_ips("\n".join(dns_lines))
    except Exception:
        return []


def _read_dns_from_resolvectl_status(wan_interface: str) -> list[str]:
    if not _command_exists("resolvectl"):
        logger.warning("resolvectl is not available. Skipping resolvectl status lookup.")
        return []

    try:
        result = subprocess.run(
            ["resolvectl", "status", wan_interface],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []

        status_lines = result.stdout.splitlines()
        dns_lines: list[str] = []
        capture_continuation = False
        for line in status_lines:
            stripped = line.strip()
            if not stripped:
                capture_continuation = False
                continue

            if stripped.startswith("DNS Servers:") or stripped.startswith("Current DNS Server:"):
                dns_lines.append(stripped)
                capture_continuation = True
                continue

            if capture_continuation and line.startswith(" "):
                dns_lines.append(stripped)
                continue

            capture_continuation = False

        return _extract_dns_ips("\n".join(dns_lines))
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        logger.warning("resolvectl command not found during status lookup.")
    except Exception:
        pass
    return []


def _read_dns_from_resolv_conf() -> list[str]:
    try:
        resolv_path = Path("/etc/resolv.conf")
        if resolv_path.exists():
            return _extract_dns_ips(resolv_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        pass
    return []


def _read_system_dns_servers() -> tuple[str, str]:
    primary = "1.1.1.1"
    secondary = "8.8.8.8"
    wan_interface = _detect_wan_interface()
    detected_dns = _read_dns_from_atlas_dropin()

    if not detected_dns:
        detected_dns = _read_dns_from_resolvectl_dns(wan_interface)

    if not detected_dns:
        detected_dns = _read_dns_from_resolv_conf()

    if detected_dns == ["127.0.0.53"]:
        resolved_dns = _read_dns_from_resolvectl_status(wan_interface)
        if resolved_dns:
            detected_dns = resolved_dns

    if detected_dns:
        primary = detected_dns[0]
    if len(detected_dns) > 1:
        secondary = detected_dns[1]

    return primary, secondary


def _apply_system_dns_servers(wan_interface: str, primary_dns: str, secondary_dns: str) -> dict:
    try:
        RESOLVED_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
        dropin_content = (
            "[Resolve]\n"
            f"DNS={primary_dns} {secondary_dns}\n"
            "Domains=~.\n"
        )
        ATLAS_DNS_DROPIN_FILE.write_text(dropin_content, encoding="utf-8")

        if _command_exists("systemctl"):
            restart_result = subprocess.run(
                ["systemctl", "restart", "systemd-resolved"],
                capture_output=True,
                text=True,
                check=False,
            )
            if restart_result.returncode != 0:
                return {
                    "success": False,
                    "message": (restart_result.stderr or restart_result.stdout or "failed to restart systemd-resolved").strip(),
                }
        else:
            logger.warning("systemctl is not available. Skipping systemd-resolved restart.")

        if _command_exists("resolvectl"):
            flush_result = subprocess.run(
                ["resolvectl", "flush-caches"],
                capture_output=True,
                text=True,
                check=False,
            )
            if flush_result.returncode != 0:
                logger.warning(
                    "resolvectl cache flush failed: %s",
                    (flush_result.stderr or flush_result.stdout or "failed to flush resolvectl caches").strip(),
                )
        else:
            logger.warning("resolvectl is not available. Skipping DNS cache flush.")

        return {"success": True, "method": "resolved-dropin"}
    except subprocess.CalledProcessError as exc:
        return {"success": False, "message": f"failed to apply system DNS: {exc}"}
    except FileNotFoundError as exc:
        logger.warning("System command missing while applying DNS settings: %s", exc)
        return {"success": True, "method": "resolved-dropin", "message": "DNS applied; skipped missing system command"}
    except Exception as exc:
        return {"success": False, "message": f"failed to apply system DNS: {exc}"}


def _get_or_create_openvpn_settings(db: Session) -> OpenVPNSettings:
    settings = db.query(OpenVPNSettings).order_by(OpenVPNSettings.id.asc()).first()
    if settings:
        return settings

    settings = OpenVPNSettings()
    db.add(settings)
    db.commit()
    _sync_openvpn_auth_db_snapshot()
    db.refresh(settings)
    return settings


def _get_or_create_wireguard_settings(db: Session) -> WireGuardSettings:
    settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
    if settings:
        return settings

    settings = WireGuardSettings()
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
    _sync_openvpn_auth_db_snapshot()
    db.refresh(settings)
    return settings


def _apply_dnstt_runtime(settings: GeneralSettings) -> dict:
    settings.tunnel_mode = "dnstt"
    tunnel = tunnel_manager.get_tunnel(settings)
    if not hasattr(tunnel, "setup_server"):
        return {"success": False, "message": "DNSTT server setup operation is not available"}

    server_result = tunnel.setup_server()
    if not server_result.get("success"):
        return {
            "success": False,
            "message": server_result.get("message", "DNSTT server setup failed"),
            "server": server_result,
        }

    architecture = str(getattr(settings, "tunnel_architecture", "standalone") or "standalone").strip().lower()
    client_result = None
    if architecture == "relay":
        if not hasattr(tunnel, "setup_client"):
            return {"success": False, "message": "DNSTT client setup operation is not available for relay mode", "server": server_result}
        client_result = tunnel.setup_client()
        if not client_result.get("success"):
            return {
                "success": False,
                "message": client_result.get("message", "DNSTT client setup failed"),
                "server": server_result,
                "client": client_result,
            }

    return {
        "success": True,
        "message": "DNSTT runtime applied",
        "server": server_result,
        "client": client_result,
    }


def _to_response(settings: OpenVPNSettings) -> OpenVPNSettingsResponse:
    allowed_ciphers = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]
    raw_ciphers = (settings.data_ciphers or "").strip()

    ciphers = [
        item.strip().upper()
        for item in raw_ciphers.split(":")
        if item and item.strip()
    ]
    ciphers = [cipher for cipher in ciphers if cipher in allowed_ciphers]

    # Recover from previously corrupted char-split values like A:E:S:-:2:5:6...
    if not ciphers:
        compact = raw_ciphers.replace(":", "").upper()
        if all(cipher.replace("-", "") in compact for cipher in ["AES-256-GCM", "AES-128-GCM"]):
            ciphers = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]
        else:
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
        enable_auth_nocache=settings.enable_auth_nocache,
        resolv_retry_mode=settings.resolv_retry_mode,
        persist_key=settings.persist_key,
        persist_tun=settings.persist_tun,
        enable_dns_leak_protection=settings.enable_dns_leak_protection,
        custom_directives=settings.custom_directives,
        advanced_client_push=settings.advanced_client_push,
        custom_ios=settings.custom_ios,
        custom_android=settings.custom_android,
        custom_windows=settings.custom_windows,
        custom_mac=settings.custom_mac,
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


def _to_wireguard_response(settings: WireGuardSettings) -> WireGuardSettingsResponse:
    return WireGuardSettingsResponse(
        id=settings.id,
        interface_name=settings.interface_name,
        listen_port=settings.listen_port,
        address_range=settings.address_range,
        endpoint_address=settings.endpoint_address,
        server_public_key=settings.server_public_key,
        created_at=settings.created_at,
        updated_at=settings.updated_at,
    )


def _sync_openvpn_auth_db_snapshot() -> None:
    """Best-effort sync of OpenVPN auth DB snapshot after settings updates."""
    try:
        result = openvpn_manager.sync_auth_database_snapshot()
        if not result.get("success"):
            logger.warning("OpenVPN auth DB sync warning after settings update: %s", result.get("message"))
    except Exception as exc:
        logger.warning("Failed to sync OpenVPN auth DB snapshot after settings update: %s", exc)


def _to_general_response(settings: GeneralSettings) -> GeneralSettingsResponse:
    return GeneralSettingsResponse(
        id=settings.id,
        server_address=settings.server_address,
        public_ipv4_address=settings.public_ipv4_address,
        public_ipv6_address=settings.public_ipv6_address,
        global_ipv6_support=settings.global_ipv6_support,
        wan_interface=settings.wan_interface,
        server_system_dns_primary=settings.server_system_dns_primary,
        server_system_dns_secondary=settings.server_system_dns_secondary,
        admin_allowed_ips=settings.admin_allowed_ips,
        login_max_failed_attempts=settings.login_max_failed_attempts,
        login_block_duration_minutes=settings.login_block_duration_minutes,
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
        is_tunnel_enabled=settings.is_tunnel_enabled,
        tunnel_mode=settings.tunnel_mode,
        foreign_server_ip=settings.foreign_server_ip,
        foreign_server_port=settings.foreign_server_port,
        foreign_ssh_user=settings.foreign_ssh_user,
        foreign_ssh_password=settings.foreign_ssh_password,
        tunnel_architecture=settings.tunnel_architecture,
        dnstt_domain=settings.dnstt_domain,
        dnstt_active_domain=settings.dnstt_active_domain,
        dnstt_dns_resolver=settings.dnstt_dns_resolver,
        dnstt_resolver_strategy=settings.dnstt_resolver_strategy,
        dnstt_duplication_mode=settings.dnstt_duplication_mode,
        dnstt_mtu_mode=settings.dnstt_mtu_mode,
        dnstt_mtu=settings.dnstt_mtu,
        dnstt_mtu_upload_min=settings.dnstt_mtu_upload_min,
        dnstt_mtu_upload_max=settings.dnstt_mtu_upload_max,
        dnstt_mtu_download_min=settings.dnstt_mtu_download_min,
        dnstt_mtu_download_max=settings.dnstt_mtu_download_max,
        dnstt_adaptive_per_resolver=settings.dnstt_adaptive_per_resolver,
        dnstt_transport_probe_workers=settings.dnstt_transport_probe_workers,
        dnstt_transport_retry_count=settings.dnstt_transport_retry_count,
        dnstt_transport_probe_timeout_ms=settings.dnstt_transport_probe_timeout_ms,
        dnstt_transport_switch_threshold_percent=settings.dnstt_transport_switch_threshold_percent,
        dnstt_telemetry=settings.dnstt_telemetry,
        dnstt_telemetry_history=settings.dnstt_telemetry_history,
        dnstt_pubkey=settings.dnstt_pubkey,
        dnstt_privkey=settings.dnstt_privkey,
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

    detected_wan = _detect_wan_interface()
    detected_ipv4 = _detect_public_ipv4(detected_wan)
    detected_ipv6 = _detect_public_ipv6(detected_wan)
    dns_primary, dns_secondary = _read_system_dns_servers()
    has_change = False

    normalized_ipv4 = None if detected_ipv4 == "N/A" else detected_ipv4
    normalized_ipv6 = None if detected_ipv6 == "Not Configured" else detected_ipv6

    if (settings.wan_interface or "").strip() != detected_wan:
        settings.wan_interface = detected_wan
        has_change = True
    if (settings.public_ipv4_address or None) != normalized_ipv4:
        settings.public_ipv4_address = normalized_ipv4
        has_change = True
    if (settings.public_ipv6_address or None) != normalized_ipv6:
        settings.public_ipv6_address = normalized_ipv6
        has_change = True
    if (settings.server_system_dns_primary or "").strip() != dns_primary:
        settings.server_system_dns_primary = dns_primary
        has_change = True
    if (settings.server_system_dns_secondary or "").strip() != dns_secondary:
        settings.server_system_dns_secondary = dns_secondary
        has_change = True

    if has_change:
        settings.updated_at = datetime.utcnow()
        db.commit()
        _sync_openvpn_auth_db_snapshot()
        db.refresh(settings)

    return _to_general_response(settings)


@router.post("/tunnel/dnstt/install-generate")
def install_and_generate_dnstt(
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    settings = _get_or_create_general_settings(db)
    settings.tunnel_mode = "dnstt"
    tunnel = tunnel_manager.get_tunnel(settings)

    if not hasattr(tunnel, "install_dependencies") or not hasattr(tunnel, "generate_keys"):
        raise HTTPException(status_code=400, detail="DNSTT engine is not available")

    dns_preflight_ok = True
    if hasattr(tunnel, "verify_dns_delegation"):
        dns_preflight_ok = bool(
            tunnel.verify_dns_delegation(
                getattr(settings, "dnstt_active_domain", None) or getattr(settings, "dnstt_domain", None)
            )
        )

    install_result = tunnel.install_dependencies()
    if not install_result.get("success"):
        detail_message = str(install_result.get("message") or "DNSTT install failed")
        local_info = install_result.get("local") or {}
        foreign_info = install_result.get("foreign") or {}
        local_error = str(local_info.get("error") or "").strip()
        foreign_error = str(foreign_info.get("error") or "").strip()

        if local_error:
            detail_message = f"{detail_message}: {local_error}"
        elif foreign_error:
            detail_message = f"{detail_message}: {foreign_error}"

        local_results = local_info.get("results") or []
        foreign_results = foreign_info.get("results") or []
        if isinstance(local_results, list) and local_results:
            failed_command = str((local_results[-1] or {}).get("command") or "").strip()
            if failed_command:
                detail_message = f"{detail_message} [command: {failed_command}]"
        elif isinstance(foreign_results, list) and foreign_results:
            failed_command = str((foreign_results[-1] or {}).get("command") or "").strip()
            if failed_command:
                detail_message = f"{detail_message} [command: {failed_command}]"

        record_audit_event(
            action="dnstt_install_generate",
            success=False,
            admin_username=current_user.username,
            resource_type="system_tunnel",
            resource_id="dnstt",
            ip_address=extract_client_ip(request),
            details={
                "stage": "install",
                "message": install_result.get("message"),
                "detail_message": detail_message,
            },
        )
        raise HTTPException(status_code=500, detail=detail_message)

    keys_result = tunnel.generate_keys()
    if not keys_result.get("success"):
        record_audit_event(
            action="dnstt_install_generate",
            success=False,
            admin_username=current_user.username,
            resource_type="system_tunnel",
            resource_id="dnstt",
            ip_address=extract_client_ip(request),
            details={"stage": "generate_keys", "message": keys_result.get("message")},
        )
        raise HTTPException(status_code=500, detail=keys_result.get("message", "DNSTT key generation failed"))

    settings.dnstt_pubkey = keys_result.get("dnstt_pubkey")
    settings.dnstt_privkey = keys_result.get("dnstt_privkey")
    settings.updated_at = datetime.utcnow()

    runtime_result = _apply_dnstt_runtime(settings)
    if not runtime_result.get("success"):
        record_audit_event(
            action="dnstt_install_generate",
            success=False,
            admin_username=current_user.username,
            resource_type="system_tunnel",
            resource_id="dnstt",
            ip_address=extract_client_ip(request),
            details={
                "stage": "runtime_apply",
                "message": runtime_result.get("message"),
                "runtime_result": runtime_result,
            },
        )
        raise HTTPException(status_code=500, detail=runtime_result.get("message", "DNSTT runtime apply failed"))

    db.commit()
    db.refresh(settings)

    record_audit_event(
        action="dnstt_install_generate",
        success=True,
        admin_username=current_user.username,
        resource_type="system_tunnel",
        resource_id="dnstt",
        ip_address=extract_client_ip(request),
        details={
            "architecture": settings.tunnel_architecture,
            "domain": settings.dnstt_domain,
            "active_domain": settings.dnstt_active_domain,
        },
    )

    return {
        "success": True,
        "message": "DNSTT dependencies installed, keys generated, and runtime applied",
        "dns_preflight_ok": dns_preflight_ok,
        "dnstt_pubkey": settings.dnstt_pubkey,
        "dnstt_privkey": settings.dnstt_privkey,
        "install_result": install_result,
        "keys_result": keys_result,
        "runtime_result": runtime_result,
    }


@router.get("/tunnel/dnstt/probe-mtu")
def probe_dnstt_mtu(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    settings.tunnel_mode = "dnstt"
    tunnel = tunnel_manager.get_tunnel(settings)

    if not hasattr(tunnel, "probe_optimal_mtu"):
        raise HTTPException(status_code=400, detail="DNSTT MTU probe is not available")

    resolver_list = str(getattr(settings, "dnstt_dns_resolver", "8.8.8.8") or "8.8.8.8")
    try:
        recommended_mtu = int(tunnel.probe_optimal_mtu(resolver_list))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DNSTT MTU probe failed: {exc}") from exc

    if not 50 <= recommended_mtu <= 1400:
        recommended_mtu = 50

    return {"recommended_mtu": recommended_mtu}


@router.get("/tunnel/dnstt/diagnostics")
def dnstt_diagnostics(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    settings.tunnel_mode = "dnstt"
    tunnel = tunnel_manager.get_tunnel(settings)

    if not hasattr(tunnel, "collect_diagnostics"):
        raise HTTPException(status_code=400, detail="DNSTT diagnostics is not available")

    try:
        report = tunnel.collect_diagnostics()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DNSTT diagnostics failed: {exc}") from exc

    return report


@router.get("/tunnel/dnstt/client-profile")
def dnstt_client_profile(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    settings.tunnel_mode = "dnstt"
    tunnel = tunnel_manager.get_tunnel(settings)

    if not hasattr(tunnel, "generate_client_profile"):
        raise HTTPException(status_code=400, detail="DNSTT client profile generator is not available")

    try:
        profile_result = tunnel.generate_client_profile()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DNSTT client profile generation failed: {exc}") from exc

    if not profile_result.get("success"):
        raise HTTPException(status_code=400, detail=profile_result.get("message", "DNSTT client profile generation failed"))

    profile_payload = profile_result.get("profile") or {}
    active_domain = str(profile_payload.get("server", {}).get("domain") or "dnstt-client").strip()
    safe_domain = re.sub(r"[^A-Za-z0-9_.-]+", "_", active_domain) or "dnstt-client"
    profile_filename = f"{safe_domain}-dnstt-client-profile.json"

    return {
        "success": True,
        "message": profile_result.get("message", "DNSTT client profile generated"),
        "filename": profile_filename,
        "profile": profile_payload,
    }


@router.get("/tunnel/dnstt/http-injector-starter")
def dnstt_http_injector_starter(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    settings.tunnel_mode = "dnstt"
    tunnel = tunnel_manager.get_tunnel(settings)

    if not hasattr(tunnel, "generate_http_injector_starter"):
        raise HTTPException(status_code=400, detail="DNSTT HTTP Injector starter generator is not available")

    try:
        starter_result = tunnel.generate_http_injector_starter()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DNSTT HTTP Injector starter generation failed: {exc}") from exc

    if not starter_result.get("success"):
        raise HTTPException(status_code=400, detail=starter_result.get("message", "DNSTT HTTP Injector starter generation failed"))

    starter_payload = starter_result.get("starter") or {}
    active_domain = str(starter_payload.get("dnstt_reference", {}).get("domain") or "dnstt-http-injector").strip()
    safe_domain = re.sub(r"[^A-Za-z0-9_.-]+", "_", active_domain) or "dnstt-http-injector"
    starter_filename = f"{safe_domain}-http-injector-starter.json"

    return {
        "success": True,
        "message": starter_result.get("message", "HTTP Injector starter generated"),
        "filename": starter_filename,
        "starter": starter_payload,
    }


@router.get("/server-ips")
def get_server_public_ips(current_user: Admin = Depends(get_current_user)):
    _ = current_user
    detected_wan = _detect_wan_interface()
    return {
        "public_ipv4": _detect_public_ipv4(detected_wan),
        "public_ipv6": _detect_public_ipv6(detected_wan),
    }


@router.patch("/general", response_model=GeneralSettingsResponse)
def update_general_settings(
    payload: GeneralSettingsUpdate,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    detected_wan = _detect_wan_interface()

    previous_ipv6_support = settings.global_ipv6_support
    current_timezone = "UTC"
    current_ntp_server = settings.ntp_server
    previous_panel_port = settings.panel_https_port
    previous_subscription_port = settings.subscription_https_port
    previous_admin_allowed_ips = settings.admin_allowed_ips or ""
    previous_login_max_failed_attempts = settings.login_max_failed_attempts
    previous_login_block_duration_minutes = settings.login_block_duration_minutes

    if payload.panel_https_port == payload.subscription_https_port:
        raise HTTPException(
            status_code=400,
            detail="Panel HTTPS Port and Subscription HTTPS Port must be different",
        )

    detected_ipv4 = _detect_public_ipv4(detected_wan)
    detected_ipv6 = _detect_public_ipv6(detected_wan)

    settings.server_address = payload.server_address
    settings.public_ipv4_address = None if detected_ipv4 == "N/A" else detected_ipv4
    settings.public_ipv6_address = None if detected_ipv6 == "Not Configured" else detected_ipv6
    settings.global_ipv6_support = payload.global_ipv6_support
    settings.wan_interface = detected_wan
    settings.server_system_dns_primary = payload.server_system_dns_primary
    settings.server_system_dns_secondary = payload.server_system_dns_secondary
    settings.admin_allowed_ips = payload.admin_allowed_ips
    settings.login_max_failed_attempts = payload.login_max_failed_attempts
    settings.login_block_duration_minutes = payload.login_block_duration_minutes
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
    settings.system_timezone = "UTC"
    settings.ntp_server = current_ntp_server
    settings.is_tunnel_enabled = payload.is_tunnel_enabled
    settings.tunnel_mode = payload.tunnel_mode
    settings.foreign_server_ip = payload.foreign_server_ip
    settings.foreign_server_port = payload.foreign_server_port
    settings.foreign_ssh_user = payload.foreign_ssh_user
    settings.foreign_ssh_password = payload.foreign_ssh_password
    settings.tunnel_architecture = payload.tunnel_architecture
    settings.dnstt_domain = payload.dnstt_domain
    settings.dnstt_active_domain = payload.dnstt_active_domain
    settings.dnstt_dns_resolver = payload.dnstt_dns_resolver
    settings.dnstt_resolver_strategy = payload.dnstt_resolver_strategy
    settings.dnstt_duplication_mode = payload.dnstt_duplication_mode
    settings.dnstt_mtu_mode = payload.dnstt_mtu_mode
    settings.dnstt_mtu = payload.dnstt_mtu
    settings.dnstt_mtu_upload_min = payload.dnstt_mtu_upload_min
    settings.dnstt_mtu_upload_max = payload.dnstt_mtu_upload_max
    settings.dnstt_mtu_download_min = payload.dnstt_mtu_download_min
    settings.dnstt_mtu_download_max = payload.dnstt_mtu_download_max
    settings.dnstt_adaptive_per_resolver = payload.dnstt_adaptive_per_resolver
    settings.dnstt_transport_probe_workers = payload.dnstt_transport_probe_workers
    settings.dnstt_transport_retry_count = payload.dnstt_transport_retry_count
    settings.dnstt_transport_probe_timeout_ms = payload.dnstt_transport_probe_timeout_ms
    settings.dnstt_transport_switch_threshold_percent = payload.dnstt_transport_switch_threshold_percent
    settings.dnstt_telemetry = payload.dnstt_telemetry
    settings.dnstt_telemetry_history = payload.dnstt_telemetry_history
    settings.dnstt_pubkey = payload.dnstt_pubkey
    settings.dnstt_privkey = payload.dnstt_privkey
    settings.updated_at = datetime.utcnow()

    dns_apply_result = _apply_system_dns_servers(
        wan_interface=detected_wan,
        primary_dns=payload.server_system_dns_primary,
        secondary_dns=payload.server_system_dns_secondary,
    )
    if not dns_apply_result.get("success"):
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=dns_apply_result.get("message", "Failed to update server DNS settings"),
        )

    sync_result = openvpn_manager.sync_system_general_settings(
        old_global_ipv6_support=previous_ipv6_support,
        new_global_ipv6_support=settings.global_ipv6_support,
        old_timezone=current_timezone,
        new_timezone=current_timezone,
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

    runtime_result = None
    if settings.is_tunnel_enabled and str(settings.tunnel_mode or "").strip().lower() == "dnstt":
        runtime_result = _apply_dnstt_runtime(settings)
        if not runtime_result.get("success"):
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail=runtime_result.get("message", "Failed to apply DNSTT runtime settings"),
            )

    db.commit()
    _sync_openvpn_auth_db_snapshot()
    db.refresh(settings)

    changed_fields: list[str] = []
    if previous_admin_allowed_ips != settings.admin_allowed_ips:
        changed_fields.append("admin_allowed_ips")
    if previous_login_max_failed_attempts != settings.login_max_failed_attempts:
        changed_fields.append("login_max_failed_attempts")
    if previous_login_block_duration_minutes != settings.login_block_duration_minutes:
        changed_fields.append("login_block_duration_minutes")
    if previous_panel_port != settings.panel_https_port:
        changed_fields.append("panel_https_port")
    if previous_subscription_port != settings.subscription_https_port:
        changed_fields.append("subscription_https_port")

    record_audit_event(
        action="general_settings_updated",
        success=True,
        admin_username=current_user.username,
        resource_type="general_settings",
        resource_id=str(settings.id),
        ip_address=extract_client_ip(request),
        details={
            "changed_fields": changed_fields,
            "dnstt_runtime_applied": bool(runtime_result and runtime_result.get("success")),
        },
    )

    return _to_general_response(settings)


@router.post("/ssl/issue")
def issue_ssl_certificate(
    payload: SSLCertificateIssueRequest,
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

    letsencrypt_email = (settings.letsencrypt_email or "").strip()
    if not letsencrypt_email:
        raise HTTPException(
            status_code=400,
            detail="Let's Encrypt email is required when SSL mode is Auto (Let's Encrypt)",
        )

    domains = [str(domain).strip() for domain in (payload.domains or []) if str(domain).strip()]
    if not domains:
        raise HTTPException(
            status_code=400,
            detail="At least one domain is required in payload to issue SSL certificates",
        )

    def sse_stream():
        try:
            for line in openvpn_manager.stream_ssl_issue_logs(
                domains=domains,
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


@router.get("/wireguard", response_model=WireGuardSettingsResponse)
def get_wireguard_settings(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_wireguard_settings(db)
    return _to_wireguard_response(settings)


@router.put("/wireguard", response_model=WireGuardSettingsResponse)
def update_wireguard_settings(
    payload: WireGuardSettingsUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_wireguard_settings(db)
    general_settings = _get_or_create_general_settings(db)

    if not (settings.server_private_key or "").strip() or not (settings.server_public_key or "").strip():
        try:
            private_key, public_key = wireguard_manager.generate_server_keypair()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to generate WireGuard server keys: {exc}") from exc

        settings.server_private_key = private_key
        settings.server_public_key = public_key
        settings.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(settings)

    settings.interface_name = payload.interface_name
    settings.listen_port = payload.listen_port
    settings.address_range = payload.address_range
    settings.endpoint_address = payload.endpoint_address
    settings.updated_at = datetime.utcnow()

    try:
        wireguard_manager.write_server_config(
            interface_name=settings.interface_name,
            listen_port=settings.listen_port,
            address_range=settings.address_range,
            private_key=settings.server_private_key or "",
            wan_interface=general_settings.wan_interface,
        )
        apply_result = wireguard_manager.apply_interface(settings.interface_name)
        if not apply_result.get("success"):
            raise HTTPException(status_code=500, detail=apply_result.get("message", "Failed to apply WireGuard interface"))
    except HTTPException:
        db.rollback()
        raise
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to apply WireGuard settings: {exc}") from exc

    db.commit()
    db.refresh(settings)
    return _to_wireguard_response(settings)


@router.get("/openvpn/auth-assets/health")
def get_openvpn_auth_assets_health(
    current_user: Admin = Depends(get_current_user),
):
    _ = current_user
    return openvpn_manager.get_auth_assets_health()


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

    if isinstance(payload.data_ciphers, list):
        settings.data_ciphers = ":".join(payload.data_ciphers)
    else:
        settings.data_ciphers = str(payload.data_ciphers or "").strip()
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
    settings.enable_auth_nocache = payload.enable_auth_nocache
    settings.resolv_retry_mode = payload.resolv_retry_mode
    settings.persist_key = payload.persist_key
    settings.persist_tun = payload.persist_tun
    settings.enable_dns_leak_protection = payload.enable_dns_leak_protection

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
    _sync_openvpn_auth_db_snapshot()
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
                "enable_auth_nocache": settings.enable_auth_nocache,
                "enable_dns_leak_protection": settings.enable_dns_leak_protection,
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
