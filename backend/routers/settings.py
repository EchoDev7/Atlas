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
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.ppp_manager import PPPManager
from backend.core.routing.pbr_manager import PBRManager
from backend.core.obfuscation_manager import ObfuscationManager
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
from backend.services.protocols.registry import protocol_registry

router = APIRouter(prefix="/settings", tags=["Server Settings"])
openvpn_service = protocol_registry.get("openvpn")
obfuscation_manager = ObfuscationManager()
wireguard_service = protocol_registry.get("wireguard")
openconnect_service = protocol_registry.get("openconnect")
singbox_service = protocol_registry.get("singbox")
logger = logging.getLogger(__name__)
RESOLVED_DROPIN_DIR = Path("/etc/systemd/resolved.conf.d")
ATLAS_DNS_DROPIN_FILE = RESOLVED_DROPIN_DIR / "atlas-dns.conf"
SINGBOX_BINARY_PATH = "/usr/local/bin/sing-box"


class SingBoxRealityKeypairResponse(BaseModel):
    success: bool
    public_key: str
    private_key: str
    message: str


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


def _parse_reality_keypair_output(stdout: str) -> tuple[str, str]:
    output = str(stdout or "")
    private_match = re.search(r"PrivateKey:\s*(\S+)", output)
    public_match = re.search(r"PublicKey:\s*(\S+)", output)
    if not private_match or not public_match:
        raise ValueError("Could not parse sing-box reality keypair output")
    private_key = private_match.group(1).strip()
    public_key = public_match.group(1).strip()
    if not private_key or not public_key:
        raise ValueError("Generated sing-box reality keypair is empty")
    return private_key, public_key


def _generate_singbox_reality_keypair() -> tuple[str, str]:
    process = subprocess.run(
        [SINGBOX_BINARY_PATH, "generate", "reality-keypair"],
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(process.stderr.strip() or process.stdout.strip() or "Failed to generate sing-box reality keypair")
    return _parse_reality_keypair_output(process.stdout)


def _ensure_singbox_reality_keypair(db: Session, settings: GeneralSettings) -> bool:
    private_key = (getattr(settings, "singbox_reality_private_key", "") or "").strip()
    if private_key:
        return False
    generated_private_key, generated_public_key = _generate_singbox_reality_keypair()
    settings.singbox_reality_private_key = generated_private_key
    settings.singbox_reality_public_key = generated_public_key
    settings.updated_at = datetime.utcnow()
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return True


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
        result = openvpn_service.sync_auth_database_snapshot()
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
        l2tp_ipsec_psk=settings.l2tp_ipsec_psk,
        l2tp_client_subnet=settings.l2tp_client_subnet,
        ocserv_port=settings.ocserv_port,
        ocserv_client_subnet=settings.ocserv_client_subnet,
        singbox_log_level=settings.singbox_log_level,
        enable_vless=settings.enable_vless,
        vless_port=settings.vless_port,
        singbox_reality_sni=settings.singbox_reality_sni,
        singbox_reality_public_key=settings.singbox_reality_public_key,
        singbox_reality_private_key=settings.singbox_reality_private_key,
        singbox_reality_short_ids=settings.singbox_reality_short_ids,
        is_tunnel_enabled=settings.is_tunnel_enabled,
        foreign_server_ip=settings.foreign_server_ip,
        foreign_server_port=settings.foreign_server_port,
        foreign_ssh_user=settings.foreign_ssh_user,
        foreign_ssh_password=settings.foreign_ssh_password,
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
        created_at=settings.created_at,
        updated_at=settings.updated_at,
    )


def _validate_global_port_anti_collision(
    *,
    openvpn_port: int,
    wireguard_port: int,
    ocserv_port: int,
    vless_port: int,
    panel_https_port: int,
    subscription_https_port: int,
) -> None:
    allocated = {
        "OpenVPN": int(openvpn_port),
        "WireGuard": int(wireguard_port),
        "OpenConnect": int(ocserv_port),
        "VLESS": int(vless_port),
        "Panel HTTPS": int(panel_https_port),
        "Subscription HTTPS": int(subscription_https_port),
    }
    seen: dict[int, str] = {}
    for owner, port in allocated.items():
        if port in seen:
            raise HTTPException(
                status_code=400,
                detail=f"Port conflict detected: Port {port} is already used by another protocol.",
            )
        seen[port] = owner


@router.get("/general", response_model=GeneralSettingsResponse)
def get_general_settings(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    _ensure_singbox_reality_keypair(db, settings)

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


@router.post("/singbox/reality-keypair", response_model=SingBoxRealityKeypairResponse)
def regenerate_singbox_reality_keypair(
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_general_settings(db)
    try:
        private_key, public_key = _generate_singbox_reality_keypair()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate sing-box reality keypair: {exc}") from exc

    settings.singbox_reality_private_key = private_key
    settings.singbox_reality_public_key = public_key
    settings.updated_at = datetime.utcnow()
    db.commit()
    _sync_openvpn_auth_db_snapshot()
    db.refresh(settings)

    record_audit_event(
        action="singbox_reality_keypair_regenerated",
        success=True,
        admin_username=current_user.username,
        resource_type="general_settings",
        resource_id=str(settings.id),
        ip_address=extract_client_ip(request),
        details={"updated_fields": ["singbox_reality_private_key", "singbox_reality_public_key"]},
    )

    return SingBoxRealityKeypairResponse(
        success=True,
        public_key=public_key,
        private_key=private_key,
        message="Sing-box REALITY keypair generated successfully",
    )


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
    previous_tunnel_enabled = settings.is_tunnel_enabled
    previous_admin_allowed_ips = settings.admin_allowed_ips or ""
    previous_login_max_failed_attempts = settings.login_max_failed_attempts
    previous_login_block_duration_minutes = settings.login_block_duration_minutes
    previous_l2tp_ipsec_psk = settings.l2tp_ipsec_psk
    previous_l2tp_client_subnet = settings.l2tp_client_subnet
    previous_ocserv_port = settings.ocserv_port
    previous_ocserv_client_subnet = settings.ocserv_client_subnet
    previous_singbox_log_level = settings.singbox_log_level
    previous_enable_vless = settings.enable_vless
    previous_vless_port = settings.vless_port
    previous_singbox_reality_sni = settings.singbox_reality_sni
    previous_singbox_reality_public_key = settings.singbox_reality_public_key
    previous_singbox_reality_private_key = settings.singbox_reality_private_key
    previous_singbox_reality_short_ids = settings.singbox_reality_short_ids

    openvpn_settings = _get_or_create_openvpn_settings(db)
    wireguard_settings = _get_or_create_wireguard_settings(db)
    _validate_global_port_anti_collision(
        openvpn_port=int(openvpn_settings.port),
        wireguard_port=int(wireguard_settings.listen_port),
        ocserv_port=int(payload.ocserv_port),
        vless_port=int(payload.vless_port),
        panel_https_port=int(payload.panel_https_port),
        subscription_https_port=int(payload.subscription_https_port),
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
    settings.l2tp_ipsec_psk = payload.l2tp_ipsec_psk
    settings.l2tp_client_subnet = payload.l2tp_client_subnet
    settings.ocserv_port = payload.ocserv_port
    settings.ocserv_client_subnet = payload.ocserv_client_subnet
    settings.singbox_log_level = payload.singbox_log_level
    settings.enable_vless = payload.enable_vless
    settings.vless_port = payload.vless_port
    settings.singbox_reality_sni = payload.singbox_reality_sni
    settings.singbox_reality_public_key = payload.singbox_reality_public_key
    settings.singbox_reality_private_key = payload.singbox_reality_private_key
    settings.singbox_reality_short_ids = payload.singbox_reality_short_ids
    if not (settings.singbox_reality_private_key or "").strip():
        generated_private_key, generated_public_key = _generate_singbox_reality_keypair()
        settings.singbox_reality_private_key = generated_private_key
        settings.singbox_reality_public_key = generated_public_key
    settings.is_tunnel_enabled = payload.is_tunnel_enabled
    settings.foreign_server_ip = payload.foreign_server_ip
    settings.foreign_server_port = payload.foreign_server_port
    settings.foreign_ssh_user = payload.foreign_ssh_user
    settings.foreign_ssh_password = payload.foreign_ssh_password
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

    try:
        l2tp_apply_result = PPPManager().apply_l2tp_runtime_settings(
            ipsec_psk=payload.l2tp_ipsec_psk,
            client_subnet=payload.l2tp_client_subnet,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to apply L2TP/IPsec settings: {exc}") from exc

    if not l2tp_apply_result.get("success"):
        db.rollback()
        restart_failure = l2tp_apply_result.get("restart", {}).get("failed") or []
        details = "; ".join(
            f"{item.get('command')}: {item.get('stderr') or item.get('stdout') or 'failed'}"
            for item in restart_failure
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to restart L2TP/IPsec daemons after settings update{': ' + details if details else ''}",
        )

    try:
        ocserv_apply_result = openconnect_service.apply_settings(
            port=int(payload.ocserv_port),
            client_subnet=str(payload.ocserv_client_subnet),
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to apply OpenConnect settings: {exc}") from exc

    if not ocserv_apply_result.get("success"):
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(ocserv_apply_result.get("message") or "Failed to apply OpenConnect settings"),
        )

    singbox_apply_result = singbox_service.apply_settings(db)
    if not singbox_apply_result.get("success"):
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(singbox_apply_result.get("message") or "Failed to apply Sing-box settings"),
        )

    sync_result = openvpn_service.sync_system_general_settings(
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

    if previous_tunnel_enabled != settings.is_tunnel_enabled:
        PBRManager(db=db).flush_routing_rules(out_iface=detected_wan)

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
    if previous_tunnel_enabled != settings.is_tunnel_enabled:
        changed_fields.append("is_tunnel_enabled")
    if previous_l2tp_ipsec_psk != settings.l2tp_ipsec_psk:
        changed_fields.append("l2tp_ipsec_psk")
    if previous_l2tp_client_subnet != settings.l2tp_client_subnet:
        changed_fields.append("l2tp_client_subnet")
    if previous_ocserv_port != settings.ocserv_port:
        changed_fields.append("ocserv_port")
    if previous_ocserv_client_subnet != settings.ocserv_client_subnet:
        changed_fields.append("ocserv_client_subnet")
    if previous_singbox_log_level != settings.singbox_log_level:
        changed_fields.append("singbox_log_level")
    if previous_enable_vless != settings.enable_vless:
        changed_fields.append("enable_vless")
    if previous_vless_port != settings.vless_port:
        changed_fields.append("vless_port")
    if previous_singbox_reality_sni != settings.singbox_reality_sni:
        changed_fields.append("singbox_reality_sni")
    if previous_singbox_reality_public_key != settings.singbox_reality_public_key:
        changed_fields.append("singbox_reality_public_key")
    if previous_singbox_reality_private_key != settings.singbox_reality_private_key:
        changed_fields.append("singbox_reality_private_key")
    if previous_singbox_reality_short_ids != settings.singbox_reality_short_ids:
        changed_fields.append("singbox_reality_short_ids")

    record_audit_event(
        action="general_settings_updated",
        success=True,
        admin_username=current_user.username,
        resource_type="general_settings",
        resource_id=str(settings.id),
        ip_address=extract_client_ip(request),
        details={
            "changed_fields": changed_fields,
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
            for line in openvpn_service.stream_ssl_issue_logs(
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
    openvpn_settings = _get_or_create_openvpn_settings(db)

    _validate_global_port_anti_collision(
        openvpn_port=int(openvpn_settings.port),
        wireguard_port=int(payload.listen_port),
        ocserv_port=int(general_settings.ocserv_port),
        vless_port=int(general_settings.vless_port),
        panel_https_port=int(general_settings.panel_https_port),
        subscription_https_port=int(general_settings.subscription_https_port),
    )

    if not (settings.server_private_key or "").strip() or not (settings.server_public_key or "").strip():
        try:
            private_key, public_key = wireguard_service.generate_server_keypair()
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
        wireguard_service.write_server_config(
            interface_name=settings.interface_name,
            listen_port=settings.listen_port,
            address_range=settings.address_range,
            private_key=settings.server_private_key or "",
            wan_interface=general_settings.wan_interface,
        )
        apply_result = wireguard_service.apply_interface(settings.interface_name)
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
    return openvpn_service.get_auth_assets_health()


@router.patch("/openvpn", response_model=OpenVPNSettingsResponse)
def update_openvpn_settings(
    payload: OpenVPNSettingsUpdate,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    settings = _get_or_create_openvpn_settings(db)
    general_settings = _get_or_create_general_settings(db)
    wireguard_settings = _get_or_create_wireguard_settings(db)

    _validate_global_port_anti_collision(
        openvpn_port=int(payload.port),
        wireguard_port=int(wireguard_settings.listen_port),
        ocserv_port=int(general_settings.ocserv_port),
        vless_port=int(general_settings.vless_port),
        panel_https_port=int(general_settings.panel_https_port),
        subscription_https_port=int(general_settings.subscription_https_port),
    )

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

    firewall_result = openvpn_service.sync_firewall_for_transport_change(
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
        generation_result = openvpn_service.generate_server_config(
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

    service_restart_result = openvpn_service.control_service("restart")
    if not service_restart_result.get("success"):
        raise HTTPException(
            status_code=500,
            detail=service_restart_result.get("message", "Failed to restart OpenVPN service"),
        )

    return _to_response(settings)
