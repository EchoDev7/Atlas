from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.orm import close_all_sessions
from starlette.background import BackgroundTask

from backend.config import settings
from backend.core.tunnels.manager import TunnelManager
from backend.database import engine, get_db
from backend.models.general_settings import GeneralSettings
from backend.models.wireguard_settings import WireGuardSettings
from backend.dependencies import get_current_user
from backend.models.user import Admin
from backend.schemas.tunnel import TunnelCommandRequest
from backend.schemas.tunnel_response import TunnelCommandResponse
from backend.services.audit_service import extract_client_ip, record_audit_event
from backend.services.protocols.registry import protocol_registry

router = APIRouter(prefix="/system", tags=["System"])
openvpn_service = protocol_registry.get("openvpn")
wireguard_service = protocol_registry.get("wireguard")
tunnel_manager = TunnelManager()

MAX_BACKUP_UPLOAD_BYTES = 512 * 1024 * 1024  # 512MB safety ceiling
LOG_TAIL_LINES = 100
ALLOWED_SERVICE_ACTIONS = {"restart", "stop", "start"}
DEFAULT_BACKEND_SYSTEMD_UNIT = os.getenv("ATLAS_BACKEND_SYSTEMD_UNIT", "atlas-backend")
BACKEND_SERVICE_CANDIDATES = (
    DEFAULT_BACKEND_SYSTEMD_UNIT,
    "atlas-backend",
    "atlas-panel-backend",
    "atlas",
)
L2TP_STRONGSWAN_CANDIDATES = ("strongswan", "strongswan-swanctl", "strongswan-starter")
L2TP_XL2TPD_UNIT = "xl2tpd"
LETSENCRYPT_LIVE_DIR = Path("/etc/letsencrypt/live")
DEFAULT_WIREGUARD_INTERFACE = "wg0"


class ServiceActionRequest(BaseModel):
    service_name: str
    action: str


class NtpSyncUpdateRequest(BaseModel):
    ntp_server: str = "pool.ntp.org"


def _execute_dummy_tunnel_command(settings_row: GeneralSettings, node: str, command: str) -> TunnelCommandResponse:
    tunnel_manager.get_tunnel(settings_row)
    mode = tunnel_manager.resolve_mode(settings_row)
    normalized_command = command.strip()
    output = (
        f"[{node}] $ {normalized_command}\n"
        f"mode={mode}\n"
        "Dummy execution successful."
    )
    return TunnelCommandResponse(
        success=True,
        node=node,
        mode=mode,
        command=normalized_command,
        output=output,
        timestamp=datetime.utcnow(),
    )


def _tls_key_candidates() -> tuple[Path, ...]:
    openvpn_server_dir = openvpn_service.get_openvpn_server_dir()
    return (
        openvpn_server_dir / "ta.key",
        openvpn_server_dir / "tc.key",
    )


def _collect_active_ssl_certificates(live_dir: Path) -> list[dict[str, str]]:
    certificates: list[dict[str, str]] = []
    if not live_dir.exists() or not live_dir.is_dir():
        return certificates

    for domain_dir in sorted(live_dir.iterdir(), key=lambda path: path.name.lower()):
        if not domain_dir.is_dir() or domain_dir.name.startswith("."):
            continue

        fullchain_path = (domain_dir / "fullchain.pem").absolute()
        privkey_path = (domain_dir / "privkey.pem").absolute()
        if not fullchain_path.is_file() or not privkey_path.is_file():
            continue

        certificates.append(
            {
                "domain_name": domain_dir.name,
                "certificate_path": str(fullchain_path),
                "private_key_path": str(privkey_path),
            }
        )

    return certificates


def _get_or_create_general_settings(db: Session) -> GeneralSettings:
    settings_row = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    if settings_row:
        return settings_row

    settings_row = GeneralSettings()
    db.add(settings_row)
    db.commit()
    db.refresh(settings_row)
    return settings_row


def _read_ntp_server_from_timesyncd_conf() -> str | None:
    conf_path = Path("/etc/systemd/timesyncd.conf")
    if not conf_path.exists() or not conf_path.is_file():
        return None

    try:
        lines = conf_path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith("ntp="):
            candidate = stripped.split("=", 1)[1].strip()
            return candidate or None
    return None


def _resolve_current_ntp_server(db: Session) -> str:
    configured = _read_ntp_server_from_timesyncd_conf()
    if configured:
        return configured

    settings_row = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    if settings_row and (settings_row.ntp_server or "").strip():
        return settings_row.ntp_server.strip()

    return "pool.ntp.org"


def _build_system_time_payload(db: Session) -> dict[str, object]:
    current_server_time = datetime.now(timezone.utc).isoformat()

    return {
        "current_server_time": current_server_time,
        "current_timezone": "UTC",
        "ntp_server": _resolve_current_ntp_server(db),
    }


def _validate_ntp_server(value: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="NTP server value is required")
    if any(ch.isspace() for ch in normalized):
        raise HTTPException(status_code=400, detail="NTP server must not contain spaces")
    if len(normalized) > 255:
        raise HTTPException(status_code=400, detail="NTP server value is too long")
    return normalized


def _apply_ntp_server_to_timesyncd(ntp_server: str) -> None:
    conf_path = Path("/etc/systemd/timesyncd.conf")
    lines: list[str] = []

    if conf_path.exists() and conf_path.is_file():
        try:
            lines = conf_path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to read {conf_path}: {exc}") from exc

    in_time_section = False
    time_section_found = False
    ntp_line_written = False
    output_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_time_section and not ntp_line_written:
                output_lines.append(f"NTP={ntp_server}")
                ntp_line_written = True

            section_name = stripped[1:-1].strip().lower()
            in_time_section = section_name == "time"
            if in_time_section:
                time_section_found = True

            output_lines.append(line)
            continue

        if in_time_section and stripped and not stripped.startswith("#") and stripped.lower().startswith("ntp="):
            output_lines.append(f"NTP={ntp_server}")
            ntp_line_written = True
            continue

        output_lines.append(line)

    if not time_section_found:
        if output_lines and output_lines[-1].strip():
            output_lines.append("")
        output_lines.append("[Time]")
        output_lines.append(f"NTP={ntp_server}")
        ntp_line_written = True
    elif in_time_section and not ntp_line_written:
        output_lines.append(f"NTP={ntp_server}")
        ntp_line_written = True

    if not ntp_line_written:
        output_lines.append(f"NTP={ntp_server}")

    try:
        conf_path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write {conf_path}: {exc}") from exc

    try:
        subprocess.run(["systemctl", "restart", "systemd-timesyncd"], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "Failed to apply NTP synchronization settings").strip()
        raise HTTPException(status_code=500, detail=detail) from exc


def _apply_secure_permissions(path: Path, mode: int, warnings: list[str], context: str) -> None:
    try:
        os.chmod(path, mode)
    except PermissionError:
        warnings.append(f"Permission denied while setting secure permissions for {context}")


def _harden_restored_private_materials(server_target: Path, warnings: list[str]) -> None:
    private_dir = server_target / "pki" / "private"
    if private_dir.exists() and private_dir.is_dir():
        _apply_secure_permissions(private_dir, 0o700, warnings, "pki/private")
        for private_file in private_dir.rglob("*"):
            if private_file.is_file():
                _apply_secure_permissions(private_file, 0o600, warnings, str(private_file.relative_to(server_target)))

    for tls_key_path in _tls_key_candidates():
        if tls_key_path.exists() and tls_key_path.is_file():
            _apply_secure_permissions(tls_key_path, 0o600, warnings, tls_key_path.name)


def _sqlite_database_path() -> Path:
    db_url = settings.DATABASE_URL.strip()
    if not db_url.startswith("sqlite:///"):
        raise HTTPException(status_code=500, detail="Backup is supported only for SQLite deployments")
    return Path(db_url.replace("sqlite:///", "", 1)).resolve()


def _ensure_systemctl_available() -> None:
    if shutil.which("systemctl") is None:
        raise HTTPException(status_code=503, detail="systemctl is not available on this host")


def _resolve_l2tp_units() -> tuple[list[str], bool]:
    _ensure_systemctl_available()
    resolved_units: list[str] = []
    strongswan_found = False

    for candidate in L2TP_STRONGSWAN_CANDIDATES:
        code, _, _ = _run_system_subprocess(["systemctl", "cat", candidate], timeout_seconds=10)
        if code == 0:
            resolved_units.append(candidate)
            strongswan_found = True
            break

    code, _, _ = _run_system_subprocess(["systemctl", "cat", L2TP_XL2TPD_UNIT], timeout_seconds=10)
    if code == 0:
        resolved_units.append(L2TP_XL2TPD_UNIT)

    return resolved_units, strongswan_found


def _run_system_subprocess(command: list[str], timeout_seconds: int = 40) -> tuple[int, str, str]:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_seconds,
    )
    return completed.returncode, (completed.stdout or "").strip(), (completed.stderr or "").strip()


def _resolve_backend_service_unit() -> str:
    _ensure_systemctl_available()
    seen: set[str] = set()
    candidates = [item.strip() for item in BACKEND_SERVICE_CANDIDATES if (item or "").strip()]

    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        code, _, _ = _run_system_subprocess(["systemctl", "cat", candidate], timeout_seconds=10)
        if code == 0:
            return candidate

    return DEFAULT_BACKEND_SYSTEMD_UNIT


def _resolve_service_unit(alias: str, db: Session | None = None) -> str:
    normalized = (alias or "").strip().lower()
    if normalized == "openvpn":
        return openvpn_service.service_name
    if normalized == "backend":
        return _resolve_backend_service_unit()
    if normalized == "l2tp":
        return "xl2tpd"
    if normalized == "wireguard":
        interface_name = DEFAULT_WIREGUARD_INTERFACE
        if db is not None:
            wg_settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
            configured_interface = (getattr(wg_settings, "interface_name", "") or "").strip()
            if configured_interface:
                interface_name = configured_interface
        return f"wg-quick@{interface_name}"
    raise HTTPException(status_code=400, detail="Unsupported service_name. Use 'openvpn', 'wireguard', 'l2tp', or 'backend'")


def _safe_extract_tar(archive_path: Path, destination_dir: Path) -> None:
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                raise HTTPException(status_code=400, detail="Backup archive contains unsupported symbolic links")
            member_path = (destination_dir / member.name).resolve()
            if os.path.commonpath([str(destination_dir.resolve()), str(member_path)]) != str(destination_dir.resolve()):
                raise HTTPException(status_code=400, detail="Backup archive contains invalid paths")
        archive.extractall(destination_dir)


def _safe_extract_zip(archive_path: Path, destination_dir: Path) -> None:
    with zipfile.ZipFile(archive_path, "r") as archive:
        for member in archive.namelist():
            member_path = (destination_dir / member).resolve()
            if os.path.commonpath([str(destination_dir.resolve()), str(member_path)]) != str(destination_dir.resolve()):
                raise HTTPException(status_code=400, detail="Backup archive contains invalid paths")
        archive.extractall(destination_dir)


def _extract_backup_archive(archive_path: Path, destination_dir: Path) -> None:
    suffix = archive_path.name.lower()
    if suffix.endswith(".tar.gz") or suffix.endswith(".tgz"):
        _safe_extract_tar(archive_path, destination_dir)
        return
    if suffix.endswith(".zip"):
        _safe_extract_zip(archive_path, destination_dir)
        return

    # Fallback sniffing for clients that upload with no extension.
    if tarfile.is_tarfile(archive_path):
        _safe_extract_tar(archive_path, destination_dir)
        return
    if zipfile.is_zipfile(archive_path):
        _safe_extract_zip(archive_path, destination_dir)
        return

    raise HTTPException(status_code=400, detail="Unsupported backup format. Use .tar.gz, .tgz, or .zip")


def _resolve_backup_root(extract_dir: Path) -> Path:
    preferred = extract_dir / "atlas_backup"
    if preferred.exists() and preferred.is_dir():
        return preferred
    return extract_dir


def _restore_openvpn_server_payload(source_root: Path, warnings: list[str]) -> bool:
    server_source = source_root / "openvpn" / "server"
    if not server_source.exists() or not server_source.is_dir():
        return False

    server_target = openvpn_service.get_openvpn_server_dir()
    pki_target = openvpn_service.get_pki_dir()
    restored_any = False

    try:
        server_target.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        warnings.append("Permission denied while preparing /etc/openvpn/server directory")
        return False

    pki_source = server_source / "pki"
    if pki_source.exists() and pki_source.is_dir():
        try:
            shutil.copytree(pki_source, pki_target, dirs_exist_ok=True)
            restored_any = True
        except PermissionError:
            warnings.append("Permission denied while restoring OpenVPN PKI directory")

    for filename in ("server.conf", "ta.key", "tc.key", "crl.pem", "atlas_auth_user_pass.py", "atlas_enforcement_hook.py"):
        src = server_source / filename
        if not src.exists() or not src.is_file():
            continue
        try:
            shutil.copy2(src, server_target / filename)
            restored_any = True
        except PermissionError:
            warnings.append(f"Permission denied while restoring {filename}")

    _harden_restored_private_materials(server_target, warnings)

    return restored_any


@router.get("/ssl/certs")
def list_active_ssl_certificates(current_user: Admin = Depends(get_current_user)):
    _ = current_user
    return {"certificates": _collect_active_ssl_certificates(LETSENCRYPT_LIVE_DIR)}


@router.get("/time")
def get_system_time(
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    return _build_system_time_payload(db)


@router.put("/time/timezone")
def update_system_time_sync(
    payload: NtpSyncUpdateRequest,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    requested_ntp_server = _validate_ntp_server(payload.ntp_server)
    if shutil.which("systemctl") is None:
        raise HTTPException(status_code=503, detail="systemctl is not available on this host")

    _apply_ntp_server_to_timesyncd(requested_ntp_server)

    settings_row = _get_or_create_general_settings(db)
    settings_row.system_timezone = "UTC"
    settings_row.ntp_server = requested_ntp_server
    settings_row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(settings_row)

    return {
        "message": f"UTC synchronization updated with NTP server {requested_ntp_server}",
        **_build_system_time_payload(db),
    }


@router.get("/backup")
def download_full_backup(
    request: Request,
    current_user: Admin = Depends(get_current_user),
):
    db_path = _sqlite_database_path()
    if not db_path.exists():
        raise HTTPException(status_code=404, detail="Database file atlas.db was not found")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    backup_filename = f"atlas-backup-{timestamp}.tar.gz"

    temp_dir = Path(tempfile.mkdtemp(prefix="atlas-backup-"))
    archive_path = temp_dir / backup_filename

    pki_dir = openvpn_service.get_pki_dir()
    private_dir = pki_dir / "private"
    if not private_dir.exists() or not private_dir.is_dir():
        raise HTTPException(status_code=500, detail="Critical PKI directory missing: pki/private")

    tls_key_paths = [path for path in _tls_key_candidates() if path.exists() and path.is_file()]
    if not tls_key_paths:
        raise HTTPException(status_code=500, detail="Critical TLS key missing: expected ta.key or tc.key")

    try:
        with tarfile.open(archive_path, "w:gz") as archive:
            archive.add(db_path, arcname="atlas_backup/database/atlas.db")

            if pki_dir.exists() and pki_dir.is_dir():
                archive.add(pki_dir, arcname="atlas_backup/openvpn/server/pki")
            archive.add(private_dir, arcname="atlas_backup/openvpn/server/pki/private")

            for file_path, arcname in (
                (openvpn_service.get_server_conf_path(), "atlas_backup/openvpn/server/server.conf"),
                (openvpn_service.get_crl_file_path(), "atlas_backup/openvpn/server/crl.pem"),
                (openvpn_service.get_auth_user_pass_script_path(), "atlas_backup/openvpn/server/atlas_auth_user_pass.py"),
                (openvpn_service.get_enforcement_hook_path(), "atlas_backup/openvpn/server/atlas_enforcement_hook.py"),
            ):
                if file_path.exists() and file_path.is_file():
                    archive.add(file_path, arcname=arcname)

            for tls_key_path in tls_key_paths:
                archive.add(tls_key_path, arcname=f"atlas_backup/openvpn/server/{tls_key_path.name}")
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Failed to build backup archive: {str(exc)}")

    record_audit_event(
        action="system_backup_download",
        success=True,
        admin_username=current_user.username,
        resource_type="system_backup",
        resource_id=timestamp,
        ip_address=extract_client_ip(request),
        details={"filename": backup_filename},
    )

    return FileResponse(
        path=archive_path,
        filename=backup_filename,
        media_type="application/gzip",
        background=BackgroundTask(shutil.rmtree, temp_dir, True),
    )


@router.post("/backup/restore")
async def restore_full_backup(
    request: Request,
    backup_file: UploadFile = File(...),
    current_user: Admin = Depends(get_current_user),
):
    uploaded_name = (backup_file.filename or "").strip() or "backup-archive"

    temp_dir = Path(tempfile.mkdtemp(prefix="atlas-restore-"))
    archive_path = temp_dir / uploaded_name

    try:
        bytes_written = 0
        with archive_path.open("wb") as destination:
            while True:
                chunk = await backup_file.read(1024 * 1024)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_BACKUP_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Backup archive is too large")
                destination.write(chunk)

        if bytes_written == 0:
            raise HTTPException(status_code=400, detail="Uploaded backup file is empty")

        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        _extract_backup_archive(archive_path, extract_dir)

        backup_root = _resolve_backup_root(extract_dir)
        backup_db = backup_root / "database" / "atlas.db"
        if not backup_db.exists() or not backup_db.is_file():
            raise HTTPException(status_code=400, detail="Backup archive is missing database/atlas.db")

        db_path = _sqlite_database_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)

        warnings: list[str] = []
        restored_components = ["database"]

        close_all_sessions()
        engine.dispose()

        db_backup_copy = db_path.with_suffix(f".pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.bak")
        if db_path.exists():
            shutil.copy2(db_path, db_backup_copy)

        restored_db_tmp = db_path.with_suffix(".restored.tmp")
        shutil.copy2(backup_db, restored_db_tmp)
        os.replace(restored_db_tmp, db_path)

        if _restore_openvpn_server_payload(backup_root, warnings):
            restored_components.append("openvpn_pki")

        restart_result = openvpn_service.control_service("restart")
        restart_performed = bool(restart_result.get("success"))
        if not restart_performed:
            warnings.append(restart_result.get("message") or "OpenVPN restart failed")

        record_audit_event(
            action="system_backup_restore",
            success=True,
            admin_username=current_user.username,
            resource_type="system_backup",
            resource_id=uploaded_name,
            ip_address=extract_client_ip(request),
            details={
                "restored_components": restored_components,
                "warnings": warnings,
                "openvpn_restart_success": restart_performed,
            },
        )

        return {
            "success": True,
            "message": "Backup restored successfully",
            "restored_components": restored_components,
            "warnings": warnings,
            "openvpn_restart_success": restart_performed,
            "restart_required": not restart_performed,
        }
    except HTTPException as exc:
        record_audit_event(
            action="system_backup_restore",
            success=False,
            admin_username=current_user.username,
            resource_type="system_backup",
            resource_id=uploaded_name,
            ip_address=extract_client_ip(request),
            details={"reason": str(exc.detail)},
        )
        raise
    except Exception as exc:
        record_audit_event(
            action="system_backup_restore",
            success=False,
            admin_username=current_user.username,
            resource_type="system_backup",
            resource_id=uploaded_name,
            ip_address=extract_client_ip(request),
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(exc)}")
    finally:
        await backup_file.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/service/action")
def run_service_action(
    payload: ServiceActionRequest,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    action = (payload.action or "").strip().lower()
    if action not in ALLOWED_SERVICE_ACTIONS:
        raise HTTPException(status_code=400, detail="Unsupported action. Use restart, stop, or start")

    target_alias = (payload.service_name or "").strip().lower()
    if target_alias == "l2tp":
        resolved_units, has_strongswan_unit = _resolve_l2tp_units()
        if not resolved_units and not shutil.which("ipsec"):
            raise HTTPException(status_code=500, detail="No L2TP/IPsec service unit or ipsec command is available on this host")

        unit_results: list[dict[str, Any]] = []
        for unit in resolved_units:
            try:
                code, stdout, stderr = _run_system_subprocess(["systemctl", action, unit], timeout_seconds=20)
            except subprocess.TimeoutExpired:
                code, stdout, stderr = 124, "", "Service operation timed out"
            unit_results.append(
                {
                    "service_unit": unit,
                    "return_code": code,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )

        if not has_strongswan_unit and shutil.which("ipsec"):
            try:
                code, stdout, stderr = _run_system_subprocess(["ipsec", action], timeout_seconds=20)
            except subprocess.TimeoutExpired:
                code, stdout, stderr = 124, "", "ipsec command timed out"
            unit_results.append(
                {
                    "service_unit": "ipsec",
                    "return_code": code,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )

        failed_results = [item for item in unit_results if int(item.get("return_code", 1)) != 0]
        success = len(failed_results) == 0
        record_audit_event(
            action="system_service_action",
            success=success,
            admin_username=current_user.username,
            resource_type="system_service",
            resource_id=target_alias,
            ip_address=extract_client_ip(request),
            details={"action": action, "units": unit_results},
        )

        if not success:
            failure_message = "; ".join(
                f"{item.get('service_unit')}: {item.get('stderr') or item.get('stdout') or 'failed'}"
                for item in failed_results
            )
            raise HTTPException(status_code=500, detail=f"L2TP/IPsec service operation failed - {failure_message}")

        return {
            "success": True,
            "service_name": target_alias,
            "service_unit": ",".join(str(item.get("service_unit") or "") for item in unit_results if str(item.get("service_unit") or "").strip()),
            "action": action,
            "message": f"L2TP/IPsec services {action} executed successfully",
            "output": "\n".join(
                f"{item['service_unit']}: {(item.get('stdout') or '').strip()}" for item in unit_results
            ).strip(),
        }

    if target_alias == "wireguard" and action in {"start", "restart"}:
        sync_result = wireguard_service.sync_users_runtime(db)
        if not sync_result.get("success"):
            raise HTTPException(
                status_code=500,
                detail=f"WireGuard sync failed before {action}: {sync_result.get('message', 'unknown error')}",
            )

    service_unit = _resolve_service_unit(target_alias, db)
    _ensure_systemctl_available()

    try:
        code, stdout, stderr = _run_system_subprocess(["systemctl", action, service_unit])
    except subprocess.TimeoutExpired:
        record_audit_event(
            action="system_service_action",
            success=False,
            admin_username=current_user.username,
            resource_type="system_service",
            resource_id=target_alias,
            ip_address=extract_client_ip(request),
            details={"service_unit": service_unit, "action": action, "reason": "timeout"},
        )
        raise HTTPException(status_code=504, detail="Service operation timed out")

    success = code == 0
    record_audit_event(
        action="system_service_action",
        success=success,
        admin_username=current_user.username,
        resource_type="system_service",
        resource_id=target_alias,
        ip_address=extract_client_ip(request),
        details={
            "service_unit": service_unit,
            "action": action,
            "return_code": code,
            "stderr": stderr[:2000],
        },
    )

    if not success:
        error_text = stderr or stdout or f"systemctl returned non-zero exit code ({code})"
        raise HTTPException(status_code=500, detail=error_text)

    return {
        "success": True,
        "service_name": target_alias,
        "service_unit": service_unit,
        "action": action,
        "message": f"Service {action} executed successfully",
        "output": stdout,
    }


@router.get("/l2tp/status")
def read_l2tp_status(
    current_user: Admin = Depends(get_current_user),
):
    _ = current_user

    unit_states: dict[str, dict[str, Any]] = {}
    resolved_units, has_strongswan_unit = _resolve_l2tp_units()
    for unit in resolved_units:
        code, stdout, stderr = _run_system_subprocess(["systemctl", "is-active", unit], timeout_seconds=10)
        is_active = int(code) == 0
        unit_states[unit] = {
            "is_active": is_active,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": code,
        }

    strongswan_active = False
    if has_strongswan_unit:
        strongswan_active = any(bool(unit_states.get(unit, {}).get("is_active")) for unit in L2TP_STRONGSWAN_CANDIDATES if unit in unit_states)
    elif shutil.which("ipsec"):
        code, stdout, stderr = _run_system_subprocess(["ipsec", "status"], timeout_seconds=15)
        strongswan_active = int(code) == 0
        unit_states["ipsec"] = {
            "is_active": strongswan_active,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": code,
        }
    else:
        unit_states["ipsec"] = {
            "is_active": False,
            "stdout": "",
            "stderr": "No supported StrongSwan unit or ipsec command found",
            "return_code": 127,
        }

    xl2tpd_active = bool(unit_states.get(L2TP_XL2TPD_UNIT, {}).get("is_active"))
    all_active = strongswan_active and xl2tpd_active

    return {
        "success": True,
        "protocol": "l2tp",
        "is_active": all_active,
        "units": unit_states,
    }


@router.get("/logs/{service_name}")
def read_service_logs(
    service_name: str,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target_alias = (service_name or "").strip().lower()
    service_unit = _resolve_service_unit(target_alias, db)
    _ensure_systemctl_available()

    try:
        code, stdout, stderr = _run_system_subprocess(
            ["journalctl", "-u", service_unit, "-n", str(LOG_TAIL_LINES), "--no-pager"],
            timeout_seconds=30,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Fetching service logs timed out")

    success = code == 0
    record_audit_event(
        action="system_service_logs_read",
        success=success,
        admin_username=current_user.username,
        resource_type="system_service",
        resource_id=target_alias,
        ip_address=extract_client_ip(request),
        details={
            "service_unit": service_unit,
            "return_code": code,
            "stderr": stderr[:2000],
        },
    )

    if not success:
        raise HTTPException(status_code=500, detail=stderr or stdout or "Failed to read service logs")

    lines = stdout.splitlines() if stdout else []
    return {
        "success": True,
        "service_name": target_alias,
        "service_unit": service_unit,
        "line_count": len(lines),
        "logs": lines,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/wireguard/diagnostics")
def read_wireguard_diagnostics(
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ensure_systemctl_available()

    wg_settings = db.query(WireGuardSettings).order_by(WireGuardSettings.id.asc()).first()
    interface_name = (
        (getattr(wg_settings, "interface_name", "") if wg_settings else "")
        or DEFAULT_WIREGUARD_INTERFACE
    ).strip() or DEFAULT_WIREGUARD_INTERFACE
    address_range = (getattr(wg_settings, "address_range", "") if wg_settings else "").strip()
    service_unit = _resolve_service_unit("wireguard", db)

    checks = {
        "default_route": ["ip", "route", "show", "default"],
        "ip_forward": ["sysctl", "net.ipv4.ip_forward"],
        "forward_rules": ["iptables", "-S", "FORWARD"],
        "nat_rules": ["iptables", "-t", "nat", "-S", "POSTROUTING"],
        "wg_show": ["wg", "show", interface_name],
        "wg_dump": ["wg", "show", interface_name, "dump"],
        "service_status": ["systemctl", "status", service_unit, "--no-pager", "-n", "25"],
    }

    command_results: dict[str, dict[str, object]] = {}
    for key, cmd in checks.items():
        try:
            code, stdout, stderr = _run_system_subprocess(cmd, timeout_seconds=20)
            command_results[key] = {
                "return_code": code,
                "stdout": stdout,
                "stderr": stderr,
            }
        except subprocess.TimeoutExpired:
            command_results[key] = {
                "return_code": 124,
                "stdout": "",
                "stderr": "Command timed out",
            }

    nat_stdout = str(command_results.get("nat_rules", {}).get("stdout") or "")
    nat_matches = []
    if address_range:
        nat_matches = [line for line in nat_stdout.splitlines() if address_range in line]

    dump_stdout = str(command_results.get("wg_dump", {}).get("stdout") or "")
    dump_lines = [line for line in dump_stdout.splitlines() if line.strip()]
    peer_count = max(0, len(dump_lines) - 1) if dump_lines else 0

    ip_forward_stdout = str(command_results.get("ip_forward", {}).get("stdout") or "")
    ip_forward_enabled = "= 1" in ip_forward_stdout

    payload = {
        "success": True,
        "service_unit": service_unit,
        "interface_name": interface_name,
        "address_range": address_range,
        "summary": {
            "ip_forward_enabled": ip_forward_enabled,
            "peer_count": peer_count,
            "nat_rule_matches_for_address_range": len(nat_matches),
        },
        "checks": command_results,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    record_audit_event(
        action="system_wireguard_diagnostics_read",
        success=True,
        admin_username=current_user.username,
        resource_type="system_service",
        resource_id="wireguard",
        ip_address=extract_client_ip(request),
        details={
            "service_unit": service_unit,
            "interface_name": interface_name,
            "address_range": address_range,
            "summary": payload["summary"],
        },
    )

    return payload


@router.post("/tunnel/local/command", response_model=TunnelCommandResponse)
def run_local_tunnel_command(
    payload: TunnelCommandRequest,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    settings_row = _get_or_create_general_settings(db)
    response = _execute_dummy_tunnel_command(settings_row, node="local", command=payload.command)
    record_audit_event(
        action="system_tunnel_local_command",
        success=True,
        admin_username=current_user.username,
        resource_type="system_tunnel",
        resource_id="local",
        ip_address=extract_client_ip(request),
        details={
            "mode": response.mode,
            "command": payload.command[:256],
        },
    )
    return response


@router.post("/tunnel/foreign/command", response_model=TunnelCommandResponse)
def run_foreign_tunnel_command(
    payload: TunnelCommandRequest,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    settings_row = _get_or_create_general_settings(db)
    response = _execute_dummy_tunnel_command(settings_row, node="foreign", command=payload.command)
    record_audit_event(
        action="system_tunnel_foreign_command",
        success=True,
        admin_username=current_user.username,
        resource_type="system_tunnel",
        resource_id="foreign",
        ip_address=extract_client_ip(request),
        details={
            "mode": response.mode,
            "command": payload.command[:256],
        },
    )
    return response
