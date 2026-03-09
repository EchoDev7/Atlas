from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.orm import close_all_sessions
from starlette.background import BackgroundTask

from backend.config import settings
from backend.core.openvpn import OpenVPNConfig, OpenVPNManager
from backend.database import engine, get_db
from backend.models.general_settings import GeneralSettings
from backend.dependencies import get_current_user
from backend.models.user import Admin
from backend.services.audit_service import extract_client_ip, record_audit_event

router = APIRouter(prefix="/system", tags=["System"])
openvpn_manager = OpenVPNManager()

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
LETSENCRYPT_LIVE_DIR = Path("/etc/letsencrypt/live")


class ServiceActionRequest(BaseModel):
    service_name: str
    action: str


class TimezoneUpdateRequest(BaseModel):
    timezone: str
    ntp_server: str = "pool.ntp.org"


def _tls_key_candidates() -> tuple[Path, ...]:
    return (
        OpenVPNConfig.OPENVPN_SERVER_DIR / "ta.key",
        OpenVPNConfig.OPENVPN_SERVER_DIR / "tc.key",
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


def _read_timezone_from_timedatectl() -> str | None:
    if shutil.which("timedatectl") is None:
        return None
    try:
        completed = subprocess.run(
            ["timedatectl", "show", "--property=Timezone", "--value"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return None

    if completed.returncode != 0:
        return None

    candidate = (completed.stdout or "").strip()
    return candidate or None


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


def _read_timezone_from_file() -> str | None:
    timezone_file = Path("/etc/timezone")
    if not timezone_file.exists() or not timezone_file.is_file():
        return None
    try:
        candidate = timezone_file.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    return candidate or None


def _normalize_timezone_candidate(candidate: str | None) -> str | None:
    normalized = (candidate or "").strip()
    if not normalized:
        return None
    try:
        ZoneInfo(normalized)
    except ZoneInfoNotFoundError:
        return None
    return normalized


def _resolve_current_timezone_name(db: Session) -> str:
    settings_row = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    persisted_timezone = _normalize_timezone_candidate(settings_row.system_timezone if settings_row else None)
    if persisted_timezone:
        return persisted_timezone

    for candidate in (_read_timezone_from_file(), _read_timezone_from_timedatectl()):
        normalized = _normalize_timezone_candidate(candidate)
        if normalized:
            return normalized

    return "UTC"


def _resolve_current_ntp_server(db: Session) -> str:
    configured = _read_ntp_server_from_timesyncd_conf()
    if configured:
        return configured

    settings_row = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    if settings_row and (settings_row.ntp_server or "").strip():
        return settings_row.ntp_server.strip()

    return "pool.ntp.org"


def _list_global_timezones() -> list[str]:
    try:
        zones = sorted(available_timezones())
    except Exception:
        zones = []
    if "UTC" not in zones:
        zones = ["UTC", *zones]
    return zones


def _build_system_time_payload(db: Session) -> dict[str, object]:
    current_timezone = _resolve_current_timezone_name(db)
    local_now = datetime.now().astimezone()
    try:
        zone = ZoneInfo(current_timezone)
        current_server_time = local_now.astimezone(zone).isoformat()
    except ZoneInfoNotFoundError:
        current_timezone = "UTC"
        current_server_time = local_now.astimezone(timezone.utc).isoformat()

    return {
        "current_server_time": current_server_time,
        "current_timezone": current_timezone,
        "ntp_server": _resolve_current_ntp_server(db),
        "available_timezones": _list_global_timezones(),
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
        subprocess.run(["timedatectl", "set-ntp", "true"], capture_output=True, text=True, check=True)
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


def _resolve_service_unit(alias: str) -> str:
    normalized = (alias or "").strip().lower()
    if normalized == "openvpn":
        return openvpn_manager.service_name
    if normalized == "backend":
        return _resolve_backend_service_unit()
    raise HTTPException(status_code=400, detail="Unsupported service_name. Use 'openvpn' or 'backend'")


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

    server_target = OpenVPNConfig.OPENVPN_SERVER_DIR
    restored_any = False

    try:
        server_target.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        warnings.append("Permission denied while preparing /etc/openvpn/server directory")
        return False

    pki_source = server_source / "pki"
    if pki_source.exists() and pki_source.is_dir():
        try:
            shutil.copytree(pki_source, OpenVPNConfig.PKI_DIR, dirs_exist_ok=True)
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
def update_system_timezone(
    payload: TimezoneUpdateRequest,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _ = current_user
    requested_timezone = (payload.timezone or "").strip()
    requested_ntp_server = _validate_ntp_server(payload.ntp_server)
    valid_timezones = set(_list_global_timezones())

    if not requested_timezone:
        raise HTTPException(status_code=400, detail="Timezone value is required")
    if requested_timezone not in valid_timezones:
        raise HTTPException(status_code=400, detail="Invalid timezone value")
    if shutil.which("timedatectl") is None:
        raise HTTPException(status_code=503, detail="timedatectl is not available on this host")
    if shutil.which("systemctl") is None:
        raise HTTPException(status_code=503, detail="systemctl is not available on this host")

    try:
        subprocess.run(
            ["timedatectl", "set-timezone", requested_timezone],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "Failed to apply timezone using timedatectl").strip()
        raise HTTPException(status_code=500, detail=detail) from exc

    try:
        time.tzset()
    except AttributeError:
        # tzset is not available on some non-POSIX platforms.
        pass

    _apply_ntp_server_to_timesyncd(requested_ntp_server)

    settings_row = _get_or_create_general_settings(db)
    settings_row.system_timezone = requested_timezone
    settings_row.ntp_server = requested_ntp_server
    settings_row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(settings_row)

    if (settings_row.system_timezone or "").strip() != requested_timezone:
        raise HTTPException(status_code=500, detail="Failed to persist timezone setting")

    return {
        "message": f"Timezone updated to {requested_timezone} and NTP server set to {requested_ntp_server}",
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

    pki_dir = OpenVPNConfig.PKI_DIR
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
                (OpenVPNConfig.SERVER_CONF, "atlas_backup/openvpn/server/server.conf"),
                (OpenVPNConfig.CRL_FILE, "atlas_backup/openvpn/server/crl.pem"),
                (OpenVPNConfig.AUTH_USER_PASS_SCRIPT, "atlas_backup/openvpn/server/atlas_auth_user_pass.py"),
                (OpenVPNConfig.ENFORCEMENT_HOOK, "atlas_backup/openvpn/server/atlas_enforcement_hook.py"),
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

        restart_result = openvpn_manager.control_service("restart")
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
):
    action = (payload.action or "").strip().lower()
    if action not in ALLOWED_SERVICE_ACTIONS:
        raise HTTPException(status_code=400, detail="Unsupported action. Use restart, stop, or start")

    target_alias = (payload.service_name or "").strip().lower()
    service_unit = _resolve_service_unit(target_alias)
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


@router.get("/logs/{service_name}")
def read_service_logs(
    service_name: str,
    request: Request,
    current_user: Admin = Depends(get_current_user),
):
    target_alias = (service_name or "").strip().lower()
    service_unit = _resolve_service_unit(target_alias)
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
