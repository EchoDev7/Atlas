from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import zipfile

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import close_all_sessions
from starlette.background import BackgroundTask

from backend.config import settings
from backend.core.openvpn import OpenVPNConfig, OpenVPNManager
from backend.database import engine
from backend.dependencies import get_current_user
from backend.models.user import Admin
from backend.services.audit_service import extract_client_ip, record_audit_event

router = APIRouter(prefix="/system", tags=["System"])
openvpn_manager = OpenVPNManager()

MAX_BACKUP_UPLOAD_BYTES = 512 * 1024 * 1024  # 512MB safety ceiling


def _sqlite_database_path() -> Path:
    db_url = settings.DATABASE_URL.strip()
    if not db_url.startswith("sqlite:///"):
        raise HTTPException(status_code=500, detail="Backup is supported only for SQLite deployments")
    return Path(db_url.replace("sqlite:///", "", 1)).resolve()


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

    for filename in ("server.conf", "ta.key", "crl.pem", "atlas_auth_user_pass.py", "atlas_enforcement_hook.py"):
        src = server_source / filename
        if not src.exists() or not src.is_file():
            continue
        try:
            shutil.copy2(src, server_target / filename)
            restored_any = True
        except PermissionError:
            warnings.append(f"Permission denied while restoring {filename}")

    return restored_any


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

    try:
        with tarfile.open(archive_path, "w:gz") as archive:
            archive.add(db_path, arcname="atlas_backup/database/atlas.db")

            pki_dir = OpenVPNConfig.PKI_DIR
            if pki_dir.exists() and pki_dir.is_dir():
                archive.add(pki_dir, arcname="atlas_backup/openvpn/server/pki")

            for file_path, arcname in (
                (OpenVPNConfig.SERVER_CONF, "atlas_backup/openvpn/server/server.conf"),
                (OpenVPNConfig.TA_KEY, "atlas_backup/openvpn/server/ta.key"),
                (OpenVPNConfig.CRL_FILE, "atlas_backup/openvpn/server/crl.pem"),
                (OpenVPNConfig.AUTH_USER_PASS_SCRIPT, "atlas_backup/openvpn/server/atlas_auth_user_pass.py"),
                (OpenVPNConfig.ENFORCEMENT_HOOK, "atlas_backup/openvpn/server/atlas_enforcement_hook.py"),
            ):
                if file_path.exists() and file_path.is_file():
                    archive.add(file_path, arcname=arcname)
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
