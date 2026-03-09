from __future__ import annotations

import asyncio
from datetime import datetime

import paramiko
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.general_settings import GeneralSettings
from backend.models.user import Admin
from backend.schemas.tunnel import TunnelCommandRequest
from backend.services.audit_service import extract_client_ip, record_audit_event

router = APIRouter(prefix="/terminal", tags=["Terminal"])


class TerminalCommandResponse(BaseModel):
    success: bool
    node: str
    command: str
    stdout: str
    stderr: str
    output: str
    exit_code: int | None = None
    timestamp: datetime


def _get_or_create_general_settings(db: Session) -> GeneralSettings:
    settings_row = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
    if settings_row:
        return settings_row

    settings_row = GeneralSettings()
    db.add(settings_row)
    db.commit()
    db.refresh(settings_row)
    return settings_row


async def _run_local_command(command: str) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_raw, stderr_raw = await asyncio.wait_for(process.communicate(), timeout=45)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return 124, "", "Command timed out after 45 seconds"

    stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
    stderr = (stderr_raw or b"").decode("utf-8", errors="replace")
    return int(process.returncode or 0), stdout, stderr


def _run_foreign_ssh_command(
    host: str,
    port: int,
    username: str,
    password: str,
    command: str,
) -> tuple[int | None, str, str]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=45)
        _ = stdin
        stdout_text = (stdout.read() or b"").decode("utf-8", errors="replace")
        stderr_text = (stderr.read() or b"").decode("utf-8", errors="replace")
        exit_code = int(stdout.channel.recv_exit_status())
        return exit_code, stdout_text, stderr_text
    finally:
        client.close()


def _build_terminal_response(node: str, command: str, exit_code: int | None, stdout: str, stderr: str) -> TerminalCommandResponse:
    output = "\n".join(part for part in [stdout.strip(), stderr.strip()] if part).strip()
    return TerminalCommandResponse(
        success=(exit_code == 0) if exit_code is not None else False,
        node=node,
        command=command,
        stdout=stdout,
        stderr=stderr,
        output=output or "[no output]",
        exit_code=exit_code,
        timestamp=datetime.utcnow(),
    )


@router.post("/local", response_model=TerminalCommandResponse)
async def run_local_terminal_command(
    payload: TunnelCommandRequest,
    request: Request,
    current_user: Admin = Depends(get_current_user),
):
    command = payload.command.strip()
    exit_code, stdout, stderr = await _run_local_command(command)
    response = _build_terminal_response("local", command, exit_code, stdout, stderr)

    record_audit_event(
        action="terminal_local_command",
        success=response.success,
        admin_username=current_user.username,
        resource_type="system_terminal",
        resource_id="local",
        ip_address=extract_client_ip(request),
        details={
            "exit_code": response.exit_code,
            "command": command[:256],
        },
    )
    return response


@router.post("/foreign", response_model=TerminalCommandResponse)
async def run_foreign_terminal_command(
    payload: TunnelCommandRequest,
    request: Request,
    current_user: Admin = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    command = payload.command.strip()
    settings_row = _get_or_create_general_settings(db)

    host = (settings_row.foreign_server_ip or "").strip()
    username = (settings_row.foreign_ssh_user or "").strip()
    password = settings_row.foreign_ssh_password or ""
    configured_port = getattr(settings_row, "foreign_ssh_port", None)
    port = int(configured_port or settings_row.foreign_server_port or 22)

    if not host or not username or not password:
        response = _build_terminal_response(
            "foreign",
            command,
            None,
            "",
            "Foreign server SSH settings are incomplete. Please configure IP, username, and password.",
        )
    else:
        try:
            exit_code, stdout, stderr = await asyncio.to_thread(
                _run_foreign_ssh_command,
                host,
                port,
                username,
                password,
                command,
            )
            response = _build_terminal_response("foreign", command, exit_code, stdout, stderr)
        except Exception as exc:
            response = _build_terminal_response("foreign", command, None, "", f"SSH error: {exc}")

    record_audit_event(
        action="terminal_foreign_command",
        success=response.success,
        admin_username=current_user.username,
        resource_type="system_terminal",
        resource_id="foreign",
        ip_address=extract_client_ip(request),
        details={
            "foreign_server_ip": host,
            "foreign_server_port": port,
            "exit_code": response.exit_code,
            "command": command[:256],
        },
    )
    return response
