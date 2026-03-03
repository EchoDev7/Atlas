#!/usr/bin/env python3
# Atlas — OpenVPN auth-user-pass authentication script
# Phase 2 Enhancements: Password-based authentication

"""
OpenVPN authentication script for username/password verification.
This script is called by OpenVPN server with auth-user-pass-verify directive.

Usage in OpenVPN server config:
    auth-user-pass-verify /path/to/openvpn_auth_user_pass.py via-file
    script-security 2
"""

import sys
import base64
import hashlib
import hmac
import sqlite3
from datetime import datetime

try:
    import bcrypt
except Exception:
    bcrypt = None


ATLAS_DB_PATH = "/root/Atlas/backend/atlas.db"
AUTH_LOG_PATH = "/var/log/atlas_auth.log"
PBKDF2_SCHEME = "pbkdf2_sha256"


def _parse_db_datetime(value: object) -> datetime | None:
    if value in (None, ""):
        return None

    text = str(value).strip()
    if not text:
        return None

    normalized = text.replace("Z", "+00:00").replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(normalized)
        return parsed.replace(tzinfo=None)
    except ValueError:
        return None


def _is_user_active(user_row: sqlite3.Row) -> bool:
    now = datetime.utcnow()
    access_start_at = _parse_db_datetime(user_row["access_start_at"])
    access_expires_at = _parse_db_datetime(user_row["access_expires_at"])
    expiry_date = _parse_db_datetime(user_row["expiry_date"])
    effective_expiry = access_expires_at or expiry_date

    if access_start_at and now < access_start_at:
        return False

    return (
        bool(user_row["is_enabled"])
        and not bool(user_row["is_expired"])
        and not bool(user_row["is_data_limit_exceeded"])
        and not bool(user_row["is_connection_limit_exceeded"])
        and not (effective_expiry and now >= effective_expiry)
    )


def _verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return False

    if hashed_password.startswith(f"{PBKDF2_SCHEME}$"):
        try:
            _, iterations_raw, salt_b64, expected_b64 = hashed_password.split("$", 3)
            iterations = int(iterations_raw)
            salt = base64.b64decode(salt_b64.encode("ascii"))
            digest = hashlib.pbkdf2_hmac(
                "sha256", plain_password.encode("utf-8"), salt, iterations
            )
            calculated_b64 = base64.b64encode(digest).decode("ascii")
            return hmac.compare_digest(calculated_b64, expected_b64)
        except Exception:
            return False

    # Backward compatibility for legacy bcrypt hashes.
    if hashed_password.startswith("$2"):
        if bcrypt is None:
            return False
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8"),
            )
        except Exception:
            return False

    return False


def log_auth_failure(username: str, reason: str) -> None:
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    safe_username = (username or "").strip() or "<unknown>"
    message = f"{timestamp} auth_failed user={safe_username} reason={reason}\n"
    try:
        with open(AUTH_LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(message)
    except Exception as exc:
        print(f"Failed to write auth debug log: {exc}", file=sys.stderr)


def verify_credentials(username: str, password: str) -> tuple[bool, str]:
    """
    Verify username and password against database.
    Returns (is_valid, reason).
    """
    conn = None
    try:
        conn = sqlite3.connect(ATLAS_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        
        # Find user
        user = conn.execute(
            (
                "SELECT username, password, is_enabled, is_expired, "
                "is_data_limit_exceeded, is_connection_limit_exceeded, "
                "access_start_at, access_expires_at, expiry_date "
                "FROM vpn_users WHERE username = ?"
            ),
            (username,),
        ).fetchone()
        
        if not user:
            return False, "user_not_found"
        
        # Check if user is active
        if not _is_user_active(user):
            return False, "user_not_active"
        
        # Keep this logic aligned with backend/services/auth_service.py.
        if not _verify_password(password, str(user["password"] or "")):
            return False, "password_mismatch"
        
        return True, "ok"
    
    except Exception as e:
        print(f"Authentication error: {e}", file=sys.stderr)
        return False, f"exception:{e}"
    finally:
        if conn is not None:
            conn.close()


def main():
    """
    Main authentication function.
    OpenVPN passes credentials via a temporary file when using 'via-file' method.
    """
    if len(sys.argv) < 2:
        print("Error: No credentials file provided", file=sys.stderr)
        log_auth_failure("", "missing_credentials_file_argument")
        sys.exit(1)
    
    credentials_file = sys.argv[1]
    
    try:
        # Read credentials from file
        # Format: first line = username, second line = password
        with open(credentials_file, 'r') as f:
            lines = f.readlines()
            if len(lines) < 2:
                print("Error: Invalid credentials file format", file=sys.stderr)
                log_auth_failure("", "invalid_credentials_file_format")
                sys.exit(1)
            
            username = lines[0].strip()
            password = lines[1].strip()
        
        # Verify credentials
        is_valid, reason = verify_credentials(username, password)
        if is_valid:
            print(f"Authentication successful for user: {username}", file=sys.stderr)
            sys.exit(0)  # Success
        else:
            log_auth_failure(username, reason)
            print(f"Authentication failed for user: {username}", file=sys.stderr)
            sys.exit(1)  # Failure
    
    except Exception as e:
        log_auth_failure("", f"main_exception:{e}")
        print(f"Authentication error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
