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
from datetime import datetime
from pathlib import Path

# Add backend to Python path
backend_path = Path(__file__).parent.parent
sys.path.insert(0, str(backend_path))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.vpn_user import VPNUser
from backend.services.auth_service import verify_password


ATLAS_DB_PATH = "/root/Atlas/backend/atlas.db"
DATABASE_URL = f"sqlite:///{ATLAS_DB_PATH}"
AUTH_LOG_PATH = "/var/log/atlas_auth.log"


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
    db = None
    try:
        # Keep DB path absolute because OpenVPN may execute from a different cwd.
        engine = create_engine(DATABASE_URL)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()
        
        # Find user
        user = db.query(VPNUser).filter(VPNUser.username == username).first()
        
        if not user:
            return False, "user_not_found"
        
        # Check if user is active
        if not user.is_active:
            return False, "user_not_active"
        
        # Use the same verification logic used in backend/services/auth_service.py
        # (PBKDF2 current format + bcrypt backward compatibility).
        if not verify_password(password, user.password):
            return False, "password_mismatch"
        
        return True, "ok"
    
    except Exception as e:
        print(f"Authentication error: {e}", file=sys.stderr)
        return False, f"exception:{e}"
    finally:
        if db is not None:
            db.close()


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
