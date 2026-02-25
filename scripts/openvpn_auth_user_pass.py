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
import os
from pathlib import Path

# Add backend to Python path
backend_path = Path(__file__).parent.parent
sys.path.insert(0, str(backend_path))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from backend.models.vpn_user import VPNUser
from backend.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_credentials(username: str, password: str) -> bool:
    """
    Verify username and password against database.
    Returns True if credentials are valid and user is active.
    """
    try:
        # Create database connection
        engine = create_engine(str(settings.DATABASE_URL))
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()
        
        # Find user
        user = db.query(VPNUser).filter(VPNUser.username == username).first()
        
        if not user:
            db.close()
            return False
        
        # Check if user is active
        if not user.is_active:
            db.close()
            return False
        
        # Verify password
        if not pwd_context.verify(password, user.password):
            db.close()
            return False
        
        db.close()
        return True
    
    except Exception as e:
        print(f"Authentication error: {e}", file=sys.stderr)
        return False


def main():
    """
    Main authentication function.
    OpenVPN passes credentials via a temporary file when using 'via-file' method.
    """
    if len(sys.argv) < 2:
        print("Error: No credentials file provided", file=sys.stderr)
        sys.exit(1)
    
    credentials_file = sys.argv[1]
    
    try:
        # Read credentials from file
        # Format: first line = username, second line = password
        with open(credentials_file, 'r') as f:
            lines = f.readlines()
            if len(lines) < 2:
                print("Error: Invalid credentials file format", file=sys.stderr)
                sys.exit(1)
            
            username = lines[0].strip()
            password = lines[1].strip()
        
        # Verify credentials
        if verify_credentials(username, password):
            print(f"Authentication successful for user: {username}", file=sys.stderr)
            sys.exit(0)  # Success
        else:
            print(f"Authentication failed for user: {username}", file=sys.stderr)
            sys.exit(1)  # Failure
    
    except Exception as e:
        print(f"Authentication error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
