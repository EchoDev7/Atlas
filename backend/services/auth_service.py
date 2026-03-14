import base64
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from backend.config import settings

PBKDF2_SCHEME = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 390000
DEFAULT_ADMIN_PASSWORD_FALLBACK = "admin123"


def verify_password(plain_password: str, hashed_password: str) -> bool:
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

    # Backward compatibility for existing bcrypt hashes.
    try:
        if not hashed_password.startswith("$2"):
            return False
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"{PBKDF2_SCHEME}${PBKDF2_ITERATIONS}${salt_b64}${digest_b64}"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        return username
    except JWTError:
        return None


def default_admin_password_candidates() -> tuple[str, ...]:
    candidates: list[str] = []
    configured_default = str(getattr(settings, "ADMIN_PASSWORD", "") or "").strip()
    if configured_default:
        candidates.append(configured_default)
    if DEFAULT_ADMIN_PASSWORD_FALLBACK not in candidates:
        candidates.append(DEFAULT_ADMIN_PASSWORD_FALLBACK)
    return tuple(candidates)


def is_default_admin_password_hash(hashed_password: str) -> bool:
    normalized_hash = str(hashed_password or "").strip()
    if not normalized_hash:
        return False
    for candidate in default_admin_password_candidates():
        if verify_password(candidate, normalized_hash):
            return True
    return False
