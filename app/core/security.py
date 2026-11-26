import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from app.core.config import get_settings

password_hash = PasswordHash.recommended()  # Argon2 — slow on purpose, resists brute force


def hash_password(raw: str) -> str:
    return password_hash.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    return password_hash.verify(raw, hashed)


def create_access_token(user_id: int, role: str) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {"sub": str(user_id), "role": role, "iat": now, "exp": now + timedelta(minutes=s.access_token_minutes)}
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    s = get_settings()
    return jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])


# --- API keys -------------------------------------------------------------
# We show the full key to the client ONCE, and store only its SHA-256 hash.
# SHA-256 (fast) is fine here because keys are 256-bit random, not guessable passwords.
def generate_api_key() -> tuple[str, str, str]:
    raw = "ss_live_" + secrets.token_urlsafe(32)
    return raw, raw[:12], hash_api_key(raw)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
