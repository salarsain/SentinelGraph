"""
SentinelGraph — Security Utilities

JWT token generation/validation, password hashing (Argon2),
API key generation, and AES-GCM encryption for secrets at rest.
"""

import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import structlog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# ── Password Hashing ────────────────────────────────────────
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against an Argon2 hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ── JWT Tokens ──────────────────────────────────────────────
def create_access_token(
    subject: str | UUID,
    extra_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes))

    to_encode: dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "access",
    }
    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str | UUID) -> str:
    """Create a JWT refresh token with longer expiry."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.jwt_refresh_token_expire_days)

    to_encode = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "refresh",
        "jti": secrets.token_urlsafe(32),  # Unique token ID for revocation
    }

    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token.

    Raises:
        JWTError: If token is invalid, expired, or tampered.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except JWTError as e:
        logger.warning("jwt.decode_failed", error=str(e))
        raise


def validate_access_token(token: str) -> dict[str, Any]:
    """Decode token and verify it's an access token."""
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise JWTError("Token is not an access token")
    return payload


def validate_refresh_token(token: str) -> dict[str, Any]:
    """Decode token and verify it's a refresh token."""
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise JWTError("Token is not a refresh token")
    return payload


# ── API Keys ────────────────────────────────────────────────
def generate_api_key(prefix: str = "sg") -> str:
    """Generate a secure API key with prefix.

    Format: sg_live_<40 random chars>
    """
    random_part = secrets.token_urlsafe(30)
    return f"{prefix}_live_{random_part}"


def generate_api_key_hash(api_key: str) -> str:
    """Hash an API key for storage (we never store plaintext keys)."""
    return pwd_context.hash(api_key)


# ── AES-GCM Encryption (secrets at rest) ────────────────────
def _get_encryption_key() -> bytes:
    """Get or generate the AES-GCM encryption key."""
    key_str = settings.encryption_key
    if not key_str:
        logger.warning("encryption.no_key", msg="No encryption key set, generating ephemeral key")
        return AESGCM.generate_key(bit_length=256)
    return base64.b64decode(key_str)


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string value using AES-256-GCM.

    Returns: base64-encoded ciphertext with nonce prepended.
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Prepend nonce to ciphertext
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_value(encrypted: str) -> str:
    """Decrypt an AES-256-GCM encrypted value.

    Expects: base64-encoded ciphertext with nonce prepended.
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    raw = base64.b64decode(encrypted)
    nonce = raw[:12]
    ciphertext = raw[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
