"""
SentinelGraph — Auth Schemas

Pydantic models for authentication request/response validation.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import UserRole


# ── Request Schemas ──────────────────────────────────────────
class UserRegisterRequest(BaseModel):
    """User registration request."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (min 8 characters)",
    )
    full_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Full name",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Enforce minimum password complexity."""
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLoginRequest(BaseModel):
    """User login request."""

    email: EmailStr
    password: str


class TokenRefreshRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str


# ── Response Schemas ─────────────────────────────────────────
class TokenPair(BaseModel):
    """JWT token pair response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token expiry in seconds")


class UserResponse(BaseModel):
    """User profile response."""

    id: uuid.UUID
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    """User profile update request."""

    full_name: str | None = Field(None, min_length=1, max_length=255)
    bio: str | None = Field(None, max_length=1000)


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str
    success: bool = True
