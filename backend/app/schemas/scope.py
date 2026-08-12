"""
SentinelGraph — Scope Schemas

Pydantic models for scope CRUD and validation.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.models.scope import ScopeStatus, ScopeType, ValidationMethod


# ── Request Schemas ──────────────────────────────────────────
class ScopeCreateRequest(BaseModel):
    """Create a new authorized scope."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable scope name",
        examples=["My Production App"],
    )

    scope_type: ScopeType = Field(
        ...,
        description="Type of scope target",
    )

    target: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Target domain, IP range, or URL prefix",
        examples=["example.com", "*.example.com", "192.168.1.0/24"],
    )

    include_subdomains: bool = Field(
        default=False,
        description="Include subdomains in scope",
    )

    description: str | None = Field(
        None,
        max_length=2000,
        description="Scope description",
    )

    max_requests_per_second: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Rate limit for requests to this scope",
    )

    excluded_paths: list[str] | None = Field(
        None,
        description="URL path patterns to exclude (glob format)",
        examples=[["/admin/*", "/api/internal/*"]],
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Basic target format validation."""
        v = v.strip().lower()
        # Remove trailing slashes for domains
        if not v.startswith("http") and not v.startswith("/"):
            v = v.rstrip("/")
        # Block obviously invalid targets
        if v in ("localhost", "127.0.0.1", "0.0.0.0"):
            raise ValueError("Cannot create scope for localhost (use SELF_HOSTED scope type)")
        return v


class ScopeUpdateRequest(BaseModel):
    """Update an existing scope."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    include_subdomains: bool | None = None
    max_requests_per_second: int | None = Field(None, ge=1, le=100)
    excluded_paths: list[str] | None = None
    ip_allowlist: list[str] | None = None
    ip_blocklist: list[str] | None = None


class ScopeValidateRequest(BaseModel):
    """Trigger scope ownership validation."""

    method: ValidationMethod = Field(
        ...,
        description="Validation method to use",
    )


# ── Response Schemas ─────────────────────────────────────────
class ScopeResponse(BaseModel):
    """Scope detail response."""

    id: uuid.UUID
    owner_id: uuid.UUID
    name: str
    scope_type: ScopeType
    target: str
    include_subdomains: bool
    status: ScopeStatus
    max_requests_per_second: int
    ip_allowlist: list[str] | None
    ip_blocklist: list[str] | None
    excluded_paths: list[str] | None
    description: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScopeListResponse(BaseModel):
    """Paginated scope list response."""

    items: list[ScopeResponse]
    total: int
    page: int
    page_size: int


class ScopeValidationResponse(BaseModel):
    """Scope validation result."""

    scope_id: uuid.UUID
    method: ValidationMethod
    is_valid: bool
    validation_token: str | None = None
    instructions: str | None = None
    message: str

    model_config = {"from_attributes": True}


class ScopeValidationStatusResponse(BaseModel):
    """Current validation status of a scope."""

    scope_id: uuid.UUID
    status: ScopeStatus
    validations: list[dict]
    is_ready_for_scanning: bool
