"""
SentinelGraph — Scope & Authorization Models

Authorized scopes define what targets a user is allowed to scan.
Every outbound request MUST be validated against an authorized scope.
"""

import enum
import uuid

from sqlalchemy import (
    Boolean,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ScopeStatus(str, enum.Enum):
    """Scope lifecycle status."""

    PENDING = "pending"          # Awaiting ownership verification
    ACTIVE = "active"            # Verified and ready for scanning
    SUSPENDED = "suspended"      # Temporarily disabled
    REVOKED = "revoked"          # Permanently disabled


class ScopeType(str, enum.Enum):
    """Type of scope target."""

    DOMAIN = "domain"            # Single domain
    WILDCARD = "wildcard"        # *.example.com
    IP_RANGE = "ip_range"        # CIDR range
    URL_PREFIX = "url_prefix"    # https://example.com/app/


class ValidationMethod(str, enum.Enum):
    """How scope ownership was validated."""

    DNS_TXT = "dns_txt"          # DNS TXT record verification
    META_TAG = "meta_tag"        # HTML meta tag
    FILE_UPLOAD = "file_upload"  # Well-known file upload
    MANUAL = "manual"            # Admin manual approval
    SELF_HOSTED = "self_hosted"  # localhost/private network (dev only)


class AuthorizedScope(Base):
    """Defines an authorized scanning scope.

    This is the P0 security boundary — nothing is scanned
    unless it falls within a validated, active scope.
    """

    __tablename__ = "authorized_scopes"

    # Ownership
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Scope definition
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    scope_type: Mapped[ScopeType] = mapped_column(
        Enum(ScopeType, name="scope_type"),
        nullable=False,
    )

    target: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        index=True,
        comment="Primary target: domain, CIDR, or URL prefix",
    )

    include_subdomains: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Status
    status: Mapped[ScopeStatus] = mapped_column(
        Enum(ScopeStatus, name="scope_status"),
        default=ScopeStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Boundaries
    ip_allowlist: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        nullable=True,
        comment="Explicit IP allowlist (overrides blocklist)",
    )

    ip_blocklist: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        nullable=True,
        comment="IPs to exclude from scope",
    )

    excluded_paths: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        nullable=True,
        comment="URL path patterns to exclude (glob)",
    )

    # Rate limiting
    max_requests_per_second: Mapped[int] = mapped_column(
        Integer,
        default=10,
        nullable=False,
    )

    # Metadata
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    config: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Additional scope configuration as JSON",
    )

    # Relationships
    owner = relationship("User", back_populates="scopes", lazy="selectin")
    validations = relationship(
        "ScopeValidation",
        back_populates="scope",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<AuthorizedScope(id={self.id}, target={self.target}, status={self.status.value})>"


class ScopeValidation(Base):
    """Records of scope ownership validation attempts."""

    __tablename__ = "scope_validations"

    scope_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_scopes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    method: Mapped[ValidationMethod] = mapped_column(
        Enum(ValidationMethod, name="validation_method"),
        nullable=False,
    )

    is_valid: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    validation_token: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="Token placed in DNS/meta/file for verification",
    )

    details: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Validation details and evidence",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    scope = relationship("AuthorizedScope", back_populates="validations")

    def __repr__(self) -> str:
        return f"<ScopeValidation(scope_id={self.scope_id}, method={self.method.value}, valid={self.is_valid})>"
