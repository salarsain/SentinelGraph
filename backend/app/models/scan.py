"""
SentinelGraph — Scan & Target Models

Scan jobs, scan phases, targets, and discovered assets.
"""

import enum
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


# ── Enums ────────────────────────────────────────────────────
class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPhaseStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    API_ENDPOINT = "api_endpoint"
    FORM = "form"
    JS_FILE = "js_file"
    PARAMETER = "parameter"


# ── Target Model ─────────────────────────────────────────────
class Target(Base):
    """A registered target for security assessment."""

    __tablename__ = "targets"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    scope_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_scopes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    scans = relationship("Scan", back_populates="target", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Target(id={self.id}, url={self.url})>"


# ── Scan Model ───────────────────────────────────────────────
class Scan(Base):
    """A security assessment scan job."""

    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    scope_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_scopes.id", ondelete="SET NULL"),
        nullable=True,
    )

    initiated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Progress tracking
    progress: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
        comment="Overall scan progress (0.0 to 1.0)",
    )

    current_phase: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    # Configuration
    config: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Scan configuration: depth, modules, rate limits",
    )

    # Results summary
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    info_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    urls_discovered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timing
    started_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Celery task tracking
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Error info
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    target = relationship("Target", back_populates="scans", lazy="selectin")
    phases = relationship("ScanPhase", back_populates="scan", lazy="selectin", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", lazy="noload", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, status={self.status.value}, progress={self.progress:.0%})>"


# ── Scan Phase Model ─────────────────────────────────────────
class ScanPhase(Base):
    """Tracks individual phases within a scan."""

    __tablename__ = "scan_phases"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    phase_name: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[ScanPhaseStatus] = mapped_column(
        Enum(ScanPhaseStatus, name="scan_phase_status"),
        default=ScanPhaseStatus.PENDING,
        nullable=False,
    )

    started_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    results: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, comment="Phase-specific results"
    )

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="phases")


# ── Discovered Asset Model ───────────────────────────────────
class DiscoveredAsset(Base):
    """An asset discovered during scanning (domain, endpoint, API, etc.)."""

    __tablename__ = "discovered_assets"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, name="asset_type"),
        nullable=False,
        index=True,
    )

    value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        comment="Asset value: URL, domain, IP, etc.",
    )

    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovered_assets.id", ondelete="SET NULL"),
        nullable=True,
        comment="Parent asset (for graph building)",
    )

    metadata_json: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Asset-specific metadata (headers, status codes, etc.)",
    )

    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    technologies: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    def __repr__(self) -> str:
        return f"<DiscoveredAsset(type={self.asset_type.value}, value={self.value[:50]})>"
