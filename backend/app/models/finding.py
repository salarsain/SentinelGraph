"""
SentinelGraph — Finding Model

Security findings with severity, evidence, confidence, and AI analysis linkage.
"""

import enum
import uuid

from sqlalchemy import (
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


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    REMEDIATED = "remediated"
    IN_REVIEW = "in_review"


class FindingType(str, enum.Enum):
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI = "sql_injection"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    CSRF = "csrf"
    CORS_MISCONFIG = "cors_misconfiguration"
    MISSING_HEADER = "missing_security_header"
    HEADER_MISCONFIG = "header_misconfiguration"
    INFO_DISCLOSURE = "information_disclosure"
    SENSITIVE_FILE = "sensitive_file_exposure"
    DEFAULT_CREDS = "default_credentials"
    WEAK_SSL = "weak_ssl_configuration"
    COOKIE_INSECURE = "insecure_cookie"
    SESSION_ISSUE = "session_management_issue"
    DIRECTORY_LISTING = "directory_listing"
    DEBUG_ENABLED = "debug_mode_enabled"
    VERSION_DISCLOSURE = "version_disclosure"
    API_SECURITY = "api_security_issue"
    GRAPHQL_ISSUE = "graphql_security_issue"
    JWT_ISSUE = "jwt_security_issue"
    MISCONFIGURATION = "misconfiguration"
    OTHER = "other"


class Finding(Base):
    """A security finding discovered during scanning."""

    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Classification
    finding_type: Mapped[FindingType] = mapped_column(
        Enum(FindingType, name="finding_type"),
        nullable=False,
        index=True,
    )

    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity"),
        nullable=False,
        index=True,
    )

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status"),
        default=FindingStatus.NEW,
        nullable=False,
        index=True,
    )

    # Description
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Location
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    path: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    # Evidence
    evidence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Evidence data: request/response, screenshots, diffs",
    )

    # Scoring
    cvss_vector: Mapped[str | None] = mapped_column(
        String(128), nullable=True,
        comment="CVSS 3.1 vector string",
    )
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(
        Float, default=0.5, nullable=False,
        comment="Detection confidence (0.0 to 1.0)",
    )

    # AI Analysis
    ai_classification: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="AI analyst classification result",
    )
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_false_positive: Mapped[bool | None] = mapped_column(
        nullable=True,
        comment="AI or human false-positive determination",
    )

    # Detection metadata
    detection_rule: Mapped[str | None] = mapped_column(
        String(128), nullable=True,
        comment="Rule ID that detected this finding",
    )
    detection_module: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
        comment="Module that detected this (passive_checks, active_probes, etc.)",
    )

    # References
    references: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="External references: OWASP, CWE, CVE links",
    )

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding(type={self.finding_type.value}, severity={self.severity.value}, url={self.url[:50]})>"
