"""
SentinelGraph — Scan & Target Schemas

Pydantic models for scan configuration, progress, and results.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl

from app.models.finding import FindingSeverity, FindingStatus, FindingType
from app.models.scan import ScanStatus


# ── Target Schemas ───────────────────────────────────────────
class TargetCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1, max_length=2048, examples=["https://example.com"])
    scope_id: uuid.UUID
    description: str | None = None
    config: dict | None = None


class TargetResponse(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    scope_id: uuid.UUID
    name: str
    url: str
    description: str | None
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Scan Schemas ─────────────────────────────────────────────
class ScanCreateRequest(BaseModel):
    """Start a new scan."""
    target_id: uuid.UUID
    config: dict | None = Field(
        None,
        description="Scan configuration overrides",
        examples=[{
            "crawl_depth": 5,
            "max_requests_per_second": 10,
            "modules": ["recon", "crawl", "headers", "passive", "active"],
            "skip_phases": [],
        }],
    )


class ScanPhaseResponse(BaseModel):
    id: uuid.UUID
    phase_name: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    results: dict | None
    error_message: str | None
    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    scope_id: uuid.UUID | None
    status: ScanStatus
    progress: float
    current_phase: str | None
    config: dict | None
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    urls_discovered: int
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime
    phases: list[ScanPhaseResponse] = []
    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


class ScanProgressUpdate(BaseModel):
    """WebSocket message for scan progress."""
    scan_id: uuid.UUID
    status: ScanStatus
    progress: float
    current_phase: str | None
    message: str | None


# ── Finding Schemas ──────────────────────────────────────────
class FindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    finding_type: FindingType
    severity: FindingSeverity
    status: FindingStatus
    title: str
    description: str
    remediation: str | None
    url: str
    parameter: str | None
    method: str | None
    evidence: dict | None
    cvss_vector: str | None
    cvss_score: float | None
    confidence: float
    ai_confidence: float | None
    is_false_positive: bool | None
    detection_rule: str | None
    references: dict | None
    created_at: datetime
    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingUpdateRequest(BaseModel):
    """Update finding status (human review)."""
    status: FindingStatus | None = None
    is_false_positive: bool | None = None
    notes: str | None = None
