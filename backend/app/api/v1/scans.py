"""
SentinelGraph — Scans & Targets API Routes

Scan lifecycle, target management, and findings retrieval.
"""

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.dependencies import ActiveUser
from app.models.scan import ScanStatus
from app.schemas.scan import (
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
    TargetCreateRequest,
    TargetResponse,
)
from app.services.scan_service import ScanService

router = APIRouter(tags=["Scans & Targets"])


# ── Dependency ───────────────────────────────────────────────
async def get_scan_service(db: AsyncSession = Depends(get_db)) -> ScanService:
    return ScanService(db)


# ── Target Endpoints ────────────────────────────────────────
@router.post(
    "/targets",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new scan target",
)
async def create_target(
    request: TargetCreateRequest,
    current_user: ActiveUser,
    service: ScanService = Depends(get_scan_service),
) -> TargetResponse:
    return await service.create_target(request, current_user.id)


@router.get(
    "/targets",
    summary="List your registered targets",
)
async def list_targets(
    current_user: ActiveUser,
    service: ScanService = Depends(get_scan_service),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    return await service.list_targets(current_user.id, page, page_size)


@router.get(
    "/targets/{target_id}",
    response_model=TargetResponse,
    summary="Get target details",
)
async def get_target(
    target_id: uuid.UUID,
    current_user: ActiveUser,
    service: ScanService = Depends(get_scan_service),
) -> TargetResponse:
    target = await service.get_target(target_id, current_user.id)
    return TargetResponse.model_validate(target)


# ── Scan Endpoints ──────────────────────────────────────────
@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new security scan",
    description="Create and immediately queue a scan. Requires an active scope.",
)
async def create_scan(
    request: ScanCreateRequest,
    current_user: ActiveUser,
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    return await service.create_scan(request, current_user.id)


@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List your scans",
)
async def list_scans(
    current_user: ActiveUser,
    service: ScanService = Depends(get_scan_service),
    target_id: uuid.UUID | None = Query(None),
    scan_status: ScanStatus | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> ScanListResponse:
    return await service.list_scans(
        owner_id=current_user.id,
        target_id=target_id,
        status=scan_status,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan details with phase progress",
)
async def get_scan(
    scan_id: uuid.UUID,
    current_user: ActiveUser,
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    return await service.get_scan(scan_id, current_user.id)


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a running scan",
)
async def cancel_scan(
    scan_id: uuid.UUID,
    current_user: ActiveUser,
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    return await service.cancel_scan(scan_id, current_user.id)
