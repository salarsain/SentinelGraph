"""
SentinelGraph — Scan Service

Business logic for scan lifecycle: creation, progress, and result management.
"""

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    AuthorizationError,
    NotFoundError,
    ScanAlreadyRunningError,
    ScopeViolationError,
)
from app.models.scan import (
    DiscoveredAsset,
    Scan,
    ScanPhase,
    ScanStatus,
    Target,
)
from app.models.scope import AuthorizedScope, ScopeStatus
from app.schemas.scan import (
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
    TargetCreateRequest,
    TargetResponse,
)

logger = structlog.get_logger(__name__)


class ScanService:
    """Manages scan lifecycle and target registration."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── Target Management ────────────────────────────────────
    async def create_target(
        self,
        request: TargetCreateRequest,
        owner_id: uuid.UUID,
    ) -> TargetResponse:
        """Register a new target for scanning."""
        # Verify scope exists and is owned by user
        scope = await self._get_active_scope(request.scope_id, owner_id)

        target = Target(
            owner_id=owner_id,
            scope_id=scope.id,
            name=request.name,
            url=request.url,
            description=request.description,
            config=request.config,
        )
        self.db.add(target)
        await self.db.flush()
        await self.db.refresh(target)

        logger.info("target.created", target_id=str(target.id), url=target.url)
        return TargetResponse.model_validate(target)

    async def get_target(
        self,
        target_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> Target:
        """Get target by ID (must belong to owner)."""
        result = await self.db.execute(
            select(Target).where(Target.id == target_id)
        )
        target = result.scalar_one_or_none()
        if not target:
            raise NotFoundError(detail="Target not found")
        if target.owner_id != owner_id:
            raise AuthorizationError(detail="You do not own this target")
        return target

    async def list_targets(
        self,
        owner_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List all targets for a user."""
        query = select(Target).where(Target.owner_id == owner_id)
        count_q = select(func.count()).select_from(query.subquery())
        total = (await self.db.execute(count_q)).scalar() or 0

        query = query.order_by(Target.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query)

        return {
            "items": [TargetResponse.model_validate(t) for t in result.scalars().all()],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    # ── Scan Lifecycle ───────────────────────────────────────
    async def create_scan(
        self,
        request: ScanCreateRequest,
        owner_id: uuid.UUID,
    ) -> ScanResponse:
        """Create and queue a new scan.

        Validates that:
        1. Target exists and belongs to user
        2. Target's scope is active
        3. No scan is already running for this target
        """
        target = await self.get_target(request.target_id, owner_id)

        # Verify scope is active
        scope = await self._get_active_scope(target.scope_id, owner_id)

        # Check for running scans
        running = await self.db.execute(
            select(Scan).where(
                Scan.target_id == target.id,
                Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
        )
        if running.scalar_one_or_none():
            raise ScanAlreadyRunningError()

        # Create scan
        scan = Scan(
            target_id=target.id,
            scope_id=scope.id,
            initiated_by=owner_id,
            status=ScanStatus.PENDING,
            config=request.config,
        )
        self.db.add(scan)
        await self.db.flush()
        await self.db.refresh(scan)

        # Create phase records
        from workers.orchestrator import PHASE_ORDER
        for phase in PHASE_ORDER:
            scan_phase = ScanPhase(
                scan_id=scan.id,
                phase_name=phase.value,
            )
            self.db.add(scan_phase)
        await self.db.flush()

        # Queue the scan via Celery
        from workers.orchestrator import ScanOrchestrator
        orchestrator = ScanOrchestrator(scan.id, scope.id)
        task_id = orchestrator.start(request.config)

        scan.celery_task_id = task_id
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await self.db.flush()
        await self.db.refresh(scan)

        logger.info(
            "scan.created",
            scan_id=str(scan.id),
            target=target.url,
            task_id=task_id,
        )

        return ScanResponse.model_validate(scan)

    async def get_scan(
        self,
        scan_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> ScanResponse:
        """Get scan details with phases."""
        result = await self.db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise NotFoundError(detail="Scan not found")

        # Verify ownership through target
        target = await self.get_target(scan.target_id, owner_id)

        return ScanResponse.model_validate(scan)

    async def list_scans(
        self,
        owner_id: uuid.UUID,
        target_id: uuid.UUID | None = None,
        status: ScanStatus | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ScanListResponse:
        """List scans with optional filters."""
        query = select(Scan).join(Target).where(Target.owner_id == owner_id)

        if target_id:
            query = query.where(Scan.target_id == target_id)
        if status:
            query = query.where(Scan.status == status)

        count_q = select(func.count()).select_from(query.subquery())
        total = (await self.db.execute(count_q)).scalar() or 0

        query = query.order_by(Scan.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query)

        return ScanListResponse(
            items=[ScanResponse.model_validate(s) for s in result.scalars().all()],
            total=total,
            page=page,
            page_size=page_size,
        )

    async def cancel_scan(
        self,
        scan_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> ScanResponse:
        """Cancel a running scan."""
        result = await self.db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise NotFoundError(detail="Scan not found")

        # Verify ownership
        await self.get_target(scan.target_id, owner_id)

        if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
            raise NotFoundError(detail="Scan is not running or pending")

        # Revoke Celery task
        if scan.celery_task_id:
            from workers.celery_app import celery_app
            celery_app.control.revoke(scan.celery_task_id, terminate=True)

        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.now(timezone.utc)
        await self.db.flush()
        await self.db.refresh(scan)

        logger.info("scan.cancelled", scan_id=str(scan_id))
        return ScanResponse.model_validate(scan)

    # ── Helpers ──────────────────────────────────────────────
    async def _get_active_scope(
        self,
        scope_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> AuthorizedScope:
        """Get scope and verify it's active and owned."""
        result = await self.db.execute(
            select(AuthorizedScope).where(AuthorizedScope.id == scope_id)
        )
        scope = result.scalar_one_or_none()
        if not scope:
            raise NotFoundError(detail="Scope not found")
        if scope.owner_id != owner_id:
            raise AuthorizationError(detail="You do not own this scope")
        if scope.status != ScopeStatus.ACTIVE:
            raise ScopeViolationError(
                detail=f"Scope is not active (status: {scope.status.value})"
            )
        return scope
