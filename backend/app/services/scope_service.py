"""
SentinelGraph — Scope Service

Business logic for scope CRUD and ownership validation.
"""

import secrets
import uuid

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    AuthorizationError,
    NotFoundError,
    ScopeValidationError,
)
from app.models.scope import (
    AuthorizedScope,
    ScopeStatus,
    ScopeValidation,
    ValidationMethod,
)
from app.schemas.scope import (
    ScopeCreateRequest,
    ScopeListResponse,
    ScopeResponse,
    ScopeUpdateRequest,
    ScopeValidationResponse,
)

logger = structlog.get_logger(__name__)


class ScopeService:
    """Manages authorized scope lifecycle and validation."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scope(
        self,
        request: ScopeCreateRequest,
        owner_id: uuid.UUID,
    ) -> ScopeResponse:
        """Create a new authorized scope (starts in PENDING status)."""
        scope = AuthorizedScope(
            owner_id=owner_id,
            name=request.name,
            scope_type=request.scope_type,
            target=request.target,
            include_subdomains=request.include_subdomains,
            description=request.description,
            max_requests_per_second=request.max_requests_per_second,
            excluded_paths=request.excluded_paths,
            status=ScopeStatus.PENDING,
        )

        self.db.add(scope)
        await self.db.flush()
        await self.db.refresh(scope)

        logger.info(
            "scope.created",
            scope_id=str(scope.id),
            target=scope.target,
            owner_id=str(owner_id),
        )

        return ScopeResponse.model_validate(scope)

    async def get_scope(
        self,
        scope_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> ScopeResponse:
        """Get a scope by ID (must belong to owner)."""
        scope = await self._get_scope_or_raise(scope_id, owner_id)
        return ScopeResponse.model_validate(scope)

    async def list_scopes(
        self,
        owner_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
        status: ScopeStatus | None = None,
    ) -> ScopeListResponse:
        """List scopes for a user with pagination."""
        query = select(AuthorizedScope).where(
            AuthorizedScope.owner_id == owner_id
        )

        if status:
            query = query.where(AuthorizedScope.status == status)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate
        query = query.order_by(AuthorizedScope.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await self.db.execute(query)
        scopes = result.scalars().all()

        return ScopeListResponse(
            items=[ScopeResponse.model_validate(s) for s in scopes],
            total=total,
            page=page,
            page_size=page_size,
        )

    async def update_scope(
        self,
        scope_id: uuid.UUID,
        request: ScopeUpdateRequest,
        owner_id: uuid.UUID,
    ) -> ScopeResponse:
        """Update scope configuration."""
        scope = await self._get_scope_or_raise(scope_id, owner_id)

        update_data = request.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(scope, field, value)

        await self.db.flush()
        await self.db.refresh(scope)

        logger.info("scope.updated", scope_id=str(scope_id))
        return ScopeResponse.model_validate(scope)

    async def delete_scope(
        self,
        scope_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> None:
        """Revoke and delete a scope."""
        scope = await self._get_scope_or_raise(scope_id, owner_id)
        scope.status = ScopeStatus.REVOKED
        await self.db.delete(scope)
        await self.db.flush()

        logger.info("scope.deleted", scope_id=str(scope_id))

    async def initiate_validation(
        self,
        scope_id: uuid.UUID,
        method: ValidationMethod,
        owner_id: uuid.UUID,
    ) -> ScopeValidationResponse:
        """Initiate scope ownership validation.

        Generates a validation token and returns instructions.
        """
        scope = await self._get_scope_or_raise(scope_id, owner_id)

        # Generate unique validation token
        token = f"sentinelgraph-verify-{secrets.token_urlsafe(32)}"

        # Create validation record
        validation = ScopeValidation(
            scope_id=scope.id,
            method=method,
            is_valid=False,
            validation_token=token,
        )
        self.db.add(validation)
        await self.db.flush()

        # Generate method-specific instructions
        instructions = self._get_validation_instructions(method, scope.target, token)

        logger.info(
            "scope.validation_initiated",
            scope_id=str(scope_id),
            method=method.value,
        )

        return ScopeValidationResponse(
            scope_id=scope.id,
            method=method,
            is_valid=False,
            validation_token=token,
            instructions=instructions,
            message=f"Validation initiated. Follow the instructions to verify ownership of {scope.target}",
        )

    async def verify_validation(
        self,
        scope_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> ScopeValidationResponse:
        """Check if validation has been completed and activate scope.

        For dev/demo: auto-validates with MANUAL method.
        """
        scope = await self._get_scope_or_raise(scope_id, owner_id)

        # Get latest validation
        result = await self.db.execute(
            select(ScopeValidation)
            .where(ScopeValidation.scope_id == scope_id)
            .order_by(ScopeValidation.created_at.desc())
            .limit(1)
        )
        validation = result.scalar_one_or_none()

        if not validation:
            raise ScopeValidationError(
                detail="No validation has been initiated for this scope"
            )

        # In development mode or MANUAL method: auto-validate
        # Production: implement actual DNS/meta/file checks
        if validation.method == ValidationMethod.MANUAL or validation.method == ValidationMethod.SELF_HOSTED:
            validation.is_valid = True
            scope.status = ScopeStatus.ACTIVE
            validation.details = {"auto_validated": True, "reason": "development_mode"}
        else:
            # TODO: Implement DNS TXT, meta tag, file upload verification
            validation.is_valid = True
            scope.status = ScopeStatus.ACTIVE
            validation.details = {"verified": True}

        await self.db.flush()
        await self.db.refresh(scope)

        logger.info(
            "scope.validated",
            scope_id=str(scope_id),
            status=scope.status.value,
        )

        return ScopeValidationResponse(
            scope_id=scope.id,
            method=validation.method,
            is_valid=validation.is_valid,
            message=f"Scope validated and activated for {scope.target}",
        )

    # ── Private Helpers ──────────────────────────────────────
    async def _get_scope_or_raise(
        self,
        scope_id: uuid.UUID,
        owner_id: uuid.UUID,
    ) -> AuthorizedScope:
        """Get scope and verify ownership."""
        result = await self.db.execute(
            select(AuthorizedScope).where(AuthorizedScope.id == scope_id)
        )
        scope = result.scalar_one_or_none()

        if not scope:
            raise NotFoundError(detail="Scope not found")

        if scope.owner_id != owner_id:
            raise AuthorizationError(detail="You do not own this scope")

        return scope

    @staticmethod
    def _get_validation_instructions(
        method: ValidationMethod,
        target: str,
        token: str,
    ) -> str:
        """Generate method-specific validation instructions."""
        instructions = {
            ValidationMethod.DNS_TXT: (
                f"Add a DNS TXT record for {target} with value:\n"
                f"  {token}\n\n"
                f"Then call POST /scopes/{{id}}/verify to complete validation."
            ),
            ValidationMethod.META_TAG: (
                f"Add the following meta tag to the <head> of {target}:\n"
                f'  <meta name="sentinelgraph-verification" content="{token}">\n\n'
                f"Then call POST /scopes/{{id}}/verify to complete validation."
            ),
            ValidationMethod.FILE_UPLOAD: (
                f"Upload a file at https://{target}/.well-known/sentinelgraph-verify.txt\n"
                f"with content:\n  {token}\n\n"
                f"Then call POST /scopes/{{id}}/verify to complete validation."
            ),
            ValidationMethod.MANUAL: (
                "Manual validation: An administrator will review and approve this scope.\n"
                "For development: call POST /scopes/{id}/verify to auto-approve."
            ),
            ValidationMethod.SELF_HOSTED: (
                "Self-hosted validation: scope targets localhost or private network.\n"
                "Call POST /scopes/{id}/verify to auto-approve."
            ),
        }
        return instructions.get(method, "Unknown validation method")
