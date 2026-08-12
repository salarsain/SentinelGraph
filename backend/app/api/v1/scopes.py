"""
SentinelGraph — Scope API Routes

CRUD operations for authorized scopes and ownership validation.
"""

import uuid

from fastapi import APIRouter, Query, status

from app.dependencies import ActiveUser, ScopeSvc
from app.models.scope import ScopeStatus
from app.schemas.scope import (
    ScopeCreateRequest,
    ScopeListResponse,
    ScopeResponse,
    ScopeUpdateRequest,
    ScopeValidateRequest,
    ScopeValidationResponse,
)

router = APIRouter(prefix="/scopes", tags=["Scopes & Authorization"])


@router.post(
    "",
    response_model=ScopeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new authorized scope",
    description="Define a target scope for security assessment. "
                "Scope starts in PENDING status until ownership is verified.",
)
async def create_scope(
    request: ScopeCreateRequest,
    current_user: ActiveUser,
    scope_service: ScopeSvc,
) -> ScopeResponse:
    return await scope_service.create_scope(request, current_user.id)


@router.get(
    "",
    response_model=ScopeListResponse,
    summary="List your authorized scopes",
)
async def list_scopes(
    current_user: ActiveUser,
    scope_service: ScopeSvc,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status_filter: ScopeStatus | None = Query(None, alias="status", description="Filter by status"),
) -> ScopeListResponse:
    return await scope_service.list_scopes(
        owner_id=current_user.id,
        page=page,
        page_size=page_size,
        status=status_filter,
    )


@router.get(
    "/{scope_id}",
    response_model=ScopeResponse,
    summary="Get scope details",
)
async def get_scope(
    scope_id: uuid.UUID,
    current_user: ActiveUser,
    scope_service: ScopeSvc,
) -> ScopeResponse:
    return await scope_service.get_scope(scope_id, current_user.id)


@router.put(
    "/{scope_id}",
    response_model=ScopeResponse,
    summary="Update scope configuration",
)
async def update_scope(
    scope_id: uuid.UUID,
    request: ScopeUpdateRequest,
    current_user: ActiveUser,
    scope_service: ScopeSvc,
) -> ScopeResponse:
    return await scope_service.update_scope(scope_id, request, current_user.id)


@router.delete(
    "/{scope_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete (revoke) a scope",
)
async def delete_scope(
    scope_id: uuid.UUID,
    current_user: ActiveUser,
    scope_service: ScopeSvc,
) -> None:
    await scope_service.delete_scope(scope_id, current_user.id)


@router.post(
    "/{scope_id}/validate",
    response_model=ScopeValidationResponse,
    summary="Initiate scope ownership validation",
    description="Start the ownership verification process. "
                "Returns instructions for the chosen validation method.",
)
async def initiate_validation(
    scope_id: uuid.UUID,
    request: ScopeValidateRequest,
    current_user: ActiveUser,
    scope_service: ScopeSvc,
) -> ScopeValidationResponse:
    return await scope_service.initiate_validation(
        scope_id, request.method, current_user.id
    )


@router.post(
    "/{scope_id}/verify",
    response_model=ScopeValidationResponse,
    summary="Verify scope ownership",
    description="Check if the validation has been completed and activate the scope.",
)
async def verify_scope(
    scope_id: uuid.UUID,
    current_user: ActiveUser,
    scope_service: ScopeSvc,
) -> ScopeValidationResponse:
    return await scope_service.verify_validation(scope_id, current_user.id)
