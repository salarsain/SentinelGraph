"""
SentinelGraph — FastAPI Dependencies

Dependency injection providers for auth, database, and services.
"""

import uuid
from typing import Annotated

import structlog
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import validate_access_token
from app.models.user import User, UserRole
from app.services.auth_service import AuthService
from app.services.scope_service import ScopeService

logger = structlog.get_logger(__name__)

# ── Security Scheme ──────────────────────────────────────────
security = HTTPBearer(auto_error=False)


# ── Auth Dependencies ────────────────────────────────────────
async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(security),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Extract and validate the current user from JWT bearer token.

    Raises:
        HTTPException 401: If token is missing, invalid, or expired.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = validate_access_token(credentials.credentials)
        user_id = uuid.UUID(payload["sub"])
    except (JWTError, ValueError, KeyError) as e:
        logger.warning("auth.invalid_token", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch user from database
    auth_service = AuthService(db)
    try:
        user = await auth_service.get_user_by_id(user_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Ensure the current user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )
    return current_user


# ── Role-Based Dependencies ──────────────────────────────────
def require_role(*roles: UserRole):
    """Create a dependency that requires specific user roles."""

    async def role_checker(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {', '.join(r.value for r in roles)}",
            )
        return current_user

    return role_checker


RequireAdmin = Depends(require_role(UserRole.ADMIN))
RequireAnalyst = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST))


# ── Service Dependencies ────────────────────────────────────
async def get_auth_service(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AuthService:
    """Inject AuthService with database session."""
    return AuthService(db)


async def get_scope_service(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScopeService:
    """Inject ScopeService with database session."""
    return ScopeService(db)


# ── Type Aliases for Clean Route Signatures ──────────────────
CurrentUser = Annotated[User, Depends(get_current_user)]
ActiveUser = Annotated[User, Depends(get_current_active_user)]
DB = Annotated[AsyncSession, Depends(get_db)]
AuthSvc = Annotated[AuthService, Depends(get_auth_service)]
ScopeSvc = Annotated[ScopeService, Depends(get_scope_service)]
