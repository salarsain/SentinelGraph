"""
SentinelGraph — Auth Service

Business logic for user registration, authentication, and token management.
"""

import uuid

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import (
    ConflictError,
    InvalidCredentialsError,
    InvalidTokenError,
    NotFoundError,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    validate_refresh_token,
    verify_password,
)
from app.models.user import User, UserRole
from app.schemas.auth import (
    TokenPair,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)

logger = structlog.get_logger(__name__)
settings = get_settings()


class AuthService:
    """Handles user authentication, registration, and token lifecycle."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def register(self, request: UserRegisterRequest) -> UserResponse:
        """Register a new user account.

        Raises:
            ConflictError: If email is already registered.
        """
        # Check for existing user
        existing = await self.db.execute(
            select(User).where(User.email == request.email.lower())
        )
        if existing.scalar_one_or_none():
            raise ConflictError(
                detail="An account with this email already exists",
                error_code="EMAIL_ALREADY_EXISTS",
            )

        # Create user
        user = User(
            email=request.email.lower(),
            hashed_password=hash_password(request.password),
            full_name=request.full_name,
            role=UserRole.ANALYST,
            is_active=True,
            is_verified=False,  # Require email verification in production
        )

        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)

        logger.info("auth.user_registered", user_id=str(user.id), email=user.email)
        return UserResponse.model_validate(user)

    async def login(self, email: str, password: str) -> TokenPair:
        """Authenticate a user and return JWT token pair.

        Raises:
            InvalidCredentialsError: If email/password is incorrect.
        """
        # Find user
        result = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        user = result.scalar_one_or_none()

        if not user or not verify_password(password, user.hashed_password):
            logger.warning("auth.login_failed", email=email)
            raise InvalidCredentialsError()

        if not user.is_active:
            raise InvalidCredentialsError(
                detail="Account is deactivated",
                error_code="ACCOUNT_DEACTIVATED",
            )

        # Generate tokens
        access_token = create_access_token(
            subject=user.id,
            extra_claims={"role": user.role.value},
        )
        refresh_token = create_refresh_token(subject=user.id)

        logger.info("auth.login_success", user_id=str(user.id))

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.jwt_access_token_expire_minutes * 60,
        )

    async def refresh_tokens(self, refresh_token: str) -> TokenPair:
        """Refresh an access token using a valid refresh token.

        Raises:
            InvalidTokenError: If refresh token is invalid or expired.
        """
        try:
            payload = validate_refresh_token(refresh_token)
        except Exception:
            raise InvalidTokenError(detail="Invalid or expired refresh token")

        user_id = uuid.UUID(payload["sub"])
        user = await self.get_user_by_id(user_id)

        if not user.is_active:
            raise InvalidTokenError(detail="Account is deactivated")

        access_token = create_access_token(
            subject=user.id,
            extra_claims={"role": user.role.value},
        )
        new_refresh_token = create_refresh_token(subject=user.id)

        return TokenPair(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=settings.jwt_access_token_expire_minutes * 60,
        )

    async def get_user_by_id(self, user_id: uuid.UUID) -> User:
        """Get user by ID.

        Raises:
            NotFoundError: If user not found.
        """
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise NotFoundError(detail="User not found")
        return user

    async def update_profile(
        self,
        user_id: uuid.UUID,
        request: UserUpdateRequest,
    ) -> UserResponse:
        """Update user profile."""
        user = await self.get_user_by_id(user_id)

        if request.full_name is not None:
            user.full_name = request.full_name
        if request.bio is not None:
            user.bio = request.bio

        await self.db.flush()
        await self.db.refresh(user)

        return UserResponse.model_validate(user)
