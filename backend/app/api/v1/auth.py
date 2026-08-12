"""
SentinelGraph — Auth API Routes

User registration, login, token refresh, and profile management.
"""

from fastapi import APIRouter, status

from app.dependencies import ActiveUser, AuthSvc
from app.schemas.auth import (
    TokenPair,
    TokenRefreshRequest,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description="Create a new user account with email and password. "
                "Passwords must be at least 8 characters with uppercase, lowercase, and digit.",
)
async def register(
    request: UserRegisterRequest,
    auth_service: AuthSvc,
) -> UserResponse:
    return await auth_service.register(request)


@router.post(
    "/login",
    response_model=TokenPair,
    summary="Authenticate and get JWT tokens",
    description="Authenticate with email and password. Returns access and refresh token pair.",
)
async def login(
    request: UserLoginRequest,
    auth_service: AuthSvc,
) -> TokenPair:
    return await auth_service.login(request.email, request.password)


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Refresh access token",
    description="Exchange a valid refresh token for a new access/refresh token pair.",
)
async def refresh_token(
    request: TokenRefreshRequest,
    auth_service: AuthSvc,
) -> TokenPair:
    return await auth_service.refresh_tokens(request.refresh_token)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(current_user: ActiveUser) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update current user profile",
)
async def update_me(
    request: UserUpdateRequest,
    current_user: ActiveUser,
    auth_service: AuthSvc,
) -> UserResponse:
    return await auth_service.update_profile(current_user.id, request)
