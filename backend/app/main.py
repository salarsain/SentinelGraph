"""
SentinelGraph — FastAPI Application

Main application factory with lifespan events, middleware,
exception handlers, and route mounting.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_v1_router
from app.config import get_settings
from app.core.database import close_db, init_db
from app.core.exceptions import SentinelGraphError
from app.core.redis import close_redis, init_redis

logger = structlog.get_logger(__name__)
settings = get_settings()


# ── Lifespan (startup/shutdown) ──────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle: initialize and tear down resources."""
    logger.info(
        "app.starting",
        name=settings.app_name,
        version=settings.app_version,
        env=settings.app_env,
    )

    # Startup
    await init_db()
    await init_redis()

    # Storage init is optional (may not have MinIO in dev)
    try:
        from app.core.storage import init_storage
        await init_storage()
    except Exception as e:
        logger.warning("app.storage_init_skipped", error=str(e))

    logger.info("app.started", msg="All services initialized")

    yield

    # Shutdown
    logger.info("app.shutting_down")
    await close_redis()
    await close_db()
    logger.info("app.stopped")


# ── App Factory ──────────────────────────────────────────────
def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    application = FastAPI(
        title=settings.app_name,
        description=(
            "AI-Powered Autonomous Web Application Security Assessment Platform. "
            "Performs authorized, evidence-based security testing with AI-assisted "
            "vulnerability classification and false-positive reduction."
        ),
        version=settings.app_version,
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:80",
            "https://localhost",
        ] if settings.is_development else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Exception Handlers ───────────────────────────────
    @application.exception_handler(SentinelGraphError)
    async def sentinelgraph_error_handler(
        request: Request,
        exc: SentinelGraphError,
    ) -> JSONResponse:
        """Handle all SentinelGraph-specific exceptions."""
        logger.warning(
            "api.error",
            error_code=exc.error_code,
            detail=exc.detail,
            path=request.url.path,
            method=request.method,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
        )

    @application.exception_handler(Exception)
    async def generic_error_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """Catch-all for unhandled exceptions."""
        logger.error(
            "api.unhandled_error",
            error=str(exc),
            error_type=type(exc).__name__,
            path=request.url.path,
            method=request.method,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred" if not settings.is_development else str(exc),
                }
            },
        )

    # ── Routes ───────────────────────────────────────────
    application.include_router(api_v1_router)

    @application.get(
        "/health",
        tags=["System"],
        summary="Health check",
        include_in_schema=True,
    )
    async def health_check():
        """System health check endpoint."""
        return {
            "status": "healthy",
            "service": settings.app_name,
            "version": settings.app_version,
            "environment": settings.app_env,
        }

    @application.get(
        "/",
        tags=["System"],
        include_in_schema=False,
    )
    async def root():
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs" if settings.is_development else None,
            "api": "/api/v1",
        }

    return application


# ── Application Instance ─────────────────────────────────────
app = create_app()
