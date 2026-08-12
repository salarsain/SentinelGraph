"""
SentinelGraph — Database Engine

Async SQLAlchemy with PostgreSQL (asyncpg).
Provides session factory, engine lifecycle, and base model.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.config import get_settings

logger = structlog.get_logger(__name__)

settings = get_settings()

# ── Engine ───────────────────────────────────────────────────
engine = create_async_engine(
    settings.effective_database_url,
    echo=settings.is_development,
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=10,
    poolclass=NullPool if settings.app_env == "test" else None,
)

# ── Session Factory ──────────────────────────────────────────
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for database sessions with automatic rollback on error."""
    session = async_session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database session injection."""
    async with get_db_session() as session:
        yield session


async def init_db() -> None:
    """Initialize database connection pool."""
    logger.info("database.init", url=settings.postgres_host, db=settings.postgres_db)
    async with engine.begin() as conn:
        # Verify connection
        await conn.execute(
            __import__("sqlalchemy").text("SELECT 1")
        )
    logger.info("database.connected")


async def close_db() -> None:
    """Dispose database engine and connection pool."""
    logger.info("database.closing")
    await engine.dispose()
    logger.info("database.closed")
