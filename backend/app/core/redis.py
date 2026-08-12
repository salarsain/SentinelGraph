"""
SentinelGraph — Redis Client

Async Redis client for caching, rate limiting, and pub/sub.
"""

from typing import Any

import redis.asyncio as aioredis
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# ── Redis Connection Pool ────────────────────────────────────
redis_pool: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    """Get the Redis client instance."""
    global redis_pool
    if redis_pool is None:
        redis_pool = aioredis.from_url(
            settings.effective_redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50,
        )
    return redis_pool


async def init_redis() -> None:
    """Initialize Redis connection and verify connectivity."""
    logger.info("redis.init", host=settings.redis_host, port=settings.redis_port)
    client = await get_redis()
    await client.ping()
    logger.info("redis.connected")


async def close_redis() -> None:
    """Close Redis connection pool."""
    global redis_pool
    if redis_pool:
        logger.info("redis.closing")
        await redis_pool.aclose()
        redis_pool = None
        logger.info("redis.closed")


# ── Cache Helpers ────────────────────────────────────────────
class RedisCache:
    """Simple cache abstraction over Redis."""

    def __init__(self, prefix: str = "sg"):
        self.prefix = prefix

    def _key(self, key: str) -> str:
        return f"{self.prefix}:{key}"

    async def get(self, key: str) -> str | None:
        client = await get_redis()
        return await client.get(self._key(key))

    async def set(
        self,
        key: str,
        value: str | bytes,
        ttl_seconds: int | None = None,
    ) -> None:
        client = await get_redis()
        await client.set(self._key(key), value, ex=ttl_seconds)

    async def delete(self, key: str) -> None:
        client = await get_redis()
        await client.delete(self._key(key))

    async def exists(self, key: str) -> bool:
        client = await get_redis()
        return bool(await client.exists(self._key(key)))

    async def increment(self, key: str, ttl_seconds: int | None = None) -> int:
        client = await get_redis()
        val = await client.incr(self._key(key))
        if ttl_seconds and val == 1:
            await client.expire(self._key(key), ttl_seconds)
        return val


# ── Rate Limiter ─────────────────────────────────────────────
class RateLimiter:
    """Sliding-window rate limiter backed by Redis."""

    def __init__(self, prefix: str = "ratelimit"):
        self.cache = RedisCache(prefix=prefix)

    async def is_allowed(
        self,
        identifier: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """Check if a request is allowed within the rate limit.

        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        key = f"{identifier}:{window_seconds}"
        current = await self.cache.increment(key, ttl_seconds=window_seconds)
        remaining = max(0, max_requests - current)
        return current <= max_requests, remaining

    async def get_remaining(
        self,
        identifier: str,
        max_requests: int,
        window_seconds: int,
    ) -> int:
        """Get remaining requests in current window."""
        key = f"{identifier}:{window_seconds}"
        current = await self.cache.get(key)
        if current is None:
            return max_requests
        return max(0, max_requests - int(current))


# ── Pub/Sub for Scan Progress ────────────────────────────────
class ScanProgressPublisher:
    """Publish scan progress updates via Redis pub/sub."""

    CHANNEL_PREFIX = "sg:scan:progress"

    async def publish(self, scan_id: str, data: dict[str, Any]) -> None:
        """Publish scan progress update."""
        import json

        client = await get_redis()
        channel = f"{self.CHANNEL_PREFIX}:{scan_id}"
        await client.publish(channel, json.dumps(data))

    async def subscribe(self, scan_id: str):
        """Subscribe to scan progress updates."""
        client = await get_redis()
        pubsub = client.pubsub()
        channel = f"{self.CHANNEL_PREFIX}:{scan_id}"
        await pubsub.subscribe(channel)
        return pubsub
