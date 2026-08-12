"""
SentinelGraph — HTTP Prober

Async HTTP client for probing targets. ALL requests are routed through
the Scope Enforcement Gateway. Captures full request/response data
for evidence and analysis.
"""

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.config import get_settings
from app.engine.scope_gateway import ScopeEnforcementGateway, get_scope_gateway
from app.models.scope import AuthorizedScope

logger = structlog.get_logger(__name__)
settings = get_settings()


@dataclass
class HTTPResponse:
    """Captured HTTP response with full metadata."""
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    body_text: str | None = None
    content_type: str | None = None
    content_length: int = 0
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str | None = None
    server: str | None = None
    technologies: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def is_html(self) -> bool:
        ct = self.content_type or ""
        return "text/html" in ct or "application/xhtml" in ct


@dataclass
class ProbeResult:
    """Result of probing a single URL with multiple methods."""
    url: str
    is_alive: bool = False
    supports_https: bool = False
    supported_methods: list[str] = field(default_factory=list)
    responses: dict[str, HTTPResponse] = field(default_factory=dict)


class HTTPProber:
    """High-performance async HTTP prober with scope enforcement.

    Every request passes through the Scope Enforcement Gateway before
    being sent to the target.
    """

    def __init__(
        self,
        scope: AuthorizedScope,
        timeout: float | None = None,
        max_redirects: int = 10,
        verify_ssl: bool = True,
    ):
        self.scope = scope
        self.timeout = timeout or settings.default_request_timeout
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl
        self.gateway = get_scope_gateway()

    async def probe(self, url: str, method: str = "GET", **kwargs) -> HTTPResponse:
        """Send an HTTP request through the scope gateway.

        Args:
            url: Target URL
            method: HTTP method
            **kwargs: Additional httpx request arguments

        Returns:
            HTTPResponse with full captured data
        """
        # ── SCOPE ENFORCEMENT (mandatory) ────────────────
        await self.gateway.validate_request(url, self.scope)

        start_time = time.monotonic()
        redirect_chain: list[str] = []

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                max_redirects=self.max_redirects,
                verify=self.verify_ssl,
                headers={
                    "User-Agent": settings.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                },
            ) as client:
                response = await client.request(method, url, **kwargs)

                # Track redirect chain
                for resp in response.history:
                    redirect_chain.append(str(resp.url))
                    # Validate each redirect hop through scope gateway
                    await self.gateway.validate_request(str(resp.url), self.scope)

                elapsed = (time.monotonic() - start_time) * 1000

                # Read body with size limit
                body = response.content
                max_size = settings.max_response_size_mb * 1024 * 1024
                if len(body) > max_size:
                    body = body[:max_size]
                    logger.warning("http_prober.response_truncated", url=url, size=len(response.content))

                # Decode body text
                body_text = None
                content_type = response.headers.get("content-type", "")
                if "text/" in content_type or "json" in content_type or "xml" in content_type:
                    try:
                        body_text = body.decode(response.encoding or "utf-8", errors="replace")
                    except Exception:
                        body_text = body.decode("utf-8", errors="replace")

                return HTTPResponse(
                    url=url,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=body,
                    body_text=body_text,
                    content_type=content_type,
                    content_length=len(body),
                    elapsed_ms=elapsed,
                    redirect_chain=redirect_chain,
                    final_url=str(response.url) if str(response.url) != url else None,
                    server=response.headers.get("server"),
                )

        except httpx.TimeoutException:
            elapsed = (time.monotonic() - start_time) * 1000
            logger.warning("http_prober.timeout", url=url, elapsed_ms=elapsed)
            return HTTPResponse(
                url=url, status_code=0, headers={}, body=b"",
                elapsed_ms=elapsed, error="Connection timed out",
            )
        except httpx.ConnectError as e:
            return HTTPResponse(
                url=url, status_code=0, headers={}, body=b"",
                error=f"Connection failed: {e}",
            )
        except Exception as e:
            logger.error("http_prober.error", url=url, error=str(e))
            return HTTPResponse(
                url=url, status_code=0, headers={}, body=b"",
                error=str(e),
            )

    async def probe_full(self, url: str) -> ProbeResult:
        """Full probe: check HTTPS, enumerate methods, capture GET response."""
        result = ProbeResult(url=url)

        # Try HTTPS first, then HTTP
        for scheme_url in [url.replace("http://", "https://"), url]:
            response = await self.probe(scheme_url)
            if response.status_code > 0:
                result.is_alive = True
                result.responses["GET"] = response
                if scheme_url.startswith("https://"):
                    result.supports_https = True
                break

        # Enumerate supported methods via OPTIONS
        if result.is_alive:
            options_resp = await self.probe(url, method="OPTIONS")
            if options_resp.status_code > 0:
                allow = options_resp.headers.get("allow", "")
                result.supported_methods = [m.strip() for m in allow.split(",") if m.strip()]

        return result

    async def check_alive(self, url: str) -> bool:
        """Quick liveness check with HEAD request."""
        response = await self.probe(url, method="HEAD")
        return response.status_code > 0
