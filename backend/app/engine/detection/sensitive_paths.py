"""
SentinelGraph — Sensitive Path Scanner

Probes for commonly exposed sensitive files and paths:
backup files, admin panels, debug endpoints, config files, VCS artifacts.
All requests go through the Scope Enforcement Gateway.
"""

import asyncio
from dataclasses import dataclass, field

import structlog

from app.engine.http.prober import HTTPProber, HTTPResponse
from app.models.finding import FindingSeverity, FindingType
from app.models.scope import AuthorizedScope

logger = structlog.get_logger(__name__)


@dataclass
class SensitivePathHit:
    """A sensitive path that returned a notable response."""
    path: str
    url: str
    status_code: int
    content_length: int
    severity: FindingSeverity
    finding_type: FindingType
    title: str
    description: str
    category: str


# ── Path Database ────────────────────────────────────────────
# (path, title, description, severity, finding_type, category)
SENSITIVE_PATHS: list[tuple[str, str, str, FindingSeverity, FindingType, str]] = [
    # Version Control
    ("/.git/HEAD", "Git Repository Exposed", "The .git directory is accessible, potentially exposing source code and commit history.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "vcs"),
    ("/.git/config", "Git Config Exposed", "Git configuration file accessible, may reveal remote URLs and credentials.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "vcs"),
    ("/.svn/entries", "SVN Repository Exposed", "SVN metadata accessible, exposing repository structure.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "vcs"),
    ("/.hg/hgrc", "Mercurial Repository Exposed", "Mercurial configuration accessible.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "vcs"),

    # Environment & Config
    ("/.env", "Environment File Exposed", "The .env file is accessible and may contain secrets, API keys, and database credentials.", FindingSeverity.CRITICAL, FindingType.SENSITIVE_FILE, "config"),
    ("/.env.production", "Production Env File Exposed", "Production environment file accessible.", FindingSeverity.CRITICAL, FindingType.SENSITIVE_FILE, "config"),
    ("/.env.local", "Local Env File Exposed", "Local environment file accessible.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "config"),
    ("/config.php", "PHP Config Exposed", "PHP configuration file accessible.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "config"),
    ("/wp-config.php", "WordPress Config Exposed", "WordPress configuration file may contain database credentials.", FindingSeverity.CRITICAL, FindingType.SENSITIVE_FILE, "config"),
    ("/config/database.yml", "Rails Database Config", "Rails database configuration accessible.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "config"),
    ("/application.yml", "Spring Boot Config", "Spring Boot configuration file accessible.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "config"),

    # Backup Files
    ("/backup.sql", "Database Backup Exposed", "SQL backup file accessible.", FindingSeverity.CRITICAL, FindingType.SENSITIVE_FILE, "backup"),
    ("/backup.zip", "Backup Archive Exposed", "Backup archive accessible.", FindingSeverity.HIGH, FindingType.SENSITIVE_FILE, "backup"),
    ("/db.sql", "Database Dump Exposed", "Database dump file accessible.", FindingSeverity.CRITICAL, FindingType.SENSITIVE_FILE, "backup"),
    ("/dump.sql", "Database Dump Exposed", "Database dump file accessible.", FindingSeverity.CRITICAL, FindingType.SENSITIVE_FILE, "backup"),

    # Admin & Debug
    ("/admin", "Admin Panel Found", "Admin panel endpoint accessible.", FindingSeverity.MEDIUM, FindingType.INFO_DISCLOSURE, "admin"),
    ("/admin/login", "Admin Login Found", "Admin login page accessible.", FindingSeverity.LOW, FindingType.INFO_DISCLOSURE, "admin"),
    ("/administrator", "Administrator Panel Found", "Administrator panel accessible.", FindingSeverity.MEDIUM, FindingType.INFO_DISCLOSURE, "admin"),
    ("/debug", "Debug Endpoint Found", "Debug endpoint accessible.", FindingSeverity.MEDIUM, FindingType.DEBUG_ENABLED, "debug"),
    ("/__debug__/", "Django Debug Toolbar", "Django debug toolbar accessible.", FindingSeverity.HIGH, FindingType.DEBUG_ENABLED, "debug"),
    ("/phpinfo.php", "PHP Info Page", "phpinfo() page accessible, exposing full server configuration.", FindingSeverity.MEDIUM, FindingType.INFO_DISCLOSURE, "debug"),
    ("/server-status", "Apache Status", "Apache server-status page accessible.", FindingSeverity.MEDIUM, FindingType.INFO_DISCLOSURE, "debug"),
    ("/server-info", "Apache Info", "Apache server-info page accessible.", FindingSeverity.MEDIUM, FindingType.INFO_DISCLOSURE, "debug"),

    # API Documentation
    ("/swagger.json", "Swagger Spec Exposed", "Swagger/OpenAPI specification accessible.", FindingSeverity.LOW, FindingType.INFO_DISCLOSURE, "api"),
    ("/openapi.json", "OpenAPI Spec Exposed", "OpenAPI specification accessible.", FindingSeverity.LOW, FindingType.INFO_DISCLOSURE, "api"),
    ("/graphql", "GraphQL Endpoint Found", "GraphQL endpoint accessible.", FindingSeverity.LOW, FindingType.INFO_DISCLOSURE, "api"),
    ("/api/docs", "API Docs Exposed", "API documentation endpoint accessible.", FindingSeverity.INFO, FindingType.INFO_DISCLOSURE, "api"),

    # Infrastructure
    ("/robots.txt", "Robots.txt Found", "Robots.txt found — may reveal hidden paths.", FindingSeverity.INFO, FindingType.INFO_DISCLOSURE, "infra"),
    ("/sitemap.xml", "Sitemap Found", "Sitemap.xml found.", FindingSeverity.INFO, FindingType.INFO_DISCLOSURE, "infra"),
    ("/.well-known/security.txt", "Security Policy Found", "Security contact policy found.", FindingSeverity.INFO, FindingType.INFO_DISCLOSURE, "infra"),
    ("/crossdomain.xml", "Flash Crossdomain Policy", "Flash crossdomain.xml found — may allow cross-origin access.", FindingSeverity.LOW, FindingType.MISCONFIGURATION, "infra"),
]


class SensitivePathScanner:
    """Scans for commonly exposed sensitive files and paths."""

    def __init__(
        self,
        scope: AuthorizedScope,
        max_concurrent: int = 10,
    ):
        self.prober = HTTPProber(scope=scope)
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan(self, base_url: str) -> list[SensitivePathHit]:
        """Scan for all sensitive paths at the given base URL.

        Args:
            base_url: Target base URL (e.g., "https://example.com")

        Returns:
            List of accessible sensitive paths
        """
        logger.info("sensitive_scan.started", base_url=base_url, paths=len(SENSITIVE_PATHS))

        base = base_url.rstrip("/")
        tasks = [self._check_path(base, entry) for entry in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        hits = [r for r in results if isinstance(r, SensitivePathHit)]

        logger.info("sensitive_scan.complete", base_url=base_url, hits=len(hits))
        return hits

    async def _check_path(
        self,
        base_url: str,
        entry: tuple[str, str, str, FindingSeverity, FindingType, str],
    ) -> SensitivePathHit | None:
        """Check a single sensitive path."""
        path, title, desc, severity, ftype, category = entry
        url = f"{base_url}{path}"

        async with self.semaphore:
            try:
                response = await self.prober.probe(url)

                # Only flag if we get a meaningful response
                if response.status_code == 200 and response.content_length > 0:
                    # Filter false positives: custom 404 pages, generic error pages
                    if self._is_likely_real(response, path):
                        return SensitivePathHit(
                            path=path,
                            url=url,
                            status_code=response.status_code,
                            content_length=response.content_length,
                            severity=severity,
                            finding_type=ftype,
                            title=title,
                            description=desc,
                            category=category,
                        )

                # 403 on sensitive paths is still interesting
                if response.status_code == 403 and category in ("vcs", "config", "backup"):
                    return SensitivePathHit(
                        path=path,
                        url=url,
                        status_code=403,
                        content_length=response.content_length,
                        severity=FindingSeverity.LOW,
                        finding_type=FindingType.INFO_DISCLOSURE,
                        title=f"{title} (403 Forbidden)",
                        description=f"{desc} Access is denied, but the resource exists.",
                        category=category,
                    )

            except Exception as e:
                logger.debug("sensitive_scan.path_error", path=path, error=str(e))

        return None

    @staticmethod
    def _is_likely_real(response: HTTPResponse, path: str) -> bool:
        """Heuristic: determine if a 200 response is a real file or a custom 404."""
        body = response.body_text or ""

        # If it's very small, it might be an empty response or error
        if response.content_length < 10:
            return False

        # Check for common 404 page indicators
        not_found_indicators = [
            "page not found", "404", "not found",
            "page does not exist", "the requested url was not found",
        ]
        body_lower = body[:2000].lower()
        if any(ind in body_lower for ind in not_found_indicators):
            return False

        # For specific file types, verify content
        if path.endswith(".env") and ("=" in body[:200]):
            return True
        if path == "/.git/HEAD" and body.strip().startswith("ref:"):
            return True
        if path.endswith(".sql") and any(kw in body_lower[:500] for kw in ("create table", "insert into", "drop")):
            return True
        if path.endswith(".json") and body.strip().startswith(("{", "[")):
            return True

        return True  # Default: trust the 200
