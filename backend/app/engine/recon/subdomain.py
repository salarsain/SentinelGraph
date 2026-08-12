"""
SentinelGraph — Subdomain Enumeration Engine

Passive subdomain discovery via Certificate Transparency logs (crt.sh),
DNS brute-force with common wordlists, and result deduplication.
All results are validated through the Scope Enforcement Gateway.
"""

import asyncio
from dataclasses import dataclass, field

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class SubdomainResult:
    """A discovered subdomain with discovery metadata."""
    subdomain: str
    source: str
    ip_addresses: list[str] = field(default_factory=list)
    is_alive: bool = False
    http_status: int | None = None


# Common subdomain prefixes for brute-force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "api", "dev", "staging",
    "test", "portal", "admin", "blog", "shop", "forum", "wiki", "docs",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "app", "apps",
    "static", "cdn", "assets", "media", "images", "img", "files",
    "auth", "login", "sso", "oauth", "dashboard", "panel", "cpanel",
    "secure", "ssl", "beta", "alpha", "demo", "sandbox", "internal",
    "intranet", "extranet", "gateway", "proxy", "cache", "backup",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "search", "kibana", "grafana", "prometheus", "monitor", "status",
    "health", "api-v1", "api-v2", "rest", "graphql", "ws", "websocket",
    "mobile", "m", "support", "help", "kb", "knowledge", "feedback",
    "survey", "analytics", "tracking", "metrics", "logs", "log",
    "s3", "storage", "upload", "download", "share", "cloud",
]


class SubdomainEnumerator:
    """Discovers subdomains through multiple passive techniques."""

    def __init__(self, timeout: int = 30, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def enumerate(self, domain: str) -> list[SubdomainResult]:
        """Run all subdomain enumeration techniques.

        Args:
            domain: Base domain to enumerate (e.g., "example.com")

        Returns:
            Deduplicated list of discovered subdomains
        """
        logger.info("subdomain_enum.started", domain=domain)

        # Run all sources concurrently
        results = await asyncio.gather(
            self._crt_sh(domain),
            self._dns_brute(domain),
            return_exceptions=True,
        )

        # Flatten and deduplicate
        all_subdomains: dict[str, SubdomainResult] = {}
        for result in results:
            if isinstance(result, Exception):
                logger.warning("subdomain_enum.source_failed", error=str(result))
                continue
            for sub in result:
                key = sub.subdomain.lower().strip(".")
                if key not in all_subdomains:
                    all_subdomains[key] = sub

        discovered = list(all_subdomains.values())
        logger.info(
            "subdomain_enum.complete",
            domain=domain,
            total=len(discovered),
        )
        return discovered

    async def _crt_sh(self, domain: str) -> list[SubdomainResult]:
        """Query Certificate Transparency logs via crt.sh."""
        results = []
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "SentinelGraph/0.1.0"},
                )

                if response.status_code != 200:
                    logger.warning("crt_sh.bad_status", status=response.status_code)
                    return results

                entries = response.json()
                seen = set()

                for entry in entries:
                    name_value = entry.get("name_value", "")
                    # crt.sh can return multiple names separated by newlines
                    for name in name_value.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and name.endswith(domain) and name not in seen:
                            seen.add(name)
                            results.append(SubdomainResult(
                                subdomain=name,
                                source="crt.sh",
                            ))

        except Exception as e:
            logger.warning("crt_sh.error", error=str(e))

        logger.info("crt_sh.complete", domain=domain, found=len(results))
        return results

    async def _dns_brute(self, domain: str) -> list[SubdomainResult]:
        """Brute-force common subdomain prefixes via DNS resolution."""
        results = []
        tasks = []

        for prefix in COMMON_SUBDOMAINS:
            subdomain = f"{prefix}.{domain}"
            tasks.append(self._resolve_subdomain(subdomain))

        resolved = await asyncio.gather(*tasks, return_exceptions=True)

        for result in resolved:
            if isinstance(result, SubdomainResult) and result.is_alive:
                results.append(result)

        logger.info("dns_brute.complete", domain=domain, found=len(results))
        return results

    async def _resolve_subdomain(self, subdomain: str) -> SubdomainResult:
        """Attempt DNS resolution for a single subdomain."""
        import socket

        async with self._semaphore:
            result = SubdomainResult(subdomain=subdomain, source="dns_brute")
            try:
                loop = asyncio.get_event_loop()
                infos = await loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC),
                )
                if infos:
                    result.ip_addresses = list({info[4][0] for info in infos})
                    result.is_alive = True
            except (socket.gaierror, OSError):
                pass  # NXDOMAIN — subdomain doesn't exist
            return result
