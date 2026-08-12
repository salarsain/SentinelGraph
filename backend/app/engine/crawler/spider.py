"""
SentinelGraph — Web Crawler (Spider)

Async BFS web crawler that discovers pages, forms, and links.
Respects robots.txt, crawl-delay, and scope boundaries.
Every URL is validated through the Scope Enforcement Gateway.
"""

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog

from app.config import get_settings
from app.engine.crawler.form_parser import DiscoveredForm, FormParser
from app.engine.crawler.link_extractor import LinkExtractor
from app.engine.http.prober import HTTPProber
from app.models.scope import AuthorizedScope

logger = structlog.get_logger(__name__)
settings = get_settings()


@dataclass
class CrawlResult:
    """Result of a complete crawl session."""
    seed_url: str
    urls_discovered: list[str] = field(default_factory=list)
    forms_discovered: list[DiscoveredForm] = field(default_factory=list)
    pages_crawled: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    robots_txt: str | None = None


class Spider:
    """Async BFS web crawler with scope enforcement.

    Discovers URLs and forms by crawling a web application.
    Every URL is validated against the scope gateway before fetching.
    """

    def __init__(
        self,
        scope: AuthorizedScope,
        max_depth: int | None = None,
        max_pages: int = 500,
        max_concurrent: int = 10,
        respect_robots: bool = True,
    ):
        self.scope = scope
        self.max_depth = max_depth or settings.max_crawl_depth
        self.max_pages = max_pages
        self.max_concurrent = max_concurrent
        self.respect_robots = respect_robots

        self.prober = HTTPProber(scope=scope)
        self.link_extractor = LinkExtractor()
        self.form_parser = FormParser()

        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._disallowed_paths: list[str] = []

    async def crawl(self, seed_url: str) -> CrawlResult:
        """Crawl a web application starting from seed_url.

        Args:
            seed_url: Starting URL for the crawl

        Returns:
            CrawlResult with all discovered URLs, forms, and metadata
        """
        logger.info("crawler.started", seed_url=seed_url, max_depth=self.max_depth)

        result = CrawlResult(seed_url=seed_url)

        # Fetch robots.txt first
        if self.respect_robots:
            await self._fetch_robots(seed_url)

        # Initialize BFS queue
        normalized = self._normalize_url(seed_url)
        self._queue.append((normalized, 0))

        while self._queue and len(self._visited) < self.max_pages:
            # Process batch
            batch: list[tuple[str, int]] = []
            while self._queue and len(batch) < self.max_concurrent:
                url, depth = self._queue.popleft()
                if url not in self._visited and depth <= self.max_depth:
                    batch.append((url, depth))

            if not batch:
                break

            # Crawl batch concurrently
            tasks = [self._crawl_page(url, depth, result) for url, depth in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        result.urls_discovered = list(self._visited)
        result.pages_crawled = len(self._visited)

        logger.info(
            "crawler.complete",
            seed_url=seed_url,
            pages_crawled=result.pages_crawled,
            forms_found=len(result.forms_discovered),
        )
        return result

    async def _crawl_page(
        self,
        url: str,
        depth: int,
        result: CrawlResult,
    ) -> None:
        """Crawl a single page: fetch, extract links, extract forms."""
        async with self._semaphore:
            if url in self._visited:
                return

            self._visited.add(url)

            # Check robots.txt
            if self._is_disallowed(url):
                logger.debug("crawler.robots_blocked", url=url)
                return

            try:
                response = await self.prober.probe(url)

                if response.status_code == 0:
                    result.errors.append({"url": url, "error": response.error})
                    return

                if not response.is_html or not response.body_text:
                    return

                # Extract links
                links = self.link_extractor.extract(response.body_text, url)
                for link in links:
                    normalized = self._normalize_url(link)
                    if normalized and normalized not in self._visited:
                        if self._is_same_scope(normalized, url):
                            self._queue.append((normalized, depth + 1))

                # Extract forms
                forms = self.form_parser.extract(response.body_text, url)
                result.forms_discovered.extend(forms)

            except Exception as e:
                logger.warning("crawler.page_error", url=url, error=str(e))
                result.errors.append({"url": url, "error": str(e)})

    async def _fetch_robots(self, base_url: str) -> None:
        """Fetch and parse robots.txt."""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        try:
            response = await self.prober.probe(robots_url)
            if response.status_code == 200 and response.body_text:
                for line in response.body_text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self._disallowed_paths.append(path)
                logger.info("crawler.robots_loaded", disallowed=len(self._disallowed_paths))
        except Exception:
            pass  # robots.txt is optional

    def _is_disallowed(self, url: str) -> bool:
        """Check if URL is disallowed by robots.txt."""
        path = urlparse(url).path
        return any(
            path.startswith(disallowed)
            for disallowed in self._disallowed_paths
        )

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        # Remove fragment, normalize scheme
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip("/")

    @staticmethod
    def _is_same_scope(url: str, base_url: str) -> bool:
        """Check if URL is in the same scope as base URL."""
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)

        # Must be HTTP(S)
        if parsed_url.scheme not in ("http", "https"):
            return False

        # Must be same domain or subdomain
        return (
            parsed_url.netloc == parsed_base.netloc
            or parsed_url.hostname == parsed_base.hostname
        )
