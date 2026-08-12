"""
SentinelGraph — Link Extractor

Extracts and resolves links from HTML content.
"""

from urllib.parse import urljoin, urlparse

import structlog
from bs4 import BeautifulSoup

logger = structlog.get_logger(__name__)


class LinkExtractor:
    """Extracts links from HTML content."""

    # Elements and their URL-bearing attributes
    LINK_ATTRIBUTES = {
        "a": "href",
        "link": "href",
        "script": "src",
        "img": "src",
        "iframe": "src",
        "form": "action",
        "area": "href",
        "base": "href",
        "embed": "src",
        "object": "data",
        "source": "src",
        "video": "src",
        "audio": "src",
    }

    # File extensions to skip (non-crawlable)
    SKIP_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".tar", ".gz", ".7z",
        ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".flv", ".wmv",
        ".woff", ".woff2", ".ttf", ".eot",
        ".css",  # We may want CSS for import analysis later
    }

    def extract(self, html: str, base_url: str) -> list[str]:
        """Extract all unique, resolved URLs from HTML.

        Args:
            html: HTML content
            base_url: Base URL for resolving relative links

        Returns:
            List of unique absolute URLs
        """
        urls: set[str] = set()

        try:
            soup = BeautifulSoup(html, "lxml")

            # Check for <base> tag
            base_tag = soup.find("base", href=True)
            if base_tag:
                base_url = urljoin(base_url, base_tag["href"])

            # Extract links from known elements
            for tag_name, attr_name in self.LINK_ATTRIBUTES.items():
                for tag in soup.find_all(tag_name, **{attr_name: True}):
                    href = tag.get(attr_name, "").strip()
                    if href:
                        resolved = self._resolve_url(href, base_url)
                        if resolved:
                            urls.add(resolved)

            # Extract URLs from meta refresh
            for meta in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
                content = meta.get("content", "")
                if "url=" in content.lower():
                    url_part = content.split("url=", 1)[-1].strip().strip("'\"")
                    resolved = self._resolve_url(url_part, base_url)
                    if resolved:
                        urls.add(resolved)

        except Exception as e:
            logger.warning("link_extractor.error", error=str(e))

        return list(urls)

    def extract_js_urls(self, html: str, base_url: str) -> list[str]:
        """Extract JavaScript file URLs for further analysis."""
        js_urls: set[str] = set()
        try:
            soup = BeautifulSoup(html, "lxml")
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                resolved = self._resolve_url(src, base_url)
                if resolved and resolved.endswith(".js"):
                    js_urls.add(resolved)
        except Exception:
            pass
        return list(js_urls)

    def _resolve_url(self, href: str, base_url: str) -> str | None:
        """Resolve a relative URL to absolute and validate it."""
        # Skip non-HTTP schemes
        if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "about:")):
            return None

        try:
            resolved = urljoin(base_url, href)
            parsed = urlparse(resolved)

            # Must be HTTP(S)
            if parsed.scheme not in ("http", "https"):
                return None

            # Skip binary/non-crawlable extensions
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in self.SKIP_EXTENSIONS):
                return None

            # Remove fragment
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            + (f"?{parsed.query}" if parsed.query else "")

        except Exception:
            return None
