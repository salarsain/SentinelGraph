"""
SentinelGraph — Technology Fingerprinting Engine

Identifies technologies, frameworks, CMS platforms, and versions
from HTTP headers, HTML content, JavaScript libraries, and cookies.
"""

import re
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class DetectedTechnology:
    """A detected technology with confidence."""
    name: str
    version: str | None = None
    category: str = "other"  # framework, cms, server, language, js-library, waf, cdn
    confidence: float = 0.5
    evidence: str = ""


# ── Signature Database ───────────────────────────────────────
# Each entry: (pattern, tech_name, category, version_regex_or_None)

HEADER_SIGNATURES: list[tuple[str, str, str, str, str | None]] = [
    # (header_name, value_pattern, tech_name, category, version_regex)
    ("server", "nginx", "Nginx", "server", r"nginx/([\d.]+)"),
    ("server", "apache", "Apache", "server", r"Apache/([\d.]+)"),
    ("server", "microsoft-iis", "IIS", "server", r"Microsoft-IIS/([\d.]+)"),
    ("server", "cloudflare", "Cloudflare", "cdn", None),
    ("server", "gunicorn", "Gunicorn", "server", r"gunicorn/([\d.]+)"),
    ("server", "uvicorn", "Uvicorn", "server", None),
    ("x-powered-by", "php", "PHP", "language", r"PHP/([\d.]+)"),
    ("x-powered-by", "asp.net", "ASP.NET", "framework", None),
    ("x-powered-by", "express", "Express.js", "framework", None),
    ("x-powered-by", "next.js", "Next.js", "framework", None),
    ("x-generator", "wordpress", "WordPress", "cms", r"WordPress ([\d.]+)"),
    ("x-generator", "drupal", "Drupal", "cms", r"Drupal ([\d.]+)"),
    ("x-drupal-cache", "", "Drupal", "cms", None),
    ("x-aspnet-version", "", "ASP.NET", "framework", r"([\d.]+)"),
    ("x-aspnetmvc-version", "", "ASP.NET MVC", "framework", r"([\d.]+)"),
    ("x-shopify-stage", "", "Shopify", "cms", None),
]

COOKIE_SIGNATURES: list[tuple[str, str, str]] = [
    # (cookie_name_pattern, tech_name, category)
    ("phpsessid", "PHP", "language"),
    ("jsessionid", "Java", "language"),
    ("asp.net_sessionid", "ASP.NET", "framework"),
    ("csrftoken", "Django", "framework"),
    ("_rails_session", "Ruby on Rails", "framework"),
    ("laravel_session", "Laravel", "framework"),
    ("ci_session", "CodeIgniter", "framework"),
    ("wordpress_logged_in", "WordPress", "cms"),
    ("wp-settings", "WordPress", "cms"),
    ("joomla_session", "Joomla", "cms"),
]

HTML_SIGNATURES: list[tuple[str, str, str, str | None]] = [
    # (regex_pattern, tech_name, category, version_group)
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', "WordPress", "cms", None),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d.]*)', "Drupal", "cms", None),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "Joomla", "cms", None),
    (r'/wp-content/', "WordPress", "cms", None),
    (r'/wp-includes/', "WordPress", "cms", None),
    (r'wp-json', "WordPress REST API", "cms", None),
    (r'sites/default/files', "Drupal", "cms", None),
    (r'react\.production\.min\.js', "React", "js-library", None),
    (r'react-dom', "React", "js-library", None),
    (r'"react":\s*"([\d.]+)"', "React", "js-library", None),
    (r'__NEXT_DATA__', "Next.js", "framework", None),
    (r'/_next/static', "Next.js", "framework", None),
    (r'ng-version="([\d.]+)"', "Angular", "js-library", None),
    (r'ng-app', "AngularJS", "js-library", None),
    (r'vue\.runtime', "Vue.js", "js-library", None),
    (r'__vue__', "Vue.js", "js-library", None),
    (r'__nuxt', "Nuxt.js", "framework", None),
    (r'jquery[.-]?([\d.]+)?\.min\.js', "jQuery", "js-library", None),
    (r'bootstrap[.-]?([\d.]+)?\.min\.(js|css)', "Bootstrap", "css-framework", None),
    (r'tailwindcss', "Tailwind CSS", "css-framework", None),
    (r'cdn\.shopify\.com', "Shopify", "cms", None),
    (r'static\.squarespace\.com', "Squarespace", "cms", None),
    (r'wix\.com', "Wix", "cms", None),
    (r'<meta\s+name=["\']csrf-token', "Ruby on Rails", "framework", None),
    (r'csrfmiddlewaretoken', "Django", "framework", None),
    (r'__RequestVerificationToken', "ASP.NET", "framework", None),
    (r'laravel', "Laravel", "framework", None),
    (r'swagger-ui', "Swagger", "api-tool", None),
    (r'graphql', "GraphQL", "api-tool", None),
    (r'graphiql', "GraphiQL", "api-tool", None),
]


class TechFingerprinter:
    """Identifies technologies from HTTP response data."""

    def fingerprint(
        self,
        headers: dict[str, str],
        body: str | None = None,
        cookies: list[str] | None = None,
        url: str = "",
    ) -> list[DetectedTechnology]:
        """Run all fingerprinting techniques.

        Args:
            headers: HTTP response headers
            body: HTML body text (optional)
            cookies: List of Set-Cookie header values (optional)
            url: Target URL for context

        Returns:
            List of detected technologies with confidence scores
        """
        detections: dict[str, DetectedTechnology] = {}

        # Header-based detection
        for tech in self._check_headers(headers):
            key = f"{tech.name}:{tech.category}"
            if key not in detections or tech.confidence > detections[key].confidence:
                detections[key] = tech

        # Cookie-based detection
        if cookies:
            for tech in self._check_cookies(cookies):
                key = f"{tech.name}:{tech.category}"
                if key not in detections:
                    detections[key] = tech

        # HTML-based detection
        if body:
            for tech in self._check_html(body):
                key = f"{tech.name}:{tech.category}"
                if key not in detections or tech.confidence > detections[key].confidence:
                    detections[key] = tech

        results = list(detections.values())
        logger.info("fingerprint.complete", url=url, technologies=len(results))
        return results

    def _check_headers(self, headers: dict[str, str]) -> list[DetectedTechnology]:
        """Check response headers against signature database."""
        results = []
        h = {k.lower(): v for k, v in headers.items()}

        for header_name, pattern, tech_name, category, version_regex in HEADER_SIGNATURES:
            value = h.get(header_name, "")
            if pattern and pattern.lower() in value.lower():
                version = None
                if version_regex:
                    match = re.search(version_regex, value, re.IGNORECASE)
                    if match:
                        version = match.group(1)

                results.append(DetectedTechnology(
                    name=tech_name,
                    version=version,
                    category=category,
                    confidence=0.9,
                    evidence=f"Header: {header_name}: {value}",
                ))
            elif not pattern and header_name in h:
                # Header existence check (no pattern needed)
                version = None
                if version_regex:
                    match = re.search(version_regex, h[header_name], re.IGNORECASE)
                    if match:
                        version = match.group(1)
                results.append(DetectedTechnology(
                    name=tech_name,
                    version=version,
                    category=category,
                    confidence=0.85,
                    evidence=f"Header present: {header_name}: {h[header_name]}",
                ))

        return results

    def _check_cookies(self, cookies: list[str]) -> list[DetectedTechnology]:
        """Check cookies against signature database."""
        results = []
        cookie_str = " ".join(cookies).lower()

        for pattern, tech_name, category in COOKIE_SIGNATURES:
            if pattern in cookie_str:
                results.append(DetectedTechnology(
                    name=tech_name,
                    category=category,
                    confidence=0.7,
                    evidence=f"Cookie pattern: {pattern}",
                ))

        return results

    def _check_html(self, body: str) -> list[DetectedTechnology]:
        """Check HTML body against signature database."""
        results = []

        for pattern, tech_name, category, _ in HTML_SIGNATURES:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = None
                if match.lastindex and match.lastindex >= 1:
                    version = match.group(1)

                results.append(DetectedTechnology(
                    name=tech_name,
                    version=version,
                    category=category,
                    confidence=0.75,
                    evidence=f"HTML pattern: {pattern[:60]}",
                ))

        return results
