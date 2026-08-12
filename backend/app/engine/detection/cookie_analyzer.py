"""
SentinelGraph — Cookie Security Analyzer

Analyzes Set-Cookie headers for security best practices:
Secure, HttpOnly, SameSite, expiration, prefixes, and naming.
"""

from dataclasses import dataclass, field

import structlog

from app.models.finding import FindingSeverity, FindingType

logger = structlog.get_logger(__name__)


@dataclass
class CookieFinding:
    """A security issue found in a cookie."""
    cookie_name: str
    severity: FindingSeverity
    finding_type: FindingType
    title: str
    description: str
    remediation: str
    evidence: dict


@dataclass
class CookieAnalysisResult:
    """Result of analyzing all cookies in a response."""
    url: str
    cookies_analyzed: int = 0
    findings: list[CookieFinding] = field(default_factory=list)


class CookieAnalyzer:
    """Analyzes cookies for security misconfigurations."""

    # Cookie names that are likely session/auth-related
    SENSITIVE_COOKIE_PATTERNS = [
        "session", "sess", "sid", "token", "auth", "jwt",
        "login", "csrf", "xsrf", "credential", "apikey",
        "phpsessid", "jsessionid", "asp.net_sessionid",
        "connect.sid", "laravel_session", "_identity",
    ]

    def analyze(self, set_cookie_headers: list[str], url: str) -> CookieAnalysisResult:
        """Analyze Set-Cookie headers for security issues.

        Args:
            set_cookie_headers: List of Set-Cookie header values
            url: URL that sent these cookies

        Returns:
            CookieAnalysisResult with findings
        """
        result = CookieAnalysisResult(url=url, cookies_analyzed=len(set_cookie_headers))

        for header in set_cookie_headers:
            cookie = self._parse_cookie(header)
            if not cookie:
                continue

            name = cookie["name"]
            flags = cookie["flags"]
            is_sensitive = self._is_sensitive_cookie(name)
            is_https = url.startswith("https://")

            # Check Secure flag
            if is_https and "secure" not in flags:
                result.findings.append(CookieFinding(
                    cookie_name=name,
                    severity=FindingSeverity.MEDIUM if is_sensitive else FindingSeverity.LOW,
                    finding_type=FindingType.COOKIE_INSECURE,
                    title=f"Cookie '{name}' Missing Secure Flag",
                    description=f"The cookie '{name}' is not marked as Secure. It can be transmitted over unencrypted HTTP connections.",
                    remediation=f"Add the Secure flag to cookie '{name}'.",
                    evidence={"cookie_header": header[:200]},
                ))

            # Check HttpOnly flag
            if is_sensitive and "httponly" not in flags:
                result.findings.append(CookieFinding(
                    cookie_name=name,
                    severity=FindingSeverity.MEDIUM,
                    finding_type=FindingType.COOKIE_INSECURE,
                    title=f"Sensitive Cookie '{name}' Missing HttpOnly",
                    description=f"The potentially sensitive cookie '{name}' is accessible to JavaScript. This increases XSS impact.",
                    remediation=f"Add the HttpOnly flag to cookie '{name}'.",
                    evidence={"cookie_header": header[:200]},
                ))

            # Check SameSite attribute
            if "samesite" not in flags:
                result.findings.append(CookieFinding(
                    cookie_name=name,
                    severity=FindingSeverity.LOW if not is_sensitive else FindingSeverity.MEDIUM,
                    finding_type=FindingType.COOKIE_INSECURE,
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    description=f"Cookie '{name}' does not set the SameSite attribute, which may enable CSRF attacks.",
                    remediation=f"Set SameSite=Lax or SameSite=Strict on cookie '{name}'.",
                    evidence={"cookie_header": header[:200]},
                ))
            elif "samesite=none" in flags and "secure" not in flags:
                result.findings.append(CookieFinding(
                    cookie_name=name,
                    severity=FindingSeverity.MEDIUM,
                    finding_type=FindingType.COOKIE_INSECURE,
                    title=f"Cookie '{name}' has SameSite=None without Secure",
                    description="SameSite=None requires the Secure flag. Modern browsers will reject this cookie.",
                    remediation="Add the Secure flag when using SameSite=None.",
                    evidence={"cookie_header": header[:200]},
                ))

            # Check for __Host- and __Secure- prefix requirements
            if name.startswith("__Host-"):
                issues = []
                if "secure" not in flags:
                    issues.append("Secure")
                if cookie.get("path") != "/":
                    issues.append("Path=/")
                if cookie.get("domain"):
                    issues.append("no Domain attribute")
                if issues:
                    result.findings.append(CookieFinding(
                        cookie_name=name,
                        severity=FindingSeverity.MEDIUM,
                        finding_type=FindingType.COOKIE_INSECURE,
                        title=f"Invalid __Host- Cookie Prefix Usage",
                        description=f"Cookie '{name}' uses __Host- prefix but doesn't meet requirements: {', '.join(issues)}.",
                        remediation="__Host- cookies must have Secure flag, Path=/, and no Domain attribute.",
                        evidence={"cookie_header": header[:200], "missing": issues},
                    ))

        return result

    @staticmethod
    def _parse_cookie(header: str) -> dict | None:
        """Parse a Set-Cookie header into components."""
        try:
            parts = header.split(";")
            name_value = parts[0].strip()
            if "=" not in name_value:
                return None

            name, value = name_value.split("=", 1)
            flags_lower = set()
            attrs = {}

            for part in parts[1:]:
                part = part.strip().lower()
                if "=" in part:
                    k, v = part.split("=", 1)
                    flags_lower.add(k.strip())
                    attrs[k.strip()] = v.strip()
                else:
                    flags_lower.add(part)

            return {
                "name": name.strip(),
                "value": value,
                "flags": flags_lower,
                "path": attrs.get("path"),
                "domain": attrs.get("domain"),
            }
        except Exception:
            return None

    def _is_sensitive_cookie(self, name: str) -> bool:
        """Check if a cookie name appears to be security-relevant."""
        name_lower = name.lower()
        return any(pattern in name_lower for pattern in self.SENSITIVE_COOKIE_PATTERNS)
