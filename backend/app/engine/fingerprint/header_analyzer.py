"""
SentinelGraph — Security Header Analyzer

Analyzes HTTP response headers for security misconfigurations.
Checks CSP, HSTS, X-Frame-Options, CORS, and other security headers.
Generates findings with severity, description, and remediation.
"""

from dataclasses import dataclass, field
from enum import Enum

import structlog

from app.models.finding import FindingSeverity, FindingType

logger = structlog.get_logger(__name__)


class HeaderGrade(str, Enum):
    """Assessment grade for a security header."""
    PRESENT_GOOD = "present_good"        # Present and well-configured
    PRESENT_WEAK = "present_weak"        # Present but misconfigured
    MISSING = "missing"                  # Missing (should be present)
    NOT_APPLICABLE = "not_applicable"    # Not relevant for this response


@dataclass
class HeaderFinding:
    """A security header finding."""
    header_name: str
    grade: HeaderGrade
    current_value: str | None
    recommended_value: str
    severity: FindingSeverity
    finding_type: FindingType
    title: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)


@dataclass
class HeaderAnalysisResult:
    """Complete header analysis result."""
    url: str
    findings: list[HeaderFinding] = field(default_factory=list)
    score: float = 0.0  # 0-100 score
    grade: str = "F"    # A+ to F

    @property
    def missing_headers(self) -> list[str]:
        return [f.header_name for f in self.findings if f.grade == HeaderGrade.MISSING]

    @property
    def weak_headers(self) -> list[str]:
        return [f.header_name for f in self.findings if f.grade == HeaderGrade.PRESENT_WEAK]


class SecurityHeaderAnalyzer:
    """Analyzes HTTP security headers and produces actionable findings."""

    def analyze(self, headers: dict[str, str], url: str) -> HeaderAnalysisResult:
        """Analyze all security headers from an HTTP response.

        Args:
            headers: Response headers (case-insensitive dict)
            url: The URL that produced these headers

        Returns:
            HeaderAnalysisResult with findings and overall score
        """
        # Normalize headers to lowercase keys
        h = {k.lower(): v for k, v in headers.items()}
        result = HeaderAnalysisResult(url=url)

        # Run all header checks
        checks = [
            self._check_strict_transport_security(h),
            self._check_content_security_policy(h),
            self._check_x_frame_options(h),
            self._check_x_content_type_options(h),
            self._check_referrer_policy(h),
            self._check_permissions_policy(h),
            self._check_x_xss_protection(h),
            self._check_cors(h),
            self._check_server_header(h),
            self._check_x_powered_by(h),
            self._check_cache_control(h),
        ]

        for finding in checks:
            if finding:
                result.findings.append(finding)

        # Calculate overall score
        result.score = self._calculate_score(result.findings)
        result.grade = self._score_to_grade(result.score)

        return result

    # ── Individual Header Checks ─────────────────────────────

    def _check_strict_transport_security(self, h: dict) -> HeaderFinding | None:
        """Check HSTS (Strict-Transport-Security) header."""
        value = h.get("strict-transport-security")

        if not value:
            return HeaderFinding(
                header_name="Strict-Transport-Security",
                grade=HeaderGrade.MISSING,
                current_value=None,
                recommended_value="max-age=31536000; includeSubDomains; preload",
                severity=FindingSeverity.MEDIUM,
                finding_type=FindingType.MISSING_HEADER,
                title="Missing HSTS Header",
                description=(
                    "The Strict-Transport-Security header is not set. "
                    "This allows attackers to perform SSL stripping attacks "
                    "and intercept sensitive data transmitted over HTTP."
                ),
                remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                references=["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
            )

        # Check for weak configuration
        if "max-age=0" in value:
            return HeaderFinding(
                header_name="Strict-Transport-Security",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value,
                recommended_value="max-age=31536000; includeSubDomains; preload",
                severity=FindingSeverity.MEDIUM,
                finding_type=FindingType.HEADER_MISCONFIG,
                title="HSTS max-age Set to Zero",
                description="HSTS max-age is set to 0, which effectively disables HSTS protection.",
                remediation="Set max-age to at least 31536000 (1 year).",
                references=["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
            )

        # Check if max-age is too short (less than 6 months)
        try:
            max_age_parts = [p for p in value.split(";") if "max-age" in p.lower()]
            if max_age_parts:
                max_age = int(max_age_parts[0].split("=")[1].strip())
                if max_age < 15768000:  # < 6 months
                    return HeaderFinding(
                        header_name="Strict-Transport-Security",
                        grade=HeaderGrade.PRESENT_WEAK,
                        current_value=value,
                        recommended_value="max-age=31536000; includeSubDomains; preload",
                        severity=FindingSeverity.LOW,
                        finding_type=FindingType.HEADER_MISCONFIG,
                        title="HSTS max-age Too Short",
                        description=f"HSTS max-age is {max_age}s ({max_age // 86400} days). Recommended minimum is 6 months.",
                        remediation="Increase max-age to at least 31536000 (1 year).",
                        references=["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
                    )
        except (ValueError, IndexError):
            pass

        return None  # HSTS is properly configured

    def _check_content_security_policy(self, h: dict) -> HeaderFinding | None:
        """Check Content-Security-Policy header."""
        value = h.get("content-security-policy")

        if not value:
            return HeaderFinding(
                header_name="Content-Security-Policy",
                grade=HeaderGrade.MISSING,
                current_value=None,
                recommended_value="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
                severity=FindingSeverity.MEDIUM,
                finding_type=FindingType.MISSING_HEADER,
                title="Missing Content-Security-Policy Header",
                description=(
                    "No CSP header is set. Content-Security-Policy prevents XSS attacks "
                    "by controlling which resources the browser is allowed to load."
                ),
                remediation="Implement a Content-Security-Policy header with restrictive directives.",
                references=["https://owasp.org/www-project-secure-headers/#content-security-policy"],
            )

        # Check for dangerous directives
        dangerous = []
        if "unsafe-inline" in value and "script-src" in value:
            dangerous.append("script-src 'unsafe-inline'")
        if "unsafe-eval" in value:
            dangerous.append("'unsafe-eval'")
        if "data:" in value and "script-src" in value:
            dangerous.append("script-src data:")
        if "*" in value.split("script-src")[-1].split(";")[0] if "script-src" in value else False:
            dangerous.append("script-src with wildcard")

        if dangerous:
            return HeaderFinding(
                header_name="Content-Security-Policy",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value[:200],
                recommended_value="Remove dangerous directives: " + ", ".join(dangerous),
                severity=FindingSeverity.MEDIUM,
                finding_type=FindingType.HEADER_MISCONFIG,
                title="Weak Content-Security-Policy",
                description=f"CSP contains potentially dangerous directives: {', '.join(dangerous)}. These weaken XSS protection.",
                remediation="Remove 'unsafe-inline', 'unsafe-eval', and wildcard sources from script-src.",
                references=["https://owasp.org/www-project-secure-headers/#content-security-policy"],
            )

        return None

    def _check_x_frame_options(self, h: dict) -> HeaderFinding | None:
        """Check X-Frame-Options header."""
        value = h.get("x-frame-options")
        # CSP frame-ancestors supersedes X-Frame-Options
        csp = h.get("content-security-policy", "")
        if "frame-ancestors" in csp:
            return None

        if not value:
            return HeaderFinding(
                header_name="X-Frame-Options",
                grade=HeaderGrade.MISSING,
                current_value=None,
                recommended_value="DENY",
                severity=FindingSeverity.MEDIUM,
                finding_type=FindingType.MISSING_HEADER,
                title="Missing X-Frame-Options Header",
                description="X-Frame-Options is not set, making the site vulnerable to clickjacking attacks.",
                remediation="Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
                references=["https://owasp.org/www-project-secure-headers/#x-frame-options"],
            )

        if value.upper() not in ("DENY", "SAMEORIGIN"):
            return HeaderFinding(
                header_name="X-Frame-Options",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value,
                recommended_value="DENY",
                severity=FindingSeverity.LOW,
                finding_type=FindingType.HEADER_MISCONFIG,
                title="Invalid X-Frame-Options Value",
                description=f"X-Frame-Options is set to '{value}', which is not a standard value.",
                remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                references=["https://owasp.org/www-project-secure-headers/#x-frame-options"],
            )

        return None

    def _check_x_content_type_options(self, h: dict) -> HeaderFinding | None:
        """Check X-Content-Type-Options header."""
        value = h.get("x-content-type-options")

        if not value:
            return HeaderFinding(
                header_name="X-Content-Type-Options",
                grade=HeaderGrade.MISSING,
                current_value=None,
                recommended_value="nosniff",
                severity=FindingSeverity.LOW,
                finding_type=FindingType.MISSING_HEADER,
                title="Missing X-Content-Type-Options Header",
                description="X-Content-Type-Options is not set. Browsers may MIME-sniff the Content-Type, enabling content-type confusion attacks.",
                remediation="Add header: X-Content-Type-Options: nosniff",
                references=["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
            )

        return None

    def _check_referrer_policy(self, h: dict) -> HeaderFinding | None:
        """Check Referrer-Policy header."""
        value = h.get("referrer-policy")

        if not value:
            return HeaderFinding(
                header_name="Referrer-Policy",
                grade=HeaderGrade.MISSING,
                current_value=None,
                recommended_value="strict-origin-when-cross-origin",
                severity=FindingSeverity.LOW,
                finding_type=FindingType.MISSING_HEADER,
                title="Missing Referrer-Policy Header",
                description="No Referrer-Policy set. The full URL including query parameters may be leaked to third-party sites.",
                remediation="Add header: Referrer-Policy: strict-origin-when-cross-origin",
                references=["https://owasp.org/www-project-secure-headers/#referrer-policy"],
            )

        # Check for unsafe values
        unsafe_values = {"unsafe-url", "no-referrer-when-downgrade"}
        if value.lower() in unsafe_values:
            return HeaderFinding(
                header_name="Referrer-Policy",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value,
                recommended_value="strict-origin-when-cross-origin",
                severity=FindingSeverity.LOW,
                finding_type=FindingType.HEADER_MISCONFIG,
                title="Weak Referrer-Policy",
                description=f"Referrer-Policy is set to '{value}', which may leak sensitive URL data.",
                remediation="Use strict-origin-when-cross-origin or no-referrer.",
                references=["https://owasp.org/www-project-secure-headers/#referrer-policy"],
            )

        return None

    def _check_permissions_policy(self, h: dict) -> HeaderFinding | None:
        """Check Permissions-Policy (formerly Feature-Policy) header."""
        value = h.get("permissions-policy") or h.get("feature-policy")

        if not value:
            return HeaderFinding(
                header_name="Permissions-Policy",
                grade=HeaderGrade.MISSING,
                current_value=None,
                recommended_value="camera=(), microphone=(), geolocation=(), payment=()",
                severity=FindingSeverity.INFO,
                finding_type=FindingType.MISSING_HEADER,
                title="Missing Permissions-Policy Header",
                description="No Permissions-Policy set. The browser may grant access to sensitive APIs like camera, microphone, and geolocation.",
                remediation="Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
            )

        return None

    def _check_x_xss_protection(self, h: dict) -> HeaderFinding | None:
        """Check X-XSS-Protection header (legacy but informational)."""
        value = h.get("x-xss-protection")

        # X-XSS-Protection is deprecated; CSP is preferred
        # Reporting only if it's set to a dangerous value
        if value and value.strip() == "0":
            return HeaderFinding(
                header_name="X-XSS-Protection",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value,
                recommended_value="Remove this header; rely on CSP instead",
                severity=FindingSeverity.INFO,
                finding_type=FindingType.HEADER_MISCONFIG,
                title="X-XSS-Protection Explicitly Disabled",
                description="X-XSS-Protection is set to 0, explicitly disabling the browser's XSS filter.",
                remediation="Remove the header and implement Content-Security-Policy instead.",
                references=["https://owasp.org/www-project-secure-headers/#x-xss-protection"],
            )

        return None

    def _check_cors(self, h: dict) -> HeaderFinding | None:
        """Check CORS (Access-Control-Allow-Origin) configuration."""
        value = h.get("access-control-allow-origin")

        if value == "*":
            creds = h.get("access-control-allow-credentials", "").lower()
            severity = FindingSeverity.HIGH if creds == "true" else FindingSeverity.MEDIUM
            return HeaderFinding(
                header_name="Access-Control-Allow-Origin",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value,
                recommended_value="Restrict to specific trusted origins",
                severity=severity,
                finding_type=FindingType.CORS_MISCONFIG,
                title="Overly Permissive CORS Policy",
                description=(
                    "Access-Control-Allow-Origin is set to '*' (wildcard), "
                    "allowing any website to make cross-origin requests. "
                    + ("Combined with Access-Control-Allow-Credentials: true, this is especially dangerous." if creds == "true" else "")
                ),
                remediation="Restrict CORS to specific trusted origins instead of wildcard.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"],
            )

        return None

    def _check_server_header(self, h: dict) -> HeaderFinding | None:
        """Check Server header for version disclosure."""
        value = h.get("server")

        if value and any(char.isdigit() for char in value):
            return HeaderFinding(
                header_name="Server",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value,
                recommended_value="Remove or obfuscate the Server header",
                severity=FindingSeverity.LOW,
                finding_type=FindingType.VERSION_DISCLOSURE,
                title="Server Version Disclosure",
                description=f"The Server header discloses version information: '{value}'. This helps attackers identify known vulnerabilities.",
                remediation="Remove or obfuscate the Server header to prevent version fingerprinting.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
            )

        return None

    def _check_x_powered_by(self, h: dict) -> HeaderFinding | None:
        """Check X-Powered-By header for technology disclosure."""
        value = h.get("x-powered-by")

        if value:
            return HeaderFinding(
                header_name="X-Powered-By",
                grade=HeaderGrade.PRESENT_WEAK,
                current_value=value,
                recommended_value="Remove this header entirely",
                severity=FindingSeverity.LOW,
                finding_type=FindingType.INFO_DISCLOSURE,
                title="Technology Disclosure via X-Powered-By",
                description=f"X-Powered-By header reveals: '{value}'. This discloses the server-side technology stack.",
                remediation="Remove the X-Powered-By header in your server configuration.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"],
            )

        return None

    def _check_cache_control(self, h: dict) -> HeaderFinding | None:
        """Check Cache-Control for sensitive pages."""
        value = h.get("cache-control", "")

        # Only flag if the page seems sensitive (has auth-related content)
        # This is a heuristic — the page content check happens elsewhere
        if not value or ("no-store" not in value.lower() and "no-cache" not in value.lower()):
            return HeaderFinding(
                header_name="Cache-Control",
                grade=HeaderGrade.PRESENT_WEAK if value else HeaderGrade.MISSING,
                current_value=value or None,
                recommended_value="no-store, no-cache, must-revalidate, private",
                severity=FindingSeverity.INFO,
                finding_type=FindingType.HEADER_MISCONFIG,
                title="Missing Cache-Control for Sensitive Data",
                description="Cache-Control does not prevent caching. Sensitive data may be cached by browsers or proxies.",
                remediation="For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate, private",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses"],
            )

        return None

    # ── Scoring ──────────────────────────────────────────────
    @staticmethod
    def _calculate_score(findings: list[HeaderFinding]) -> float:
        """Calculate overall security header score (0-100)."""
        total_points = 100.0
        deductions = {
            FindingSeverity.CRITICAL: 25,
            FindingSeverity.HIGH: 20,
            FindingSeverity.MEDIUM: 15,
            FindingSeverity.LOW: 8,
            FindingSeverity.INFO: 3,
        }

        for finding in findings:
            if finding.grade in (HeaderGrade.MISSING, HeaderGrade.PRESENT_WEAK):
                total_points -= deductions.get(finding.severity, 5)

        return max(0.0, total_points)

    @staticmethod
    def _score_to_grade(score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
