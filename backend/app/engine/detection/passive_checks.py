"""
SentinelGraph — Passive Security Checks

Purely passive analysis of HTTP responses — no additional requests sent.
Detects information disclosure, sensitive files, misconfigurations,
and security weaknesses from existing response data.
"""

import re
from dataclasses import dataclass, field

import structlog

from app.engine.http.prober import HTTPResponse
from app.models.finding import FindingSeverity, FindingType

logger = structlog.get_logger(__name__)


@dataclass
class PassiveFinding:
    """A finding from passive analysis."""
    finding_type: FindingType
    severity: FindingSeverity
    title: str
    description: str
    url: str
    evidence: dict
    remediation: str
    confidence: float = 0.8
    cvss_vector: str | None = None
    references: list[str] = field(default_factory=list)


class PassiveChecks:
    """Run passive security checks against crawled responses."""

    def analyze(self, response: HTTPResponse) -> list[PassiveFinding]:
        """Run all passive checks against a single HTTP response."""
        findings: list[PassiveFinding] = []

        if not response.body_text:
            return findings

        checks = [
            self._check_error_disclosure,
            self._check_email_disclosure,
            self._check_internal_ip_disclosure,
            self._check_debug_mode,
            self._check_directory_listing,
            self._check_source_code_comments,
            self._check_sensitive_data_exposure,
            self._check_mixed_content,
            self._check_autocomplete_password,
        ]

        for check in checks:
            try:
                result = check(response)
                if result:
                    findings.extend(result if isinstance(result, list) else [result])
            except Exception as e:
                logger.debug("passive_check.error", check=check.__name__, error=str(e))

        return findings

    def _check_error_disclosure(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect stack traces and error messages that leak information."""
        findings = []
        body = resp.body_text or ""

        error_patterns = [
            (r"Traceback \(most recent call last\)", "Python stack trace", FindingSeverity.MEDIUM),
            (r"at\s+[\w.]+\([\w]+\.java:\d+\)", "Java stack trace", FindingSeverity.MEDIUM),
            (r"Fatal error:.*in\s+/\S+\.php\s+on line\s+\d+", "PHP fatal error", FindingSeverity.HIGH),
            (r"Warning:.*in\s+/\S+\.php\s+on line\s+\d+", "PHP warning with path", FindingSeverity.MEDIUM),
            (r"Microsoft OLE DB Provider for", "ASP/OLEDB error", FindingSeverity.MEDIUM),
            (r"mysql_fetch_array\(\)", "MySQL error disclosure", FindingSeverity.MEDIUM),
            (r"pg_query\(\):", "PostgreSQL error disclosure", FindingSeverity.MEDIUM),
            (r"ORA-\d{5}", "Oracle error disclosure", FindingSeverity.MEDIUM),
            (r"SQLSTATE\[\w+\]", "SQL error disclosure", FindingSeverity.MEDIUM),
            (r"Unhandled Exception", ".NET unhandled exception", FindingSeverity.MEDIUM),
            (r"<b>Notice</b>:.*in\s+<b>/", "PHP notice with path", FindingSeverity.LOW),
        ]

        for pattern, name, severity in error_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                findings.append(PassiveFinding(
                    finding_type=FindingType.INFO_DISCLOSURE,
                    severity=severity,
                    title=f"Error Information Disclosure: {name}",
                    description=f"The response contains a {name} that reveals internal implementation details.",
                    url=resp.url,
                    evidence={"pattern": pattern, "match": match.group(0)[:200]},
                    remediation="Configure custom error pages. Never display raw stack traces or error messages to users in production.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/"],
                ))

        return findings

    def _check_email_disclosure(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect email addresses in responses (potential info disclosure)."""
        body = resp.body_text or ""
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body))

        # Filter common false positives
        emails = {e for e in emails if not e.endswith(('.png', '.jpg', '.gif', '.css', '.js', '.svg'))}

        if len(emails) > 3:
            return [PassiveFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=FindingSeverity.INFO,
                title="Email Address Disclosure",
                description=f"Found {len(emails)} email addresses in the response. These could be used for social engineering.",
                url=resp.url,
                evidence={"emails_found": list(emails)[:10]},
                remediation="Review exposed email addresses. Consider using contact forms instead.",
            )]
        return []

    def _check_internal_ip_disclosure(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect internal/private IP addresses leaked in responses."""
        body = resp.body_text or ""
        headers_str = str(resp.headers)

        combined = body + headers_str
        ip_pattern = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'

        ips = set(re.findall(ip_pattern, combined))
        if ips:
            return [PassiveFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=FindingSeverity.LOW,
                title="Internal IP Address Disclosure",
                description=f"Internal/private IP addresses found in the response: {', '.join(str(ip) for ip in list(ips)[:5])}",
                url=resp.url,
                evidence={"internal_ips": list(str(ip) for ip in ips)[:5]},
                remediation="Remove internal IP addresses from responses, headers, and error messages.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"],
            )]
        return []

    def _check_debug_mode(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect debug mode indicators."""
        body = resp.body_text or ""

        debug_indicators = [
            (r"Django Debug", "Django debug mode"),
            (r"Werkzeug Debugger", "Werkzeug/Flask debug mode"),
            (r"DJANGO_SETTINGS_MODULE", "Django settings exposure"),
            (r"X-Debug-Token", "Symfony debug toolbar"),
            (r"_debugbar", "Laravel debug bar"),
            (r"phpinfo\(\)", "PHP info page"),
            (r"<title>phpinfo\(\)</title>", "PHP info page"),
        ]

        for pattern, name in debug_indicators:
            if re.search(pattern, body, re.IGNORECASE):
                return [PassiveFinding(
                    finding_type=FindingType.DEBUG_ENABLED,
                    severity=FindingSeverity.HIGH,
                    title=f"Debug Mode Enabled: {name}",
                    description=f"Detected {name}. Debug mode exposes sensitive configuration and may allow code execution.",
                    url=resp.url,
                    evidence={"indicator": pattern},
                    remediation="Disable debug mode in production environments immediately.",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                )]

        # Check debug headers
        debug_headers = ["x-debug-token", "x-debug-token-link", "x-debug"]
        for header in debug_headers:
            if header in {k.lower() for k in resp.headers}:
                return [PassiveFinding(
                    finding_type=FindingType.DEBUG_ENABLED,
                    severity=FindingSeverity.MEDIUM,
                    title="Debug Headers Present",
                    description=f"Debug header '{header}' found in response. Debug features may be enabled.",
                    url=resp.url,
                    evidence={"header": header, "value": resp.headers.get(header, "")},
                    remediation="Remove debug headers in production.",
                )]

        return []

    def _check_directory_listing(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect directory listing enabled."""
        body = resp.body_text or ""

        patterns = [
            r"<title>Index of /",
            r"<title>Directory listing for",
            r'<h1>Index of /',
            r'Parent Directory</a>',
            r"Directory Listing For",
        ]

        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return [PassiveFinding(
                    finding_type=FindingType.DIRECTORY_LISTING,
                    severity=FindingSeverity.MEDIUM,
                    title="Directory Listing Enabled",
                    description="Web server directory listing is enabled, exposing the file structure and potentially sensitive files.",
                    url=resp.url,
                    evidence={"indicator": pattern},
                    remediation="Disable directory listing in the web server configuration.",
                )]

        return []

    def _check_source_code_comments(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect potentially sensitive HTML comments."""
        body = resp.body_text or ""
        findings = []

        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        sensitive_patterns = [
            (r'(password|passwd|pwd)\s*[:=]', "password reference"),
            (r'(api[_-]?key|apikey|secret)\s*[:=]', "API key/secret reference"),
            (r'TODO|FIXME|HACK|BUG|XXX', "development note"),
            (r'(jdbc:|mysql:|postgres:|mongodb:)', "database connection string"),
            (r'/etc/(passwd|shadow|hosts)', "system file path"),
        ]

        for comment in comments:
            for pattern, label in sensitive_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    findings.append(PassiveFinding(
                        finding_type=FindingType.INFO_DISCLOSURE,
                        severity=FindingSeverity.LOW,
                        title=f"Sensitive HTML Comment: {label}",
                        description=f"An HTML comment contains potentially sensitive information ({label}).",
                        url=resp.url,
                        evidence={"comment": comment.strip()[:200]},
                        remediation="Remove sensitive comments from production HTML.",
                    ))
                    break  # One finding per comment

        return findings[:5]  # Limit to 5 findings per page

    def _check_sensitive_data_exposure(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect potential sensitive data patterns in responses."""
        body = resp.body_text or ""
        findings = []

        # AWS keys
        if re.search(r'AKIA[0-9A-Z]{16}', body):
            findings.append(PassiveFinding(
                finding_type=FindingType.SENSITIVE_FILE,
                severity=FindingSeverity.CRITICAL,
                title="AWS Access Key Exposed",
                description="An AWS access key ID pattern was found in the response.",
                url=resp.url,
                evidence={"pattern": "AKIA[0-9A-Z]{16}"},
                remediation="Immediately rotate the exposed AWS credentials.",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            ))

        # Private keys
        if "BEGIN RSA PRIVATE KEY" in body or "BEGIN PRIVATE KEY" in body:
            findings.append(PassiveFinding(
                finding_type=FindingType.SENSITIVE_FILE,
                severity=FindingSeverity.CRITICAL,
                title="Private Key Exposed",
                description="A private key was found in the response.",
                url=resp.url,
                evidence={"indicator": "BEGIN PRIVATE KEY"},
                remediation="Remove the private key immediately and rotate all affected keys.",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            ))

        return findings

    def _check_mixed_content(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect mixed content (HTTP resources on HTTPS pages)."""
        if not resp.url.startswith("https://"):
            return []

        body = resp.body_text or ""
        http_resources = re.findall(r'(src|href|action)=["\']http://[^"\']+["\']', body, re.IGNORECASE)

        if http_resources:
            return [PassiveFinding(
                finding_type=FindingType.MISCONFIGURATION,
                severity=FindingSeverity.LOW,
                title="Mixed Content Detected",
                description=f"HTTPS page loads {len(http_resources)} resources over HTTP, weakening encryption.",
                url=resp.url,
                evidence={"count": len(http_resources), "examples": http_resources[:3]},
                remediation="Ensure all resources are loaded over HTTPS.",
            )]
        return []

    def _check_autocomplete_password(self, resp: HTTPResponse) -> list[PassiveFinding]:
        """Detect password fields without autocomplete=off."""
        body = resp.body_text or ""

        password_inputs = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', body, re.IGNORECASE)
        for inp in password_inputs:
            if 'autocomplete="off"' not in inp.lower() and "autocomplete='off'" not in inp.lower():
                return [PassiveFinding(
                    finding_type=FindingType.MISCONFIGURATION,
                    severity=FindingSeverity.INFO,
                    title="Password Field Without Autocomplete=off",
                    description="Password input field does not disable autocomplete. Browsers may store sensitive credentials.",
                    url=resp.url,
                    evidence={"input": inp[:200]},
                    remediation='Add autocomplete="off" to password input fields.',
                )]
        return []
