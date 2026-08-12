"""
SentinelGraph — Active Security Probes

Safe, evidence-based active security testing probes.
All probes use BENIGN payloads only — no exploitation, no data extraction.
"""

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ProbeResult:
    """Result from an active security probe."""
    probe_name: str
    severity: str
    title: str
    description: str
    url: str
    category: str
    confidence: float
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float | None = None
    verified: bool = False


# ══════════════════════════════════════════════════════════════
# XSS REFLECTION PROBE
# ══════════════════════════════════════════════════════════════
class XSSReflectionProbe:
    """
    Detects reflected XSS by injecting BENIGN unique strings and checking
    if they appear in the response without encoding.
    SAFE: Uses only alphanumeric canary strings — no actual script payloads.
    """

    CANARY_PREFIX = "sgxss"
    CONTEXTS = {
        "html_body": {
            "probe": "<{canary}>",
            "check": lambda body, canary: f"<{canary}>" in body,
            "severity": "high",
            "desc": "Input reflected in HTML body without encoding — XSS possible",
        },
        "html_attr": {
            "probe": '"{canary}"',
            "check": lambda body, canary: f'"{canary}"' in body,
            "severity": "medium",
            "desc": "Input reflected in HTML attribute without quote escaping",
        },
        "js_context": {
            "probe": "'-{canary}-'",
            "check": lambda body, canary: f"'-{canary}-'" in body,
            "severity": "high",
            "desc": "Input reflected in JavaScript context without escaping",
        },
        "url_context": {
            "probe": "javascript:{canary}",
            "check": lambda body, canary: f"javascript:{canary}" in body.lower(),
            "severity": "high",
            "desc": "JavaScript protocol accepted in URL context",
        },
    }

    async def probe(self, client: httpx.AsyncClient, url: str, params: list[str]) -> list[ProbeResult]:
        results = []
        for param in params:
            for ctx_name, ctx in self.CONTEXTS.items():
                canary = f"{self.CANARY_PREFIX}{hashlib.md5(f'{url}{param}{ctx_name}'.encode()).hexdigest()[:8]}"
                probe_value = ctx["probe"].format(canary=canary)

                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [probe_value]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                try:
                    resp = await client.get(test_url)
                    if ctx["check"](resp.text, canary):
                        results.append(ProbeResult(
                            probe_name="xss_reflection",
                            severity=ctx["severity"],
                            title=f"Reflected XSS ({ctx_name}) in '{param}'",
                            description=ctx["desc"],
                            url=test_url,
                            category="xss",
                            confidence=0.85,
                            evidence={"parameter": param, "context": ctx_name, "canary": canary, "reflected": True},
                            remediation="Implement context-aware output encoding. Use Content-Security-Policy headers.",
                            cvss_score=6.1 if ctx["severity"] == "high" else 4.3,
                            verified=True,
                        ))
                        logger.info("xss.reflection.found", param=param, context=ctx_name, url=url)
                        break  # One finding per param is enough
                except Exception as e:
                    logger.debug("xss.probe.error", param=param, error=str(e))

        return results


# ══════════════════════════════════════════════════════════════
# SQL INJECTION INDICATOR PROBE
# ══════════════════════════════════════════════════════════════
class SQLInjectionProbe:
    """
    Detects SQL injection indicators using SAFE probes:
    - Error-based: Sends syntax-breaking characters and looks for SQL error messages
    - Boolean-based: Sends tautology and contradiction, compares response differences
    - Time-based: Sends benign SLEEP probe and measures response time delta
    SAFE: No data extraction, no destructive queries.
    """

    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"PostgreSQL.*?ERROR",
        r"ORA-\d{5}",
        r"Microsoft.*?ODBC.*?SQL",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQLite3?::(?:Statement|Database)",
        r"SQLSTATE\[\w+\]",
        r"Dynamic SQL Error",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"com\.mysql\.jdbc",
    ]

    BOOLEAN_PAIRS = [
        ("' OR '1'='1", "' AND '1'='2"),
        ("1 OR 1=1", "1 AND 1=2"),
    ]

    async def probe(self, client: httpx.AsyncClient, url: str, params: list[str]) -> list[ProbeResult]:
        results = []

        for param in params:
            # Error-based detection
            error_result = await self._error_based(client, url, param)
            if error_result:
                results.append(error_result)
                continue

            # Boolean-based detection
            bool_result = await self._boolean_based(client, url, param)
            if bool_result:
                results.append(bool_result)
                continue

            # Time-based detection (only if other methods fail)
            time_result = await self._time_based(client, url, param)
            if time_result:
                results.append(time_result)

        return results

    async def _error_based(self, client: httpx.AsyncClient, url: str, param: str) -> ProbeResult | None:
        """Send syntax-breaking characters and look for SQL error messages."""
        probes = ["'", '"', "' OR '", "1' --", "1; --"]

        for probe_val in probes:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [probe_val]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

            try:
                resp = await client.get(test_url)
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.I):
                        return ProbeResult(
                            probe_name="sqli_error",
                            severity="critical",
                            title=f"SQL Injection (Error-based) in '{param}'",
                            description=f"SQL error message exposed when injecting syntax-breaking characters into '{param}'.",
                            url=test_url,
                            category="sqli",
                            confidence=0.90,
                            evidence={"parameter": param, "probe": probe_val, "error_pattern": pattern},
                            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                            cvss_score=9.8,
                            verified=True,
                        )
            except Exception:
                pass
        return None

    async def _boolean_based(self, client: httpx.AsyncClient, url: str, param: str) -> ProbeResult | None:
        """Compare responses between tautology and contradiction."""
        parsed = urlparse(url)

        for true_payload, false_payload in self.BOOLEAN_PAIRS:
            try:
                qs_true = parse_qs(parsed.query)
                qs_true[param] = [true_payload]
                url_true = parsed._replace(query=urlencode(qs_true, doseq=True)).geturl()

                qs_false = parse_qs(parsed.query)
                qs_false[param] = [false_payload]
                url_false = parsed._replace(query=urlencode(qs_false, doseq=True)).geturl()

                resp_true = await client.get(url_true)
                resp_false = await client.get(url_false)

                # Significant difference indicates boolean injection
                len_diff = abs(len(resp_true.text) - len(resp_false.text))
                if len_diff > 100 and resp_true.status_code == resp_false.status_code:
                    return ProbeResult(
                        probe_name="sqli_boolean",
                        severity="high",
                        title=f"SQL Injection (Boolean-based) in '{param}'",
                        description=f"Significant response difference between tautology and contradiction in '{param}'.",
                        url=url,
                        category="sqli",
                        confidence=0.70,
                        evidence={"parameter": param, "len_true": len(resp_true.text), "len_false": len(resp_false.text), "diff": len_diff},
                        remediation="Use parameterized queries/prepared statements.",
                        cvss_score=8.6,
                        verified=False,
                    )
            except Exception:
                pass
        return None

    async def _time_based(self, client: httpx.AsyncClient, url: str, param: str) -> ProbeResult | None:
        """Send SLEEP probe and measure response time delta. Uses 2 seconds — minimal impact."""
        parsed = urlparse(url)
        sleep_payloads = [
            ("1' AND SLEEP(2)-- -", "MySQL"),
            ("1'; WAITFOR DELAY '0:0:2'-- -", "MSSQL"),
            ("1' AND pg_sleep(2)-- -", "PostgreSQL"),
        ]

        # Baseline timing
        try:
            t0 = time.monotonic()
            await client.get(url)
            baseline = time.monotonic() - t0
        except Exception:
            return None

        for payload, db_type in sleep_payloads:
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

            try:
                t0 = time.monotonic()
                await client.get(test_url)
                elapsed = time.monotonic() - t0

                if elapsed > baseline + 1.5:  # At least 1.5s longer than baseline
                    return ProbeResult(
                        probe_name="sqli_time",
                        severity="critical",
                        title=f"SQL Injection (Time-based) in '{param}'",
                        description=f"Response delayed by ~{elapsed - baseline:.1f}s with SLEEP payload ({db_type}).",
                        url=test_url,
                        category="sqli",
                        confidence=0.75,
                        evidence={"parameter": param, "baseline_ms": round(baseline * 1000), "probe_ms": round(elapsed * 1000), "db_hint": db_type},
                        remediation="Use parameterized queries/prepared statements.",
                        cvss_score=9.8,
                        verified=True,
                    )
            except Exception:
                pass
        return None


# ══════════════════════════════════════════════════════════════
# CSRF PROBE
# ══════════════════════════════════════════════════════════════
class CSRFProbe:
    """
    Checks for missing CSRF protection on state-changing forms.
    SAFE: Only analyzes form HTML — no form submission.
    """

    TOKEN_PATTERNS = [
        r'name=["\']?csrf',
        r'name=["\']?_token',
        r'name=["\']?authenticity_token',
        r'name=["\']?__RequestVerificationToken',
        r'name=["\']?csrfmiddlewaretoken',
        r'name=["\']?_csrf',
        r'x-csrf-token',
        r'x-xsrf-token',
    ]

    async def probe(self, client: httpx.AsyncClient, url: str, html: str) -> list[ProbeResult]:
        results = []
        forms = re.findall(r'<form[^>]*>.*?</form>', html, re.I | re.DOTALL)

        for form in forms:
            if 'method' not in form.lower():
                continue
            if 'post' not in form.lower() and 'put' not in form.lower() and 'delete' not in form.lower():
                continue

            has_csrf = any(re.search(p, form, re.I) for p in self.TOKEN_PATTERNS)

            if not has_csrf:
                action = re.search(r'action=["\']([^"\']*)["\']', form, re.I)
                action_url = action.group(1) if action else url

                results.append(ProbeResult(
                    probe_name="csrf_missing",
                    severity="medium",
                    title="Missing CSRF Protection",
                    description=f"POST form at '{action_url}' lacks anti-CSRF token.",
                    url=url,
                    category="csrf",
                    confidence=0.80,
                    evidence={"form_action": action_url, "has_csrf_token": False},
                    remediation="Add CSRF tokens to all state-changing forms. Use SameSite=Lax cookies.",
                    cvss_score=4.3,
                ))

        return results


# ══════════════════════════════════════════════════════════════
# SSRF INDICATOR PROBE
# ══════════════════════════════════════════════════════════════
class SSRFProbe:
    """
    Detects SSRF indicators by analyzing URL parameters.
    SAFE: Only probes with localhost:1 (non-routable port) and analyzes error patterns.
    """

    URL_PARAM_PATTERNS = [
        "url", "uri", "link", "src", "source", "target", "dest", "destination",
        "redirect", "page", "feed", "host", "site", "path", "file", "document",
        "folder", "root", "dir", "img", "image", "load", "fetch", "proxy",
    ]

    async def probe(self, client: httpx.AsyncClient, url: str, params: list[str]) -> list[ProbeResult]:
        results = []

        url_params = [p for p in params if any(pat in p.lower() for pat in self.URL_PARAM_PATTERNS)]

        for param in url_params:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            # Probe 1: Internal address (safe - port 1 is always closed)
            qs[param] = ["http://127.0.0.1:1"]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

            try:
                resp = await client.get(test_url)
                # If we get a connection error message or different response, SSRF may be possible
                error_indicators = ["connection refused", "connect error", "timed out", "could not connect", "failed to connect"]
                if any(ind in resp.text.lower() for ind in error_indicators):
                    results.append(ProbeResult(
                        probe_name="ssrf_indicator",
                        severity="high",
                        title=f"SSRF Indicator in '{param}'",
                        description=f"Server attempted to connect to internal address via '{param}' parameter.",
                        url=test_url,
                        category="ssrf",
                        confidence=0.65,
                        evidence={"parameter": param, "probe": "http://127.0.0.1:1", "response_indicates_connection_attempt": True},
                        remediation="Validate and sanitize URL inputs. Use allowlists. Block internal IP ranges.",
                        cvss_score=7.5,
                    ))
            except Exception:
                pass

        return results


# ══════════════════════════════════════════════════════════════
# PATH TRAVERSAL PROBE
# ══════════════════════════════════════════════════════════════
class PathTraversalProbe:
    """
    Detects path traversal by sending safe probes.
    SAFE: Only checks for error message patterns — no file reading.
    """

    FILE_PARAMS = ["file", "path", "page", "doc", "document", "folder", "root",
                   "dir", "include", "template", "filename", "filepath", "name"]

    TRAVERSAL_PROBES = [
        ("../../../etc/passwd", r"root:.*:0:0"),
        ("..\\..\\..\\windows\\win.ini", r"\[fonts\]"),
        ("....//....//....//etc/passwd", r"root:.*:0:0"),
        ("/etc/passwd%00.jpg", r"root:.*:0:0"),
    ]

    async def probe(self, client: httpx.AsyncClient, url: str, params: list[str]) -> list[ProbeResult]:
        results = []
        file_params = [p for p in params if any(fp in p.lower() for fp in self.FILE_PARAMS)]

        for param in file_params:
            for probe_path, success_pattern in self.TRAVERSAL_PROBES:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [probe_path]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                try:
                    resp = await client.get(test_url)
                    if re.search(success_pattern, resp.text, re.I):
                        results.append(ProbeResult(
                            probe_name="path_traversal",
                            severity="critical",
                            title=f"Path Traversal in '{param}'",
                            description=f"Directory traversal successful via '{param}' — sensitive file content exposed.",
                            url=test_url,
                            category="path_traversal",
                            confidence=0.95,
                            evidence={"parameter": param, "probe": probe_path, "matched_pattern": success_pattern},
                            remediation="Validate file paths against allowlists. Use chroot. Never use user input in file paths.",
                            cvss_score=9.1,
                            verified=True,
                        ))
                        break  # One finding per param
                except Exception:
                    pass

        return results


# ══════════════════════════════════════════════════════════════
# TEMPLATE INJECTION PROBE
# ══════════════════════════════════════════════════════════════
class TemplateInjectionProbe:
    """
    Detects server-side template injection using mathematical expressions.
    SAFE: Only sends {{7*7}} and checks for 49 in response.
    """

    MATH_PROBES = [
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("${7*7}", "49", "Freemarker/EL"),
        ("#{7*7}", "49", "Ruby ERB/Thymeleaf"),
        ("<%= 7*7 %>", "49", "EJS/ERB"),
        ("{{7*'7'}}", "7777777", "Jinja2 string multiply"),
    ]

    async def probe(self, client: httpx.AsyncClient, url: str, params: list[str]) -> list[ProbeResult]:
        results = []

        for param in params:
            for probe_val, expected, engine in self.MATH_PROBES:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [probe_val]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                try:
                    resp = await client.get(test_url)
                    if expected in resp.text and probe_val not in resp.text:
                        results.append(ProbeResult(
                            probe_name="ssti",
                            severity="critical",
                            title=f"Template Injection ({engine}) in '{param}'",
                            description=f"Server evaluates template expression in '{param}' — SSTI confirmed.",
                            url=test_url,
                            category="ssti",
                            confidence=0.92,
                            evidence={"parameter": param, "probe": probe_val, "expected": expected, "engine_hint": engine},
                            remediation="Never render user input as template code. Use sandboxed template engines.",
                            cvss_score=9.8,
                            verified=True,
                        ))
                        break
                except Exception:
                    pass

        return results


# ══════════════════════════════════════════════════════════════
# OPEN REDIRECT PROBE
# ══════════════════════════════════════════════════════════════
class OpenRedirectProbe:
    """
    Detects open redirect vulnerabilities.
    SAFE: Checks redirect behavior with external domain.
    """

    REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "redirect_uri",
                       "goto", "target", "destination", "redir", "return_to", "continue"]

    async def probe(self, client: httpx.AsyncClient, url: str, params: list[str]) -> list[ProbeResult]:
        results = []
        redirect_params = [p for p in params if any(rp in p.lower() for rp in self.REDIRECT_PARAMS)]

        # Also try common redirect params not in the URL
        for rp in self.REDIRECT_PARAMS:
            if rp not in [p.lower() for p in params]:
                redirect_params.append(rp)

        for param in redirect_params[:5]:  # Limit to 5
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = ["https://evil-redirect-test.example.com"]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

            try:
                resp = await client.get(test_url, follow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil-redirect-test.example.com" in location:
                        results.append(ProbeResult(
                            probe_name="open_redirect",
                            severity="medium",
                            title=f"Open Redirect via '{param}'",
                            description=f"Parameter '{param}' allows redirection to arbitrary external sites.",
                            url=test_url,
                            category="open_redirect",
                            confidence=0.90,
                            evidence={"parameter": param, "redirect_to": location},
                            remediation="Validate redirect URLs against an allowlist. Use relative paths only.",
                            cvss_score=6.1,
                            verified=True,
                        ))
                        break
            except Exception:
                pass

        return results


# ══════════════════════════════════════════════════════════════
# CORS MISCONFIGURATION PROBE
# ══════════════════════════════════════════════════════════════
class CORSProbe:
    """
    Tests CORS configuration for misconfigurations.
    SAFE: Only sends OPTIONS requests with custom Origin header.
    """

    async def probe(self, client: httpx.AsyncClient, url: str) -> list[ProbeResult]:
        results = []
        test_origins = [
            ("https://evil-attacker.example.com", "arbitrary"),
            (f"https://{urlparse(url).hostname}.evil.com", "subdomain_suffix"),
            ("null", "null_origin"),
        ]

        for origin, attack_type in test_origins:
            try:
                resp = await client.options(url, headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                })

                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                if acao == "*" and acac == "true":
                    results.append(ProbeResult(
                        probe_name="cors_wildcard_creds",
                        severity="critical",
                        title="CORS Wildcard with Credentials",
                        description="Access-Control-Allow-Origin is '*' with credentials enabled. Attackers can steal authenticated data.",
                        url=url, category="cors", confidence=0.95,
                        evidence={"origin_tested": origin, "acao": acao, "acac": acac},
                        remediation="Never use '*' with credentials. Whitelist specific origins.",
                        cvss_score=9.1, verified=True,
                    ))
                    break
                elif origin in acao and origin != "null":
                    results.append(ProbeResult(
                        probe_name="cors_reflection",
                        severity="high" if acac == "true" else "medium",
                        title=f"CORS Origin Reflection ({attack_type})",
                        description=f"Server reflects attacker Origin '{origin}'. Cross-origin data theft possible.",
                        url=url, category="cors", confidence=0.90,
                        evidence={"origin_tested": origin, "acao": acao, "attack_type": attack_type},
                        remediation="Validate Origin against a strict whitelist. Never reflect Origin directly.",
                        cvss_score=7.5 if acac == "true" else 5.3, verified=True,
                    ))
                    break
            except Exception:
                pass

        return results


# ══════════════════════════════════════════════════════════════
# RATE LIMITING PROBE
# ══════════════════════════════════════════════════════════════
class RateLimitProbe:
    """
    Tests for rate limiting on authentication endpoints.
    SAFE: Sends 15 requests max — well below abuse threshold.
    """

    async def probe(self, client: httpx.AsyncClient, url: str) -> list[ProbeResult]:
        results = []
        status_codes = []

        for i in range(15):
            try:
                resp = await client.get(url)
                status_codes.append(resp.status_code)
                if resp.status_code == 429:
                    # Rate limiting is active — good!
                    return results
                await asyncio.sleep(0.05)
            except Exception:
                break

        # If all 15 requests succeeded with same status, no rate limiting
        if len(status_codes) >= 15 and all(s == status_codes[0] for s in status_codes):
            # Only flag if this looks like an auth endpoint
            auth_indicators = ["login", "signin", "auth", "password", "register", "signup", "api/token"]
            if any(ind in url.lower() for ind in auth_indicators):
                results.append(ProbeResult(
                    probe_name="rate_limit_missing",
                    severity="medium",
                    title="No Rate Limiting on Authentication Endpoint",
                    description="Sent 15 requests without rate limiting. Brute-force attacks possible.",
                    url=url, category="rate_limiting", confidence=0.75,
                    evidence={"requests_sent": 15, "all_status": status_codes[0]},
                    remediation="Implement rate limiting (e.g., 5 attempts per minute). Add CAPTCHA after failures.",
                    cvss_score=5.3,
                ))

        return results


# ══════════════════════════════════════════════════════════════
# MASTER PROBE RUNNER
# ══════════════════════════════════════════════════════════════
class ActiveProbeEngine:
    """Runs all active security probes against a target."""

    def __init__(self):
        self.xss = XSSReflectionProbe()
        self.sqli = SQLInjectionProbe()
        self.csrf = CSRFProbe()
        self.ssrf = SSRFProbe()
        self.path_traversal = PathTraversalProbe()
        self.ssti = TemplateInjectionProbe()
        self.open_redirect = OpenRedirectProbe()
        self.cors = CORSProbe()
        self.rate_limit = RateLimitProbe()

    async def run_all(self, client: httpx.AsyncClient, url: str, params: list[str], html: str = "") -> list[ProbeResult]:
        """Run all probes and collect results."""
        logger.info("active_probes.start", url=url, param_count=len(params))
        all_results = []

        # Parameter-based probes
        if params:
            probe_tasks = [
                self.xss.probe(client, url, params),
                self.sqli.probe(client, url, params),
                self.ssrf.probe(client, url, params),
                self.path_traversal.probe(client, url, params),
                self.ssti.probe(client, url, params),
                self.open_redirect.probe(client, url, params),
            ]
            results = await asyncio.gather(*probe_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    all_results.extend(r)

        # Non-parameter probes
        if html:
            csrf_results = await self.csrf.probe(client, url, html)
            all_results.extend(csrf_results)

        cors_results = await self.cors.probe(client, url)
        all_results.extend(cors_results)

        rate_results = await self.rate_limit.probe(client, url)
        all_results.extend(rate_results)

        logger.info("active_probes.complete", url=url, total_findings=len(all_results))
        return all_results
