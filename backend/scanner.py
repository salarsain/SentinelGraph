"""
SentinelGraph — Standalone Live Scanner
Runs security analysis engines directly against a target URL.
No Docker/DB required — uses all detection modules in-process.
"""

import asyncio
import json
import re
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin

import httpx

# ══════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════
TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "https://cyberhackathon.pk/admin/login/"
MAX_PATHS = 35
TIMEOUT = 15
USER_AGENT = "SentinelGraph/0.1.0 (Security Assessment)"


# ══════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════
@dataclass
class Finding:
    severity: str
    title: str
    description: str
    url: str
    category: str
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float | None = None
    confidence: float = 0.8


@dataclass
class ScanResult:
    target: str
    started_at: str
    completed_at: str = ""
    status: str = "running"
    technologies: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    headers_grade: str = ""
    ssl_info: dict = field(default_factory=dict)
    server_info: dict = field(default_factory=dict)
    pages_crawled: int = 0
    total_findings: int = 0
    severity_counts: dict = field(default_factory=dict)


# ══════════════════════════════════════════════════════════════
# HEADER SIGNATURES
# ══════════════════════════════════════════════════════════════
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "medium",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "medium",
        "remediation": "Implement a strict Content-Security-Policy header to prevent XSS attacks.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "info",
        "remediation": "Add header: X-XSS-Protection: 0 (modern browsers use CSP instead).",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "remediation": "Add Permissions-Policy header to control browser features.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "severity": "info",
        "remediation": "Add header: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "CORP",
        "severity": "info",
        "remediation": "Add header: Cross-Origin-Resource-Policy: same-origin",
    },
}

TECH_HEADER_SIGS = [
    ("server", "nginx", "Nginx", "server", r"nginx/([\d.]+)"),
    ("server", "apache", "Apache", "server", r"Apache/([\d.]+)"),
    ("server", "cloudflare", "Cloudflare", "cdn", None),
    ("server", "gunicorn", "Gunicorn", "server", r"gunicorn/([\d.]+)"),
    ("x-powered-by", "php", "PHP", "language", r"PHP/([\d.]+)"),
    ("x-powered-by", "express", "Express.js", "framework", None),
    ("x-powered-by", "asp.net", "ASP.NET", "framework", None),
    ("x-generator", "wordpress", "WordPress", "cms", r"WordPress ([\d.]+)"),
    ("x-generator", "drupal", "Drupal", "cms", r"Drupal ([\d.]+)"),
]

TECH_HTML_SIGS = [
    (r'/wp-content/', "WordPress", "cms"),
    (r'/wp-includes/', "WordPress", "cms"),
    (r'wp-json', "WordPress REST API", "cms"),
    (r'__NEXT_DATA__', "Next.js", "framework"),
    (r'/_next/static', "Next.js", "framework"),
    (r'react-dom', "React", "js-library"),
    (r'ng-version="([\d.]+)"', "Angular", "js-library"),
    (r'__vue__', "Vue.js", "js-library"),
    (r'jquery[.-]?([\d.]+)?\.min\.js', "jQuery", "js-library"),
    (r'bootstrap[.-]?([\d.]+)?\.min\.(js|css)', "Bootstrap", "css-framework"),
    (r'tailwindcss', "Tailwind CSS", "css-framework"),
    (r'django', "Django", "framework"),
    (r'csrfmiddlewaretoken', "Django", "framework"),
    (r'laravel', "Laravel", "framework"),
    (r'swagger-ui', "Swagger", "api-tool"),
    (r'graphql', "GraphQL", "api-tool"),
]

SENSITIVE_PATHS = [
    ("/.git/HEAD", "Git Repository Exposed", "critical"),
    ("/.git/config", "Git Config Exposed", "high"),
    ("/.env", "Environment File Exposed", "critical"),
    ("/.env.production", "Production Env Exposed", "critical"),
    ("/wp-config.php", "WordPress Config Exposed", "critical"),
    ("/config.php", "PHP Config Exposed", "high"),
    ("/backup.sql", "SQL Backup Exposed", "critical"),
    ("/db.sql", "DB Dump Exposed", "critical"),
    ("/phpinfo.php", "PHP Info Page", "medium"),
    ("/admin", "Admin Panel", "info"),
    ("/robots.txt", "Robots.txt", "info"),
    ("/sitemap.xml", "Sitemap", "info"),
    ("/.well-known/security.txt", "Security.txt", "info"),
    ("/swagger.json", "Swagger Spec", "low"),
    ("/openapi.json", "OpenAPI Spec", "low"),
    ("/server-status", "Apache Status", "medium"),
    ("/.svn/entries", "SVN Exposed", "high"),
    ("/.htaccess", "htaccess Exposed", "medium"),
    ("/wp-login.php", "WP Login", "info"),
    ("/debug", "Debug Endpoint", "medium"),
    ("/__debug__/", "Django Debug Toolbar", "high"),
    ("/api/", "API Endpoint", "info"),
    ("/api/v1/", "API v1 Endpoint", "info"),
    ("/graphql", "GraphQL Endpoint", "low"),
    ("/crossdomain.xml", "Flash Crossdomain", "low"),
]

COOKIE_SENSITIVE_NAMES = [
    "session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf",
    "phpsessid", "jsessionid", "connect.sid", "laravel_session",
]


# ══════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ══════════════════════════════════════════════════════════════
async def run_scan(target_url: str) -> ScanResult:
    result = ScanResult(
        target=target_url,
        started_at=datetime.utcnow().isoformat() + "Z",
    )

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n{'='*60}")
    print(f"  🔍 SentinelGraph — Live Security Scan")
    print(f"  Target: {target_url}")
    print(f"  Started: {result.started_at}")
    print(f"{'='*60}\n")

    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=True,
        verify=False,  # Allow self-signed certs for scanning
        headers={"User-Agent": USER_AGENT},
    ) as client:

        # ── Phase 1: Initial Probe ────────────────────────────
        print("▸ Phase 1: Initial Probe...")
        try:
            resp = await client.get(target_url)
            print(f"  ✓ {resp.status_code} — {len(resp.text)} bytes")
            result.pages_crawled = 1
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            result.status = "failed"
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        # ── Phase 2: Security Headers ─────────────────────────
        print("\n▸ Phase 2: Security Headers Analysis...")
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        present = 0
        total = len(SECURITY_HEADERS)

        for header_key, info in SECURITY_HEADERS.items():
            if header_key in headers_lower:
                present += 1
                print(f"  ✓ {info['name']}: Present")
            else:
                print(f"  ✗ {info['name']}: MISSING")
                result.findings.append(Finding(
                    severity=info["severity"],
                    title=f"Missing Security Header: {info['name']}",
                    description=f"The {info['name']} header is not set. This may weaken security posture.",
                    url=target_url,
                    category="security_header",
                    evidence={"header": header_key, "status": "missing"},
                    remediation=info["remediation"],
                ))

        # Grade
        ratio = present / total if total else 0
        if ratio >= 0.9: grade = "A+"
        elif ratio >= 0.8: grade = "A"
        elif ratio >= 0.7: grade = "B"
        elif ratio >= 0.5: grade = "C"
        elif ratio >= 0.3: grade = "D"
        else: grade = "F"
        result.headers_grade = grade
        print(f"  📊 Headers Grade: {grade} ({present}/{total})")

        # Check for leaky headers
        for leak_header in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
            if leak_header in headers_lower:
                value = headers_lower[leak_header]
                result.findings.append(Finding(
                    severity="low",
                    title=f"Server Information Disclosure: {leak_header}",
                    description=f"The '{leak_header}' header reveals: {value}",
                    url=target_url,
                    category="info_disclosure",
                    evidence={"header": leak_header, "value": value},
                    remediation=f"Remove or obfuscate the '{leak_header}' header.",
                ))
                print(f"  ⚠ Info leak: {leak_header}: {value}")

        # ── Phase 3: Technology Fingerprinting ─────────────────
        print("\n▸ Phase 3: Technology Fingerprinting...")
        techs = set()

        for h_name, pattern, tech, category, ver_re in TECH_HEADER_SIGS:
            value = headers_lower.get(h_name, "")
            if pattern.lower() in value.lower():
                version = ""
                if ver_re:
                    m = re.search(ver_re, value, re.I)
                    if m: version = f" {m.group(1)}"
                techs.add(f"{tech}{version}")
                print(f"  ✓ {tech}{version} ({category})")

        body = resp.text
        for pattern, tech, category in TECH_HTML_SIGS:
            if re.search(pattern, body, re.I):
                techs.add(tech)
                print(f"  ✓ {tech} ({category})")

        result.technologies = list(techs)
        if not techs:
            print("  · No specific technologies detected")

        # ── Phase 4: SSL/TLS Analysis ──────────────────────────
        if parsed.scheme == "https":
            print("\n▸ Phase 4: SSL/TLS Analysis...")
            try:
                ctx = ssl.create_default_context()
                conn = ctx.wrap_socket(
                    __import__('socket').socket(),
                    server_hostname=parsed.hostname,
                )
                conn.settimeout(10)
                conn.connect((parsed.hostname, 443))
                cert = conn.getpeercert()
                conn.close()

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                result.ssl_info = {
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "subject": subject.get("commonName", "Unknown"),
                    "valid_from": cert.get("notBefore", ""),
                    "valid_to": cert.get("notAfter", ""),
                    "version": cert.get("version", ""),
                }
                print(f"  ✓ Issuer: {result.ssl_info['issuer']}")
                print(f"  ✓ Subject: {result.ssl_info['subject']}")
                print(f"  ✓ Valid: {result.ssl_info['valid_from']} → {result.ssl_info['valid_to']}")
            except Exception as e:
                print(f"  ⚠ SSL check error: {e}")
        else:
            print("\n▸ Phase 4: SSL — Not HTTPS, skipping")
            result.findings.append(Finding(
                severity="high",
                title="No HTTPS Encryption",
                description="The site does not use HTTPS. All data is transmitted in plaintext.",
                url=target_url,
                category="encryption",
                remediation="Enable HTTPS with a valid TLS certificate.",
                cvss_score=7.5,
            ))

        # ── Phase 5: Cookie Analysis ───────────────────────────
        print("\n▸ Phase 5: Cookie Security Analysis...")
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]

        if cookies:
            for cookie_header in cookies:
                parts = cookie_header.split(";")
                name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
                flags_lower = {p.strip().lower().split("=")[0] for p in parts[1:]}
                is_sensitive = any(s in name.lower() for s in COOKIE_SENSITIVE_NAMES)

                print(f"  📋 Cookie: {name}")

                if "secure" not in flags_lower and parsed.scheme == "https":
                    result.findings.append(Finding(
                        severity="medium" if is_sensitive else "low",
                        title=f"Cookie '{name}' Missing Secure Flag",
                        description=f"Cookie '{name}' can be sent over unencrypted HTTP.",
                        url=target_url,
                        category="cookie",
                        evidence={"cookie": name, "flags": list(flags_lower)},
                        remediation=f"Add 'Secure' flag to cookie '{name}'.",
                    ))
                    print(f"    ✗ Missing: Secure")

                if is_sensitive and "httponly" not in flags_lower:
                    result.findings.append(Finding(
                        severity="medium",
                        title=f"Sensitive Cookie '{name}' Missing HttpOnly",
                        description=f"Cookie '{name}' is accessible to JavaScript (XSS risk).",
                        url=target_url,
                        category="cookie",
                        evidence={"cookie": name},
                        remediation=f"Add 'HttpOnly' flag to cookie '{name}'.",
                    ))
                    print(f"    ✗ Missing: HttpOnly")

                if "samesite" not in flags_lower:
                    result.findings.append(Finding(
                        severity="low" if not is_sensitive else "medium",
                        title=f"Cookie '{name}' Missing SameSite",
                        description=f"Cookie '{name}' without SameSite may enable CSRF.",
                        url=target_url,
                        category="cookie",
                        evidence={"cookie": name},
                        remediation=f"Add 'SameSite=Lax' to cookie '{name}'.",
                    ))
                    print(f"    ✗ Missing: SameSite")
        else:
            print("  · No cookies set")

        # ── Phase 6: Passive Content Analysis ─────────────────
        print("\n▸ Phase 6: Passive Content Analysis...")

        # Error disclosure
        error_patterns = [
            (r"Traceback \(most recent call last\)", "Python stack trace", "medium"),
            (r"Fatal error:.*\.php", "PHP fatal error", "high"),
            (r"SQLSTATE\[\w+\]", "SQL error", "medium"),
            (r"Unhandled Exception", ".NET exception", "medium"),
        ]
        for pattern, name, sev in error_patterns:
            if re.search(pattern, body, re.I):
                result.findings.append(Finding(severity=sev, title=f"Error Disclosure: {name}",
                    description=f"Response contains {name}, revealing implementation details.",
                    url=target_url, category="info_disclosure",
                    remediation="Configure custom error pages for production."))
                print(f"  ⚠ Error disclosure: {name}")

        # Internal IPs
        ips = re.findall(r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b', body)
        if ips:
            result.findings.append(Finding(severity="low", title="Internal IP Disclosure",
                description=f"Internal IPs found: {', '.join(set(ips)[:3])}",
                url=target_url, category="info_disclosure",
                remediation="Remove internal IPs from responses."))
            print(f"  ⚠ Internal IPs: {set(ips)}")

        # Debug mode
        debug_patterns = [
            (r"Django Debug", "Django debug mode"),
            (r"Werkzeug Debugger", "Flask debug mode"),
            (r"DJANGO_SETTINGS_MODULE", "Django settings exposed"),
        ]
        for pattern, name in debug_patterns:
            if re.search(pattern, body, re.I):
                result.findings.append(Finding(severity="high", title=f"Debug Mode: {name}",
                    description=f"{name} is active, exposing sensitive information.",
                    url=target_url, category="debug", cvss_score=7.5,
                    remediation="Disable debug mode in production."))
                print(f"  🚨 DEBUG MODE: {name}")

        # Password autocomplete
        pwd_inputs = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', body, re.I)
        for inp in pwd_inputs:
            if 'autocomplete="off"' not in inp.lower():
                result.findings.append(Finding(severity="info", title="Password Autocomplete Enabled",
                    description="Password field allows browser autocomplete.",
                    url=target_url, category="best_practice",
                    remediation='Add autocomplete="off" to password inputs.'))
                print(f"  · Password autocomplete enabled")
                break

        # CSRF token check on forms
        forms = re.findall(r'<form[^>]*>.*?</form>', body, re.I | re.DOTALL)
        for form in forms:
            if 'method' in form.lower() and 'post' in form.lower():
                if not re.search(r'csrf|_token|authenticity_token', form, re.I):
                    result.findings.append(Finding(severity="medium", title="Form Without CSRF Token",
                        description="A POST form may lack CSRF protection.",
                        url=target_url, category="csrf",
                        remediation="Add CSRF tokens to all POST forms."))
                    print(f"  ⚠ Form without CSRF token detected")
                    break

        # ── Phase 7: Sensitive Path Probing ────────────────────
        print(f"\n▸ Phase 7: Sensitive Path Probing ({len(SENSITIVE_PATHS)} paths)...")
        probe_tasks = []

        async def probe_path(path_info):
            path, title, sev = path_info
            url = f"{base_url}{path}"
            try:
                r = await client.get(url, follow_redirects=False)
                return (path, title, sev, r.status_code, len(r.text), r.text[:500])
            except:
                return (path, title, sev, 0, 0, "")

        tasks = [probe_path(p) for p in SENSITIVE_PATHS]
        results_paths = await asyncio.gather(*tasks)

        for path, title, sev, status, size, body_snippet in results_paths:
            if status == 200 and size > 50:
                # Filter false 200s (custom 404 pages)
                is_real = True
                body_low = body_snippet.lower()
                if any(x in body_low for x in ["page not found", "404", "not found", "does not exist"]):
                    is_real = False

                if is_real:
                    actual_sev = sev
                    if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/admin", "/api/", "/api/v1/"):
                        actual_sev = "info"

                    result.findings.append(Finding(
                        severity=actual_sev,
                        title=f"{title} ({path})",
                        description=f"Accessible at {base_url}{path} — returned {status} with {size} bytes.",
                        url=f"{base_url}{path}",
                        category="sensitive_path",
                        evidence={"status": status, "size": size},
                        remediation=f"Restrict access to {path} or remove from web root.",
                    ))
                    icon = "🚨" if actual_sev in ("critical", "high") else "⚠" if actual_sev == "medium" else "·"
                    print(f"  {icon} [{actual_sev.upper()}] {path} → {status} ({size}b)")

            elif status == 403:
                print(f"  🔒 {path} → 403 (exists but blocked)")
                result.findings.append(Finding(
                    severity="info",
                    title=f"{title} - Blocked ({path})",
                    description=f"Path {path} exists but returns 403 Forbidden.",
                    url=f"{base_url}{path}",
                    category="sensitive_path",
                    evidence={"status": 403},
                    remediation="Verify this path should be accessible.",
                ))

        result.pages_crawled += len(SENSITIVE_PATHS)

        # ── Phase 8: CORS Check ────────────────────────────────
        print("\n▸ Phase 8: CORS Configuration Check...")
        try:
            cors_resp = await client.options(target_url, headers={
                "Origin": "https://evil-attacker.com",
                "Access-Control-Request-Method": "GET",
            })
            acao = cors_resp.headers.get("access-control-allow-origin", "")
            acac = cors_resp.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                result.findings.append(Finding(
                    severity="high" if acac.lower() == "true" else "medium",
                    title="CORS Wildcard Origin",
                    description="Access-Control-Allow-Origin is set to '*', allowing any site to read responses.",
                    url=target_url, category="cors", cvss_score=7.5 if acac else 5.3,
                    remediation="Replace '*' with specific trusted origins.",
                ))
                print(f"  🚨 CORS: Wildcard origin (*) {'+credentials' if acac else ''}")
            elif "evil-attacker.com" in acao:
                result.findings.append(Finding(
                    severity="critical",
                    title="CORS Origin Reflection",
                    description="Server reflects attacker-controlled Origin header. Attackers can steal data cross-origin.",
                    url=target_url, category="cors", cvss_score=9.1,
                    remediation="Validate Origin against a whitelist. Never reflect the Origin header directly.",
                ))
                print(f"  🚨 CORS: Origin reflection — CRITICAL!")
            else:
                print(f"  ✓ CORS: Properly restricted")
        except Exception as e:
            print(f"  · CORS check skipped: {e}")

        # ── Phase 9: Redirect Analysis ─────────────────────────
        print("\n▸ Phase 9: Open Redirect Check...")
        redirect_params = ["redirect", "url", "next", "return", "returnUrl", "redirect_uri", "goto", "target"]
        for param in redirect_params:
            test_url = f"{target_url}?{param}=https://evil.com"
            try:
                r = await client.get(test_url, follow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("location", "")
                    if "evil.com" in location:
                        result.findings.append(Finding(
                            severity="medium",
                            title=f"Open Redirect via '{param}' parameter",
                            description=f"Parameter '{param}' allows redirection to external sites.",
                            url=test_url, category="open_redirect", cvss_score=6.1,
                            remediation="Validate redirect URLs against a whitelist.",
                        ))
                        print(f"  🚨 Open redirect: {param} → {location}")
                        break
            except:
                pass
        else:
            print(f"  ✓ No open redirects detected")

    # ── Finalize ──────────────────────────────────────────────
    result.completed_at = datetime.utcnow().isoformat() + "Z"
    result.status = "complete"
    result.total_findings = len(result.findings)

    # Count by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in result.findings:
        if f.severity in counts:
            counts[f.severity] += 1
    result.severity_counts = counts

    print(f"\n{'='*60}")
    print(f"  ✅ Scan Complete!")
    print(f"  Duration: {result.completed_at}")
    print(f"  Pages Probed: {result.pages_crawled}")
    print(f"  Total Findings: {result.total_findings}")
    print(f"  Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']} | Info: {counts['info']}")
    print(f"  Technologies: {', '.join(result.technologies) if result.technologies else 'None detected'}")
    print(f"  Headers Grade: {result.headers_grade}")
    print(f"{'='*60}\n")

    return result


async def main():
    result = await run_scan(TARGET_URL)

    # Save results as JSON for frontend consumption
    output = {
        "target": result.target,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "status": result.status,
        "technologies": result.technologies,
        "headers_grade": result.headers_grade,
        "ssl_info": result.ssl_info,
        "pages_crawled": result.pages_crawled,
        "total_findings": result.total_findings,
        "severity_counts": result.severity_counts,
        "findings": [asdict(f) for f in result.findings],
    }

    output_path = "scan_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"📄 Results saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
