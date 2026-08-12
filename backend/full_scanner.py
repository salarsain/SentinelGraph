"""
SentinelGraph — Full Orchestrated Scanner

Integrates all engine modules into a complete scanning pipeline:
1. Initial probe + technology fingerprinting
2. Web crawling + form/parameter discovery
3. Passive security analysis (headers, cookies, content)
4. Active security probes (XSS, SQLi, CSRF, SSRF, etc.)
5. Vulnerability correlation
6. Risk scoring
7. Report generation
"""

import asyncio
import json
import re
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

import httpx
import structlog

from app.engine.detection.active_probes import ActiveProbeEngine, ProbeResult
from app.engine.detection.correlation import VulnerabilityCorrelationEngine
from app.engine.risk.scoring import RiskEngine
from app.engine.report.generator import ReportGenerator

logger = structlog.get_logger(__name__)

USER_AGENT = "SentinelGraph/0.1.0 (Authorized Security Assessment)"
MAX_CRAWL_DEPTH = 5
MAX_URLS = 50
TIMEOUT = 15


# ══════════════════════════════════════════════════════════════
# SECURITY HEADER DEFINITIONS
# ══════════════════════════════════════════════════════════════
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "medium", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    "content-security-policy": ("CSP", "medium", "Implement a strict Content-Security-Policy to prevent XSS."),
    "x-content-type-options": ("X-Content-Type-Options", "low", "Add: X-Content-Type-Options: nosniff"),
    "x-frame-options": ("X-Frame-Options", "medium", "Add: X-Frame-Options: DENY or SAMEORIGIN"),
    "permissions-policy": ("Permissions-Policy", "low", "Add Permissions-Policy to control browser features."),
    "referrer-policy": ("Referrer-Policy", "low", "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    "cross-origin-opener-policy": ("COOP", "info", "Add: Cross-Origin-Opener-Policy: same-origin"),
    "cross-origin-resource-policy": ("CORP", "info", "Add: Cross-Origin-Resource-Policy: same-origin"),
}

TECH_SIGS = [
    ("server", "nginx", "Nginx"), ("server", "apache", "Apache"), ("server", "cloudflare", "Cloudflare"),
    ("server", "gunicorn", "Gunicorn"), ("x-powered-by", "php", "PHP"), ("x-powered-by", "express", "Express.js"),
    ("x-powered-by", "asp.net", "ASP.NET"),
]

HTML_TECH_SIGS = [
    (r'/wp-content/', "WordPress"), (r'__NEXT_DATA__', "Next.js"), (r'react-dom', "React"),
    (r'ng-version', "Angular"), (r'__vue__', "Vue.js"), (r'jquery.*\.min\.js', "jQuery"),
    (r'bootstrap.*\.min\.(js|css)', "Bootstrap"), (r'tailwindcss', "Tailwind CSS"),
    (r'csrfmiddlewaretoken', "Django"), (r'laravel', "Laravel"),
]

SENSITIVE_PATHS = [
    ("/.git/HEAD", "Git Repository Exposed", "critical"),
    ("/.env", "Environment File Exposed", "critical"),
    ("/robots.txt", "Robots.txt", "info"),
    ("/sitemap.xml", "Sitemap", "info"),
    ("/.well-known/security.txt", "Security.txt", "info"),
    ("/phpinfo.php", "PHP Info Page", "medium"),
    ("/admin", "Admin Panel", "info"),
    ("/debug", "Debug Endpoint", "medium"),
    ("/.svn/entries", "SVN Exposed", "high"),
    ("/swagger.json", "Swagger Spec", "low"),
    ("/graphql", "GraphQL Endpoint", "low"),
    ("/api/", "API Endpoint", "info"),
]

COOKIE_SENSITIVE = ["session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf",
                    "phpsessid", "jsessionid", "connect.sid", "laravel_session"]


# ══════════════════════════════════════════════════════════════
# FULL SCANNER
# ══════════════════════════════════════════════════════════════
class FullScanner:
    """Complete scanning pipeline orchestrator."""

    def __init__(self):
        self.active_probes = ActiveProbeEngine()
        self.correlator = VulnerabilityCorrelationEngine()
        self.risk_engine = RiskEngine()
        self.report_gen = ReportGenerator()

    async def scan(self, target_url: str, config: dict = None) -> dict:
        """Run complete scan pipeline."""
        config = config or {}
        scan_start = datetime.utcnow()
        findings = []
        technologies = set()
        pages_crawled = 0
        discovered_urls = set()
        discovered_params = {}

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        logger.info("scan.start", target=target_url)
        print(f"\n{'='*70}")
        print(f"  🛡️  SentinelGraph — Full Security Assessment")
        print(f"  Target: {target_url}")
        print(f"  Started: {scan_start.isoformat()}Z")
        print(f"{'='*70}\n")

        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:

            # ── Phase 1: Initial Probe ────────────────────────
            print("▸ Phase 1: Initial Probe + Fingerprinting...")
            try:
                resp = await client.get(target_url)
                pages_crawled += 1
                print(f"  ✓ {resp.status_code} — {len(resp.text)} bytes")
            except Exception as e:
                print(f"  ✗ Failed: {e}")
                return {"status": "failed", "error": str(e)}

            # Technology fingerprinting
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for h, pattern, tech in TECH_SIGS:
                if pattern in headers_lower.get(h, "").lower():
                    technologies.add(tech)
                    print(f"  ✓ Tech: {tech}")

            for pattern, tech in HTML_TECH_SIGS:
                if re.search(pattern, resp.text, re.I):
                    technologies.add(tech)
                    print(f"  ✓ Tech: {tech}")

            # ── Phase 2: Security Headers ─────────────────────
            print("\n▸ Phase 2: Security Headers...")
            present = 0
            for hdr, (name, sev, rem) in SECURITY_HEADERS.items():
                if hdr in headers_lower:
                    present += 1
                else:
                    findings.append({"severity": sev, "title": f"Missing: {name}", "description": f"{name} header not set.",
                        "url": target_url, "category": "security_header", "evidence": {"header": hdr}, "remediation": rem, "confidence": 0.95})

            total_h = len(SECURITY_HEADERS)
            ratio = present / total_h
            grade = "A+" if ratio >= 0.9 else "A" if ratio >= 0.8 else "B" if ratio >= 0.7 else "C" if ratio >= 0.5 else "D" if ratio >= 0.3 else "F"
            print(f"  Headers Grade: {grade} ({present}/{total_h})")

            # Info leak headers
            for leak in ["server", "x-powered-by", "x-aspnet-version"]:
                if leak in headers_lower:
                    findings.append({"severity": "low", "title": f"Info Disclosure: {leak}",
                        "description": f"'{leak}' reveals: {headers_lower[leak]}", "url": target_url,
                        "category": "info_disclosure", "evidence": {"header": leak, "value": headers_lower[leak]},
                        "remediation": f"Remove '{leak}' header.", "confidence": 0.9})

            # ── Phase 3: Cookie Analysis ──────────────────────
            print("\n▸ Phase 3: Cookie Analysis...")
            cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
            for cookie_hdr in cookies:
                parts = cookie_hdr.split(";")
                name = parts[0].split("=")[0].strip()
                flags = {p.strip().lower().split("=")[0] for p in parts[1:]}
                is_sensitive = any(s in name.lower() for s in COOKIE_SENSITIVE)

                if parsed.scheme == "https" and "secure" not in flags:
                    findings.append({"severity": "medium" if is_sensitive else "low", "title": f"Cookie '{name}' Missing Secure",
                        "url": target_url, "category": "cookie", "description": f"Cookie '{name}' sent over HTTP.",
                        "evidence": {"cookie": name}, "remediation": f"Add Secure flag to '{name}'.", "confidence": 0.9})
                if is_sensitive and "httponly" not in flags:
                    findings.append({"severity": "medium", "title": f"Cookie '{name}' Missing HttpOnly",
                        "url": target_url, "category": "cookie", "description": f"Cookie '{name}' accessible to JS.",
                        "evidence": {"cookie": name}, "remediation": f"Add HttpOnly to '{name}'.", "confidence": 0.9})
                if "samesite" not in flags:
                    findings.append({"severity": "medium" if is_sensitive else "low", "title": f"Cookie '{name}' Missing SameSite",
                        "url": target_url, "category": "cookie", "description": f"Cookie '{name}' may enable CSRF.",
                        "evidence": {"cookie": name}, "remediation": f"Add SameSite=Lax to '{name}'.", "confidence": 0.85})

            # ── Phase 4: SSL/TLS ──────────────────────────────
            ssl_info = {}
            if parsed.scheme == "https":
                print("\n▸ Phase 4: SSL/TLS Analysis...")
                try:
                    ctx = ssl.create_default_context()
                    conn = ctx.wrap_socket(__import__('socket').socket(), server_hostname=parsed.hostname)
                    conn.settimeout(10)
                    conn.connect((parsed.hostname, 443))
                    cert = conn.getpeercert()
                    conn.close()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    ssl_info = {"issuer": issuer.get("organizationName", ""), "subject": subject.get("commonName", ""),
                                "valid_from": cert.get("notBefore", ""), "valid_to": cert.get("notAfter", "")}
                    print(f"  ✓ SSL: {ssl_info['issuer']} → {ssl_info['subject']}")
                except Exception as e:
                    print(f"  ⚠ SSL error: {e}")

            # ── Phase 5: Web Crawling ─────────────────────────
            print(f"\n▸ Phase 5: Web Crawling (max {MAX_URLS} URLs)...")
            discovered_urls.add(target_url)
            to_crawl = [target_url]
            crawled = set()

            while to_crawl and len(crawled) < MAX_URLS:
                url = to_crawl.pop(0)
                if url in crawled:
                    continue
                crawled.add(url)

                try:
                    r = await client.get(url)
                    pages_crawled += 1

                    # Extract links
                    links = re.findall(r'href=["\']([^"\'#]+)', r.text, re.I)
                    for link in links:
                        abs_url = urljoin(url, link)
                        abs_parsed = urlparse(abs_url)
                        if abs_parsed.netloc == parsed.netloc and abs_url not in discovered_urls:
                            discovered_urls.add(abs_url)
                            to_crawl.append(abs_url)

                    # Extract parameters from URLs and forms
                    qs = parse_qs(urlparse(url).query)
                    if qs:
                        discovered_params[url] = list(qs.keys())

                    form_params = re.findall(r'name=["\']([^"\']+)', r.text, re.I)
                    if form_params:
                        discovered_params.setdefault(url, []).extend(form_params)

                except Exception:
                    pass

            print(f"  ✓ Discovered: {len(discovered_urls)} URLs, {sum(len(v) for v in discovered_params.values())} parameters")

            # ── Phase 6: Sensitive Path Probing ───────────────
            print(f"\n▸ Phase 6: Sensitive Path Probing ({len(SENSITIVE_PATHS)} paths)...")

            async def probe_path(path, title, sev):
                try:
                    r = await client.get(f"{base_url}{path}", follow_redirects=False)
                    return (path, title, sev, r.status_code, len(r.text), r.text[:300])
                except:
                    return (path, title, sev, 0, 0, "")

            path_tasks = [probe_path(p, t, s) for p, t, s in SENSITIVE_PATHS]
            path_results = await asyncio.gather(*path_tasks)

            for path, title, sev, status, size, body in path_results:
                if status == 200 and size > 50:
                    if not any(x in body.lower() for x in ["not found", "404"]):
                        findings.append({"severity": sev, "title": f"{title} ({path})", "url": f"{base_url}{path}",
                            "category": "sensitive_path", "description": f"Accessible: {path} ({status}, {size}b)",
                            "evidence": {"status": status, "size": size}, "remediation": f"Restrict access to {path}.", "confidence": 0.85})
                        print(f"  ⚠ {path} → {status} ({size}b)")
                elif status == 403:
                    findings.append({"severity": "info", "title": f"{title} - Blocked ({path})", "url": f"{base_url}{path}",
                        "category": "sensitive_path", "description": f"{path} exists but blocked (403).",
                        "evidence": {"status": 403}, "remediation": "Verify access restrictions.", "confidence": 0.7})

            # ── Phase 7: Active Security Probes ───────────────
            print(f"\n▸ Phase 7: Active Security Probes...")
            active_findings = []

            for url, params in discovered_params.items():
                if params:
                    try:
                        results = await self.active_probes.run_all(client, url, params, resp.text)
                        for r in results:
                            active_findings.append(asdict(r))
                            print(f"  🚨 [{r.severity.upper()}] {r.title}")
                    except Exception as e:
                        logger.debug("active_probe.error", url=url, error=str(e))

            # Also run CORS and rate limit probes on main target
            try:
                cors_results = await self.active_probes.cors.probe(client, target_url)
                for r in cors_results:
                    active_findings.append(asdict(r))
                    print(f"  🚨 [{r.severity.upper()}] {r.title}")

                rate_results = await self.active_probes.rate_limit.probe(client, target_url)
                for r in rate_results:
                    active_findings.append(asdict(r))
                    print(f"  ⚠ [{r.severity.upper()}] {r.title}")
            except Exception:
                pass

            findings.extend(active_findings)

            # ── Phase 8: Passive Content Analysis ─────────────
            print(f"\n▸ Phase 8: Passive Content Analysis...")
            error_patterns = [
                (r"Traceback \(most recent call last\)", "Python stack trace", "medium"),
                (r"Fatal error:.*\.php", "PHP fatal error", "high"),
                (r"SQLSTATE\[\w+\]", "SQL error", "medium"),
            ]
            for pattern, name, sev in error_patterns:
                if re.search(pattern, resp.text, re.I):
                    findings.append({"severity": sev, "title": f"Error Disclosure: {name}",
                        "description": f"Response contains {name}.", "url": target_url,
                        "category": "info_disclosure", "remediation": "Use custom error pages.", "confidence": 0.9})
                    print(f"  ⚠ {name}")

            # Password autocomplete
            pwd_inputs = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', resp.text, re.I)
            for inp in pwd_inputs:
                if 'autocomplete="off"' not in inp.lower():
                    findings.append({"severity": "info", "title": "Password Autocomplete Enabled",
                        "description": "Password field allows autocomplete.", "url": target_url,
                        "category": "best_practice", "remediation": 'Add autocomplete="off".', "confidence": 0.8})
                    break

        # ── Phase 9: Vulnerability Correlation ────────────
        print(f"\n▸ Phase 9: Vulnerability Correlation...")
        correlated = self.correlator.correlate(findings)
        correlated_dicts = [asdict(f) if hasattr(f, '__dataclass_fields__') else f for f in correlated]
        print(f"  ✓ {len(findings)} → {len(correlated_dicts)} (after dedup/correlation)")

        # ── Phase 10: Risk Scoring ────────────────────────
        print(f"\n▸ Phase 10: Risk Scoring (CVSS + Context)...")
        risk_scores = self.risk_engine.score_all(correlated_dicts, technologies=list(technologies))
        print(f"  ✓ {len(risk_scores)} findings scored")

        # ── Compile Results ───────────────────────────────
        scan_end = datetime.utcnow()
        duration = (scan_end - scan_start).total_seconds()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in correlated_dicts:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        result = {
            "target": target_url,
            "started_at": scan_start.isoformat() + "Z",
            "completed_at": scan_end.isoformat() + "Z",
            "duration_seconds": round(duration, 1),
            "status": "complete",
            "technologies": list(technologies),
            "headers_grade": grade,
            "ssl_info": ssl_info,
            "pages_crawled": pages_crawled,
            "urls_discovered": len(discovered_urls),
            "parameters_found": sum(len(v) for v in discovered_params.values()),
            "total_findings": len(correlated_dicts),
            "severity_counts": severity_counts,
            "findings": correlated_dicts,
            "risk_scores": [asdict(rs) for rs in risk_scores],
        }

        print(f"\n{'='*70}")
        print(f"  ✅ Full Scan Complete!")
        print(f"  Duration: {duration:.1f}s")
        print(f"  URLs Discovered: {len(discovered_urls)}")
        print(f"  Parameters Found: {sum(len(v) for v in discovered_params.values())}")
        print(f"  Total Findings: {len(correlated_dicts)}")
        print(f"  Critical: {severity_counts['critical']} | High: {severity_counts['high']} | Medium: {severity_counts['medium']} | Low: {severity_counts['low']} | Info: {severity_counts['info']}")
        print(f"  Technologies: {', '.join(technologies) or 'None'}")
        print(f"  Headers Grade: {grade}")
        print(f"{'='*70}\n")

        return result


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "https://cyberhackathon.pk/admin/login/"
    scanner = FullScanner()
    result = await scanner.scan(target)

    with open("scan_results_full.json", "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"📄 Full results saved to: scan_results_full.json")

    # Generate reports
    ReportGenerator.generate_html(result, "full_report.html")
    print(f"📄 HTML report: full_report.html")


if __name__ == "__main__":
    asyncio.run(main())
