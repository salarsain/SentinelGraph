"""
SentinelGraph — Vulnerability Correlation Engine

Correlates multiple findings to reduce false positives,
detect compound vulnerabilities, and adjust confidence scores.
"""

from dataclasses import dataclass, field
from collections import defaultdict

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class CorrelatedFinding:
    """A finding enriched with correlation data."""
    id: str
    severity: str
    title: str
    description: str
    url: str
    category: str
    confidence: float
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cvss_score: float | None = None
    correlated_with: list = field(default_factory=list)
    confidence_adjustment: float = 0.0
    chain_id: str | None = None
    is_duplicate: bool = False
    original_finding_id: str | None = None


class VulnerabilityCorrelationEngine:
    """
    Multi-layer correlation engine:
    1. Deduplication — merge duplicate findings
    2. Category correlation — boost confidence when related findings appear together
    3. Chain detection — identify compound vulnerability chains
    4. Context adjustment — adjust severity based on technology/asset context
    """

    # Findings that strengthen each other when co-occurring
    CORRELATION_RULES = {
        ("xss", "security_header"):  0.15,   # XSS + missing CSP = higher confidence
        ("sqli", "info_disclosure"): 0.10,    # SQLi + error disclosure = confirmed
        ("csrf", "cookie"):          0.10,    # CSRF + weak cookies = higher risk
        ("ssrf", "info_disclosure"): 0.10,    # SSRF + internal info = confirmed
        ("cors", "cookie"):          0.15,    # CORS + weak cookies = data theft
        ("xss", "cookie"):           0.10,    # XSS + no HttpOnly = session hijack
        ("ssti", "info_disclosure"): 0.15,    # SSTI + info leak = RCE path
    }

    # Vulnerability chains that indicate compound attacks
    CHAIN_PATTERNS = [
        {
            "name": "Session Hijacking Chain",
            "required": ["xss", "cookie"],
            "severity_override": "critical",
            "description": "XSS combined with weak cookie flags enables full session hijacking.",
        },
        {
            "name": "Data Exfiltration Chain",
            "required": ["cors", "cookie"],
            "severity_override": "high",
            "description": "CORS misconfiguration with weak cookies allows cross-origin data theft.",
        },
        {
            "name": "Server Compromise Chain",
            "required": ["ssti", "path_traversal"],
            "severity_override": "critical",
            "description": "Template injection with path traversal may enable remote code execution.",
        },
        {
            "name": "Authentication Bypass Chain",
            "required": ["sqli", "csrf"],
            "severity_override": "critical",
            "description": "SQL injection with missing CSRF protection enables unauthorized actions.",
        },
    ]

    def correlate(self, findings: list[dict]) -> list[CorrelatedFinding]:
        """Run full correlation pipeline."""
        logger.info("correlation.start", finding_count=len(findings))

        # Step 1: Convert and deduplicate
        correlated = self._deduplicate(findings)

        # Step 2: Category correlation
        correlated = self._correlate_categories(correlated)

        # Step 3: Chain detection
        correlated = self._detect_chains(correlated)

        # Step 4: Final confidence adjustment
        correlated = self._adjust_confidence(correlated)

        active = [f for f in correlated if not f.is_duplicate]
        logger.info("correlation.complete",
                     total=len(correlated),
                     active=len(active),
                     duplicates=len(correlated) - len(active))

        return active

    def _deduplicate(self, findings: list[dict]) -> list[CorrelatedFinding]:
        """Remove duplicate findings based on title + URL similarity."""
        seen = {}
        result = []

        for i, f in enumerate(findings):
            key = f"{f.get('category', '')}:{f.get('title', '')}:{f.get('url', '')}"
            fid = f"F-{i+1:04d}"

            cf = CorrelatedFinding(
                id=fid,
                severity=f.get("severity", "info"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                url=f.get("url", ""),
                category=f.get("category", ""),
                confidence=f.get("confidence", 0.5),
                evidence=f.get("evidence", {}),
                remediation=f.get("remediation", ""),
                cvss_score=f.get("cvss_score"),
            )

            if key in seen:
                cf.is_duplicate = True
                cf.original_finding_id = seen[key]
            else:
                seen[key] = fid

            result.append(cf)

        return result

    def _correlate_categories(self, findings: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
        """Boost confidence when correlated finding categories co-occur."""
        categories_present = set(f.category for f in findings if not f.is_duplicate)

        for f in findings:
            if f.is_duplicate:
                continue

            for (cat_a, cat_b), boost in self.CORRELATION_RULES.items():
                if f.category == cat_a and cat_b in categories_present:
                    f.confidence_adjustment += boost
                    related = [r.id for r in findings if r.category == cat_b and not r.is_duplicate]
                    f.correlated_with.extend(related)
                elif f.category == cat_b and cat_a in categories_present:
                    f.confidence_adjustment += boost * 0.5  # Secondary gets half boost

        return findings

    def _detect_chains(self, findings: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
        """Detect compound vulnerability chains."""
        categories_present = set(f.category for f in findings if not f.is_duplicate)

        for chain in self.CHAIN_PATTERNS:
            required = set(chain["required"])
            if required.issubset(categories_present):
                chain_id = chain["name"].replace(" ", "_").lower()

                # Mark all findings in this chain
                for f in findings:
                    if f.is_duplicate:
                        continue
                    if f.category in required:
                        f.chain_id = chain_id
                        f.confidence_adjustment += 0.1

                        # Escalate severity if chain pattern matches
                        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                        chain_sev = severity_order.get(chain["severity_override"], 0)
                        current_sev = severity_order.get(f.severity, 0)
                        if chain_sev > current_sev:
                            f.severity = chain["severity_override"]
                            f.description += f" [Part of {chain['name']}]"

                logger.info("chain.detected", chain=chain["name"], categories=list(required))

        return findings

    def _adjust_confidence(self, findings: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
        """Apply final confidence adjustments (cap at 0.99)."""
        for f in findings:
            f.confidence = min(0.99, f.confidence + f.confidence_adjustment)
        return findings
