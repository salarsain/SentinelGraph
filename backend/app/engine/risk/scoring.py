"""
SentinelGraph — Risk Scoring & CVSS Engine

Calculates contextual risk scores combining CVSS 3.1 base scores
with environmental context, technology stack, and exploitability factors.
"""

from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class RiskScore:
    """Complete risk assessment for a finding."""
    finding_id: str
    cvss_base: float
    cvss_vector: str
    contextual_score: float
    exploitability_factor: float
    asset_importance: float
    final_risk_score: float
    risk_level: str  # critical, high, medium, low, info
    breakdown: dict = field(default_factory=dict)


class CVSSCalculator:
    """
    CVSS 3.1 Base Score calculator.
    Provides pre-defined vectors for common vulnerability types.
    """

    # Pre-defined CVSS vectors for common finding types
    VECTORS = {
        "xss": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "base": 6.1,
        },
        "sqli": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base": 9.8,
        },
        "csrf": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "base": 4.3,
        },
        "ssrf": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
            "base": 7.5,
        },
        "ssti": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base": 9.8,
        },
        "path_traversal": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "base": 7.5,
        },
        "open_redirect": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "base": 6.1,
        },
        "cors": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
            "base": 7.4,
        },
        "security_header": {
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "base": 3.1,
        },
        "cookie": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "base": 4.3,
        },
        "info_disclosure": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "base": 5.3,
        },
        "rate_limiting": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "base": 5.3,
        },
        "sensitive_path": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "base": 5.3,
        },
        "encryption": {
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "base": 7.4,
        },
        "debug": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "base": 7.5,
        },
    }

    def get_base_score(self, category: str) -> tuple[float, str]:
        """Get CVSS base score and vector for a category."""
        info = self.VECTORS.get(category, {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "base": 0.0})
        return info["base"], info["vector"]


class RiskEngine:
    """
    Contextual risk scoring engine.
    Combines CVSS base score with:
    - Technology context (framework-specific risk modifiers)
    - Asset importance (auth endpoints > static pages)
    - Exploitability (verified findings score higher)
    - Environmental factors (internet-facing, data sensitivity)
    """

    TECH_MODIFIERS = {
        "Django": {"csrf": -0.5, "xss": -0.3},       # Django has built-in CSRF/XSS protection
        "React": {"xss": -0.3},                        # React auto-escapes JSX
        "Angular": {"xss": -0.3},                      # Angular sanitizes by default
        "WordPress": {"sqli": 0.2, "xss": 0.2},        # WP plugins often vulnerable
        "PHP": {"sqli": 0.1, "path_traversal": 0.1},   # PHP has historical issues
        "Express.js": {"ssrf": 0.1},                    # Node apps often fetch URLs
    }

    ASSET_IMPORTANCE = {
        "login": 1.3,
        "admin": 1.4,
        "api": 1.2,
        "auth": 1.3,
        "payment": 1.5,
        "checkout": 1.5,
        "account": 1.3,
        "settings": 1.2,
        "dashboard": 1.1,
        "register": 1.2,
    }

    def __init__(self):
        self.cvss = CVSSCalculator()

    def calculate_risk(
        self,
        finding: dict,
        technologies: list[str] = None,
        is_verified: bool = False,
        is_internet_facing: bool = True,
    ) -> RiskScore:
        """Calculate contextual risk score for a finding."""
        category = finding.get("category", "")
        url = finding.get("url", "")
        confidence = finding.get("confidence", 0.5)

        # 1. Base CVSS score
        cvss_base, cvss_vector = self.cvss.get_base_score(category)
        if finding.get("cvss_score"):
            cvss_base = finding["cvss_score"]

        # 2. Technology modifier
        tech_modifier = 0.0
        for tech in (technologies or []):
            mods = self.TECH_MODIFIERS.get(tech, {})
            tech_modifier += mods.get(category, 0.0)

        # 3. Asset importance
        asset_factor = 1.0
        url_lower = url.lower()
        for keyword, importance in self.ASSET_IMPORTANCE.items():
            if keyword in url_lower:
                asset_factor = max(asset_factor, importance)
                break

        # 4. Exploitability
        exploit_factor = 1.0
        if is_verified:
            exploit_factor = 1.2
        elif confidence >= 0.8:
            exploit_factor = 1.1
        elif confidence < 0.5:
            exploit_factor = 0.8

        # 5. Environmental
        env_factor = 1.1 if is_internet_facing else 0.9

        # Calculate final score
        adjusted = cvss_base + tech_modifier
        contextual = adjusted * asset_factor * exploit_factor * env_factor
        final = min(10.0, max(0.0, round(contextual, 1)))

        # Determine risk level
        if final >= 9.0:
            risk_level = "critical"
        elif final >= 7.0:
            risk_level = "high"
        elif final >= 4.0:
            risk_level = "medium"
        elif final >= 0.1:
            risk_level = "low"
        else:
            risk_level = "info"

        return RiskScore(
            finding_id=finding.get("id", ""),
            cvss_base=cvss_base,
            cvss_vector=cvss_vector,
            contextual_score=round(adjusted, 1),
            exploitability_factor=exploit_factor,
            asset_importance=asset_factor,
            final_risk_score=final,
            risk_level=risk_level,
            breakdown={
                "cvss_base": cvss_base,
                "tech_modifier": tech_modifier,
                "asset_factor": asset_factor,
                "exploit_factor": exploit_factor,
                "env_factor": env_factor,
                "technologies": technologies or [],
            },
        )

    def score_all(
        self,
        findings: list[dict],
        technologies: list[str] = None,
    ) -> list[RiskScore]:
        """Score all findings."""
        scores = []
        for f in findings:
            score = self.calculate_risk(
                f,
                technologies=technologies,
                is_verified=f.get("verified", False),
            )
            scores.append(score)
        return scores
