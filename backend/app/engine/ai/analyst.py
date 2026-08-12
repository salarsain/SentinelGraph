"""
SentinelGraph — AI Security Analyst (Hugging Face Transformers)

Uses Hugging Face models for finding analysis — NO OpenAI API needed.
Runs locally with transformers pipeline or via Hugging Face Inference API (free tier).
"""

from enum import Enum
from typing import Any
import json
import re

import structlog
from pydantic import BaseModel, Field

from app.config import get_settings
from app.models.finding import FindingSeverity

logger = structlog.get_logger(__name__)
settings = get_settings()


# ── Structured Output Models ────────────────────────────────
class FalsePositiveAssessment(str, Enum):
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    POSSIBLE_TRUE_POSITIVE = "possible_true_positive"
    UNCERTAIN = "uncertain"
    POSSIBLE_FALSE_POSITIVE = "possible_false_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


class AIAnalysisResult(BaseModel):
    """Structured output from AI analysis of a security finding."""

    is_valid_finding: bool = Field(
        description="Whether this appears to be a genuine security finding based on the evidence"
    )
    false_positive_assessment: FalsePositiveAssessment = Field(
        description="Assessment of false-positive likelihood"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="AI confidence in this assessment (0.0-1.0)"
    )
    severity_recommendation: FindingSeverity = Field(
        description="Recommended severity based on context analysis"
    )
    analysis: str = Field(
        description="Detailed analysis explaining the assessment"
    )
    evidence_quality: str = Field(
        description="Assessment of evidence quality: strong, moderate, weak, insufficient"
    )
    remediation_advice: str = Field(
        description="Specific remediation recommendation"
    )
    attack_scenario: str = Field(
        description="Brief description of how this vulnerability could be exploited"
    )
    related_weaknesses: list[str] = Field(
        default_factory=list,
        description="Related CWE IDs or vulnerability categories"
    )


# ── Prompt Templates ────────────────────────────────────────
ANALYSIS_PROMPT = """You are a web application security analyst. Analyze this security finding and respond with JSON only.

Finding:
- Type: {finding_type}
- Title: {title}
- Severity: {severity}
- URL: {url}
- Parameter: {parameter}
- Evidence: {evidence_text}
- Technology: {tech_context}

Respond with this exact JSON structure:
{{
    "is_valid_finding": true/false,
    "false_positive_assessment": "likely_true_positive" or "possible_true_positive" or "uncertain" or "possible_false_positive" or "likely_false_positive",
    "confidence": 0.0-1.0,
    "severity_recommendation": "critical" or "high" or "medium" or "low" or "info",
    "analysis": "your analysis here",
    "evidence_quality": "strong" or "moderate" or "weak" or "insufficient",
    "remediation_advice": "specific fix recommendation",
    "attack_scenario": "how this could be exploited",
    "related_weaknesses": ["CWE-79", "CWE-89"]
}}
"""

# ── Vulnerability Knowledge Base ─────────────────────────────
# Rule-based fallback when LLM is unavailable
VULN_KNOWLEDGE = {
    "sql_injection": {
        "severity": FindingSeverity.CRITICAL,
        "cwe": ["CWE-89"],
        "attack": "Attacker can inject SQL queries to read/modify/delete database data, bypass authentication, or execute OS commands.",
        "remediation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Use an ORM where possible.",
        "fp_indicators": ["error-based detection without confirmed injection", "WAF blocking payloads"],
    },
    "xss_stored": {
        "severity": FindingSeverity.HIGH,
        "cwe": ["CWE-79"],
        "attack": "Attacker stores malicious JavaScript that executes in other users' browsers, stealing sessions, credentials, or performing actions on their behalf.",
        "remediation": "Implement context-aware output encoding. Use Content-Security-Policy headers. Sanitize input on server-side.",
        "fp_indicators": ["reflected in attribute without breaking out", "encoded output"],
    },
    "xss_reflected": {
        "severity": FindingSeverity.MEDIUM,
        "cwe": ["CWE-79"],
        "attack": "Attacker crafts a URL with malicious JavaScript that executes when a victim clicks the link.",
        "remediation": "Apply output encoding appropriate to the HTML context. Implement CSP headers.",
        "fp_indicators": ["parameter reflected but HTML-encoded", "in JavaScript string but escaped"],
    },
    "cors_misconfiguration": {
        "severity": FindingSeverity.HIGH,
        "cwe": ["CWE-942"],
        "attack": "Attacker's site can make authenticated cross-origin requests, stealing sensitive data from the API.",
        "remediation": "Replace wildcard (*) with specific trusted origins. Never reflect the Origin header directly. Remove Access-Control-Allow-Credentials with wildcards.",
        "fp_indicators": ["credentials not allowed", "no sensitive data in response"],
    },
    "open_redirect": {
        "severity": FindingSeverity.MEDIUM,
        "cwe": ["CWE-601"],
        "attack": "Attacker can redirect users to phishing sites using the trusted domain, stealing credentials.",
        "remediation": "Validate redirect URLs against a whitelist. Use relative URLs only. Reject external URLs.",
        "fp_indicators": ["redirect only to same domain", "requires authentication"],
    },
    "missing_security_header": {
        "severity": FindingSeverity.MEDIUM,
        "cwe": ["CWE-693"],
        "attack": "Missing headers allow clickjacking, MIME sniffing, or downgrade attacks.",
        "remediation": "Add Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy headers.",
        "fp_indicators": [],
    },
    "debug_mode_enabled": {
        "severity": FindingSeverity.HIGH,
        "cwe": ["CWE-215"],
        "attack": "Debug mode exposes source code, environment variables, database credentials, and may allow interactive code execution.",
        "remediation": "Disable debug mode in production (DEBUG=False in Django, NODE_ENV=production in Node.js).",
        "fp_indicators": [],
    },
    "version_disclosure": {
        "severity": FindingSeverity.LOW,
        "cwe": ["CWE-200"],
        "attack": "Disclosed software versions help attackers identify known vulnerabilities and craft targeted exploits.",
        "remediation": "Remove or obfuscate version information from Server headers, X-Powered-By, and error pages.",
        "fp_indicators": [],
    },
    "sensitive_file": {
        "severity": FindingSeverity.HIGH,
        "cwe": ["CWE-538", "CWE-200"],
        "attack": "Exposed files (.env, .git, backups) may contain credentials, source code, or database dumps.",
        "remediation": "Block access to sensitive files via web server configuration. Remove backup files from web root.",
        "fp_indicators": ["custom 404 page returning 200", "generic error page"],
    },
    "cookie_insecure": {
        "severity": FindingSeverity.MEDIUM,
        "cwe": ["CWE-614", "CWE-1004"],
        "attack": "Cookies without Secure/HttpOnly flags can be stolen via XSS or man-in-the-middle attacks.",
        "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict on all session and authentication cookies.",
        "fp_indicators": [],
    },
}


class AISecurityAnalyst:
    """Security finding analyst using Hugging Face models.

    Supports three modes (auto-selected):
    1. Hugging Face Inference API (free tier, recommended)
    2. Local transformers pipeline (no network required)
    3. Rule-based knowledge base fallback (always available)
    """

    def __init__(self):
        self.mode = settings.ai_mode  # "huggingface_api", "local_transformers", "rule_based"
        self.model_name = settings.hf_model_name
        self.hf_api_token = settings.hf_api_token
        self._local_pipeline = None

    async def analyze_finding(
        self,
        finding_type: str,
        title: str,
        severity: str,
        url: str,
        parameter: str | None,
        evidence: dict[str, Any],
        tech_context: str = "",
        detection_module: str = "",
        detection_rule: str = "",
        status_code: int = 0,
        content_type: str = "",
    ) -> AIAnalysisResult:
        """Analyze a security finding.

        Attempts LLM analysis first, falls back to rule-based knowledge base.
        """
        logger.info("ai_analyst.analyzing", finding_type=finding_type, url=url, mode=self.mode)

        evidence_text = self._format_evidence(evidence)

        # Try LLM-based analysis first
        if self.mode == "huggingface_api":
            try:
                result = await self._analyze_huggingface_api(
                    finding_type, title, severity, url, parameter, evidence_text, tech_context
                )
                if result:
                    return self._validate_against_evidence(result, evidence)
            except Exception as e:
                logger.warning("ai_analyst.hf_api_failed", error=str(e))

        elif self.mode == "local_transformers":
            try:
                result = await self._analyze_local_transformers(
                    finding_type, title, severity, url, parameter, evidence_text, tech_context
                )
                if result:
                    return self._validate_against_evidence(result, evidence)
            except Exception as e:
                logger.warning("ai_analyst.local_failed", error=str(e))

        # Fallback: Rule-based analysis (always works, no API needed)
        return self._analyze_rule_based(finding_type, title, severity, url, parameter, evidence)

    async def _analyze_huggingface_api(
        self,
        finding_type: str, title: str, severity: str, url: str,
        parameter: str | None, evidence_text: str, tech_context: str,
    ) -> AIAnalysisResult | None:
        """Analyze using Hugging Face Inference API (free tier)."""
        import httpx

        prompt = ANALYSIS_PROMPT.format(
            finding_type=finding_type,
            title=title,
            severity=severity,
            url=url,
            parameter=parameter or "N/A",
            evidence_text=evidence_text[:1500],
            tech_context=tech_context or "Not detected",
        )

        headers = {}
        if self.hf_api_token:
            headers["Authorization"] = f"Bearer {self.hf_api_token}"

        api_url = f"https://api-inference.huggingface.co/models/{self.model_name}"

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                api_url,
                headers=headers,
                json={
                    "inputs": prompt,
                    "parameters": {
                        "max_new_tokens": 800,
                        "temperature": 0.1,
                        "return_full_text": False,
                    },
                },
            )

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    generated_text = data[0].get("generated_text", "")
                    return self._parse_llm_response(generated_text, finding_type, severity)
            else:
                logger.warning("ai_analyst.hf_api_error", status=response.status_code, body=response.text[:200])

        return None

    async def _analyze_local_transformers(
        self,
        finding_type: str, title: str, severity: str, url: str,
        parameter: str | None, evidence_text: str, tech_context: str,
    ) -> AIAnalysisResult | None:
        """Analyze using local Hugging Face transformers pipeline."""
        import asyncio

        if self._local_pipeline is None:
            from transformers import pipeline
            # Use a smaller model for local inference
            self._local_pipeline = pipeline(
                "text-generation",
                model=self.model_name,
                device_map="auto",
                torch_dtype="auto",
            )

        prompt = ANALYSIS_PROMPT.format(
            finding_type=finding_type,
            title=title,
            severity=severity,
            url=url,
            parameter=parameter or "N/A",
            evidence_text=evidence_text[:1000],
            tech_context=tech_context or "Not detected",
        )

        # Run in executor to avoid blocking event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self._local_pipeline(
                prompt,
                max_new_tokens=600,
                temperature=0.1,
                do_sample=True,
            ),
        )

        if result and len(result) > 0:
            text = result[0].get("generated_text", "")
            # Remove the prompt from the output
            if prompt in text:
                text = text[len(prompt):]
            return self._parse_llm_response(text, finding_type, severity)

        return None

    def _analyze_rule_based(
        self,
        finding_type: str, title: str, severity: str, url: str,
        parameter: str | None, evidence: dict[str, Any],
    ) -> AIAnalysisResult:
        """Rule-based analysis using vulnerability knowledge base.

        Always works — no API or model required.
        """
        knowledge = VULN_KNOWLEDGE.get(finding_type, {})

        # Determine severity from knowledge base
        kb_severity = knowledge.get("severity", FindingSeverity.MEDIUM)

        # Check for false positive indicators
        fp_indicators = knowledge.get("fp_indicators", [])
        evidence_str = json.dumps(evidence).lower()
        fp_matches = [ind for ind in fp_indicators if ind.lower() in evidence_str]

        if fp_matches:
            fp_assessment = FalsePositiveAssessment.POSSIBLE_FALSE_POSITIVE
            confidence = 0.5
        else:
            fp_assessment = FalsePositiveAssessment.LIKELY_TRUE_POSITIVE
            confidence = 0.75

        # Build analysis
        attack = knowledge.get("attack", f"This {finding_type} vulnerability could be exploited by an attacker.")
        remediation = knowledge.get("remediation", "Review and remediate this finding. Consult OWASP guidelines.")
        cwes = knowledge.get("cwe", [])

        # Determine evidence quality
        evidence_size = len(str(evidence))
        if evidence_size > 500:
            evidence_quality = "strong"
        elif evidence_size > 100:
            evidence_quality = "moderate"
        else:
            evidence_quality = "weak"
            confidence = min(confidence, 0.5)

        return AIAnalysisResult(
            is_valid_finding=fp_assessment != FalsePositiveAssessment.LIKELY_FALSE_POSITIVE,
            false_positive_assessment=fp_assessment,
            confidence=confidence,
            severity_recommendation=kb_severity,
            analysis=f"Rule-based analysis for {finding_type}: {title}. "
                     f"Found at {url}" + (f" via parameter '{parameter}'" if parameter else "") + ". "
                     f"Based on vulnerability knowledge base and evidence analysis.",
            evidence_quality=evidence_quality,
            remediation_advice=remediation,
            attack_scenario=attack,
            related_weaknesses=cwes,
        )

    def _parse_llm_response(
        self,
        text: str,
        finding_type: str,
        default_severity: str,
    ) -> AIAnalysisResult | None:
        """Parse LLM text response into structured AIAnalysisResult."""
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'\{[\s\S]*\}', text)
            if not json_match:
                return None

            data = json.loads(json_match.group())
            return AIAnalysisResult.model_validate(data)
        except (json.JSONDecodeError, Exception) as e:
            logger.debug("ai_analyst.parse_failed", error=str(e))
            return None

    def _validate_against_evidence(
        self,
        result: AIAnalysisResult,
        evidence: dict[str, Any],
    ) -> AIAnalysisResult:
        """Validate LLM output against evidence (hallucination check)."""
        evidence_size = len(str(evidence))
        if evidence_size < 100 and result.confidence > 0.7:
            result.confidence = min(result.confidence, 0.5)
            result.evidence_quality = "weak"

        quality_caps = {"strong": 1.0, "moderate": 0.85, "weak": 0.6, "insufficient": 0.4}
        quality = result.evidence_quality.lower()
        if quality in quality_caps:
            result.confidence = min(result.confidence, quality_caps[quality])

        return result

    @staticmethod
    def _format_evidence(evidence: dict[str, Any]) -> str:
        """Format evidence dict for prompt."""
        parts = []
        if "request" in evidence:
            parts.append(f"Request: {str(evidence['request'])[:500]}")
        if "response" in evidence:
            parts.append(f"Response: {str(evidence['response'])[:1000]}")
        if "match" in evidence:
            parts.append(f"Match: {evidence['match']}")
        if "headers" in evidence:
            parts.append(f"Headers: {str(evidence['headers'])[:300]}")
        return "\n".join(parts) if parts else "No detailed evidence."
