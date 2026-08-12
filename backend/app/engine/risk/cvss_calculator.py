"""
SentinelGraph — CVSS 3.1 Calculator

Parses CVSS 3.1 vector strings and calculates base scores.
Adds contextual adjustments based on asset importance, exposure, and exploitability.
"""

import math
import re
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class CVSSScore:
    """Calculated CVSS score with breakdown."""
    vector: str
    base_score: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    impact_score: float
    exploitability_score: float
    contextual_score: float | None = None
    contextual_adjustments: dict[str, float] | None = None


# CVSS 3.1 metric values
CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},   # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},                            # Attack Complexity
    "PR": {                                                    # Privileges Required
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},                            # User Interaction
    "S":  {"U": "unchanged", "C": "changed"},                 # Scope
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},                 # Confidentiality
    "I":  {"H": 0.56, "L": 0.22, "N": 0.0},                 # Integrity
    "A":  {"H": 0.56, "L": 0.22, "N": 0.0},                 # Availability
}


class CVSSCalculator:
    """CVSS 3.1 base score calculator with contextual adjustments."""

    def calculate(self, vector: str) -> CVSSScore:
        """Calculate CVSS 3.1 base score from vector string.

        Args:
            vector: CVSS 3.1 vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")

        Returns:
            CVSSScore with base, impact, and exploitability scores
        """
        metrics = self._parse_vector(vector)

        # Get metric values
        av = CVSS_METRICS["AV"][metrics["AV"]]
        ac = CVSS_METRICS["AC"][metrics["AC"]]
        scope = CVSS_METRICS["S"][metrics["S"]]
        pr = CVSS_METRICS["PR"][metrics["PR"]][metrics["S"][0]]
        ui = CVSS_METRICS["UI"][metrics["UI"]]
        c = CVSS_METRICS["C"][metrics["C"]]
        i = CVSS_METRICS["I"][metrics["I"]]
        a = CVSS_METRICS["A"][metrics["A"]]

        # Calculate Impact Sub-Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact Score
        if scope == "unchanged":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        # Calculate Exploitability Score
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope == "unchanged":
            base_score = min(impact + exploitability, 10.0)
            base_score = math.ceil(base_score * 10) / 10
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
            base_score = math.ceil(base_score * 10) / 10

        severity = self._score_to_severity(base_score)

        return CVSSScore(
            vector=vector,
            base_score=base_score,
            severity=severity,
            impact_score=round(max(0, impact), 1),
            exploitability_score=round(exploitability, 1),
        )

    def calculate_contextual(
        self,
        vector: str,
        asset_importance: float = 1.0,
        exposure_level: float = 1.0,
        exploitability_factor: float = 1.0,
    ) -> CVSSScore:
        """Calculate CVSS score with contextual adjustments.

        Args:
            vector: CVSS 3.1 vector string
            asset_importance: Asset importance multiplier (0.5-2.0)
            exposure_level: Internet exposure factor (0.5-2.0)
            exploitability_factor: Known exploit availability (1.0-2.0)
        """
        score = self.calculate(vector)

        # Apply contextual adjustments
        adjustments = {
            "asset_importance": asset_importance,
            "exposure_level": exposure_level,
            "exploitability_factor": exploitability_factor,
        }

        contextual = score.base_score * (
            0.4 * asset_importance +
            0.3 * exposure_level +
            0.3 * exploitability_factor
        )

        score.contextual_score = min(10.0, round(contextual, 1))
        score.contextual_adjustments = adjustments

        return score

    @staticmethod
    def _parse_vector(vector: str) -> dict[str, str]:
        """Parse CVSS vector string into metric dict."""
        # Remove prefix
        clean = re.sub(r'^CVSS:3\.[01]/', '', vector)
        metrics = {}
        for part in clean.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        missing = required - set(metrics.keys())
        if missing:
            raise ValueError(f"Missing CVSS metrics: {missing}")

        return metrics

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert CVSS base score to severity rating."""
        if score == 0.0:
            return "NONE"
        elif score <= 3.9:
            return "LOW"
        elif score <= 6.9:
            return "MEDIUM"
        elif score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"
