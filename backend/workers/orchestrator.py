"""
SentinelGraph — Scan Orchestrator

State machine that drives the end-to-end scan pipeline.
Manages scan phases, transitions, error handling, and progress reporting.
"""

import uuid
from enum import Enum

import structlog
from celery import chain, chord, group

logger = structlog.get_logger(__name__)


class ScanPhase(str, Enum):
    """Scan pipeline phases in execution order."""

    PENDING = "pending"
    SCOPE_VALIDATION = "scope_validation"
    RECONNAISSANCE = "reconnaissance"
    CRAWLING = "crawling"
    FINGERPRINTING = "fingerprinting"
    API_DISCOVERY = "api_discovery"
    SECURITY_TESTING = "security_testing"
    VERIFICATION = "verification"
    EVIDENCE_COLLECTION = "evidence_collection"
    CORRELATION = "correlation"
    AI_ANALYSIS = "ai_analysis"
    RISK_SCORING = "risk_scoring"
    REPORT_GENERATION = "report_generation"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Phase execution order (used by the state machine)
PHASE_ORDER = [
    ScanPhase.SCOPE_VALIDATION,
    ScanPhase.RECONNAISSANCE,
    ScanPhase.CRAWLING,
    ScanPhase.FINGERPRINTING,
    ScanPhase.API_DISCOVERY,
    ScanPhase.SECURITY_TESTING,
    ScanPhase.VERIFICATION,
    ScanPhase.EVIDENCE_COLLECTION,
    ScanPhase.CORRELATION,
    ScanPhase.AI_ANALYSIS,
    ScanPhase.RISK_SCORING,
    ScanPhase.REPORT_GENERATION,
]


class ScanOrchestrator:
    """Orchestrates the full scan pipeline as a Celery workflow.

    The orchestrator builds a Celery workflow (chain of tasks) that
    executes each scan phase in order. Some phases can run in parallel
    (e.g., fingerprinting and API discovery), which are modeled as groups.
    """

    def __init__(self, scan_id: uuid.UUID, scope_id: uuid.UUID):
        self.scan_id = str(scan_id)
        self.scope_id = str(scope_id)

    def build_workflow(self, config: dict | None = None):
        """Build the full Celery workflow for a scan.

        Returns a Celery chain that can be applied asynchronously.
        """
        from workers.tasks.recon_tasks import run_reconnaissance
        from workers.tasks.scan_tasks import (
            run_api_discovery,
            run_correlation,
            run_crawling,
            run_fingerprinting,
            run_risk_scoring,
            run_security_testing,
        )
        from workers.tasks.verification_tasks import run_verification
        from workers.tasks.evidence_tasks import run_evidence_collection
        from workers.tasks.ai_tasks import run_ai_analysis
        from workers.tasks.report_tasks import run_report_generation

        scan_args = {
            "scan_id": self.scan_id,
            "scope_id": self.scope_id,
            "config": config or {},
        }

        # Build the pipeline as a Celery chain
        # Some phases can run in parallel (group), then continue sequentially
        workflow = chain(
            # Phase 1: Reconnaissance
            run_reconnaissance.si(**scan_args),

            # Phase 2 & 3: Crawling → then Fingerprinting + API Discovery in parallel
            run_crawling.si(**scan_args),

            group(
                run_fingerprinting.si(**scan_args),
                run_api_discovery.si(**scan_args),
            ),

            # Phase 4: Security Testing
            run_security_testing.si(**scan_args),

            # Phase 5: Verification + Evidence Collection
            run_verification.si(**scan_args),
            run_evidence_collection.si(**scan_args),

            # Phase 6: Correlation → AI Analysis → Risk Scoring
            run_correlation.si(**scan_args),
            run_ai_analysis.si(**scan_args),
            run_risk_scoring.si(**scan_args),

            # Phase 7: Report Generation
            run_report_generation.si(**scan_args),
        )

        return workflow

    def start(self, config: dict | None = None) -> str:
        """Start the scan workflow.

        Returns the Celery task ID of the chain.
        """
        workflow = self.build_workflow(config)
        result = workflow.apply_async()

        logger.info(
            "orchestrator.scan_started",
            scan_id=self.scan_id,
            scope_id=self.scope_id,
            task_id=result.id,
        )

        return result.id
