"""
SentinelGraph — Celery Application

Distributed task queue for scan orchestration.
Defines the Celery app, task routing, and configuration.
"""

from celery import Celery

from app.config import get_settings

settings = get_settings()

# ── Celery App ───────────────────────────────────────────────
celery_app = Celery(
    "sentinelgraph",
    broker=settings.effective_celery_broker_url,
    backend=settings.celery_result_backend or settings.effective_celery_broker_url.replace("/1", "/2"),
)

# ── Configuration ────────────────────────────────────────────
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task execution
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,

    # Result backend
    result_expires=86400,  # 24 hours

    # Task routing
    task_routes={
        "workers.tasks.recon_tasks.*": {"queue": "recon_queue"},
        "workers.tasks.scan_tasks.*": {"queue": "scan_queue"},
        "workers.tasks.verification_tasks.*": {"queue": "scan_queue"},
        "workers.tasks.evidence_tasks.*": {"queue": "evidence_queue"},
        "workers.tasks.ai_tasks.*": {"queue": "ai_queue"},
        "workers.tasks.report_tasks.*": {"queue": "report_queue"},
    },

    # Default queue
    task_default_queue="scan_queue",

    # Retry settings
    task_default_retry_delay=60,
    task_max_retries=3,

    # Rate limiting (per worker)
    worker_concurrency=4,

    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)

# ── Auto-discover tasks ─────────────────────────────────────
celery_app.autodiscover_tasks(["workers.tasks"])
