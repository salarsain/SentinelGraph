"""
SentinelGraph — API Router

Central router that mounts all v1 API route modules.
"""

from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.scopes import router as scopes_router
from app.api.v1.scans import router as scans_router
from app.api.v1.websocket import router as ws_router

# ── V1 API Router ────────────────────────────────────────────
api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth_router)
api_v1_router.include_router(scopes_router)
api_v1_router.include_router(scans_router)
api_v1_router.include_router(ws_router)

# Future routes will be mounted here:
# api_v1_router.include_router(targets_router)
# api_v1_router.include_router(scans_router)
# api_v1_router.include_router(findings_router)
# api_v1_router.include_router(reports_router)
# api_v1_router.include_router(assets_router)
# api_v1_router.include_router(ai_router)
# api_v1_router.include_router(schedules_router)
