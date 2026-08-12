"""
SentinelGraph — Standalone API Server

Lightweight FastAPI server that works WITHOUT PostgreSQL, Redis, or Docker.
Just install the minimal deps and run it!

Usage:
    pip install fastapi uvicorn httpx structlog jinja2
    python run_api.py

Endpoints:
    GET  /                      → API info
    GET  /health                → Health check  
    GET  /api/v1/results        → Latest scan results
    POST /api/v1/scan           → Start a new scan
    GET  /api/v1/scan/status    → Current scan status
    GET  /docs                  → Swagger UI
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, HttpUrl

logger = structlog.get_logger(__name__)

# ══════════════════════════════════════════════════════════════
# State (in-memory, no database needed)
# ══════════════════════════════════════════════════════════════
scan_state = {
    "status": "idle",  # idle, running, complete, failed
    "target": None,
    "started_at": None,
    "completed_at": None,
    "progress": 0,
    "current_phase": None,
    "result": None,
    "error": None,
}

DATA_DIR = Path(__file__).parent
RESULTS_FILE = DATA_DIR / "scan_results_full.json"
REPORT_FILE = DATA_DIR / "full_report.html"

# Load existing results if available
if RESULTS_FILE.exists():
    with open(RESULTS_FILE) as f:
        scan_state["result"] = json.load(f)
        scan_state["status"] = "complete"
        scan_state["target"] = scan_state["result"].get("target")
        scan_state["completed_at"] = scan_state["result"].get("completed_at")


# ══════════════════════════════════════════════════════════════
# Pydantic Models
# ══════════════════════════════════════════════════════════════
class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "full"  # "quick" or "full"
    max_depth: int = 5
    timeout: int = 15


class ScanStatus(BaseModel):
    status: str
    target: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    progress: int = 0
    current_phase: Optional[str] = None
    total_findings: int = 0
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════
# Background Scan Task
# ══════════════════════════════════════════════════════════════
async def run_scan_task(target_url: str, scan_type: str):
    """Run scan in background."""
    global scan_state
    
    scan_state["status"] = "running"
    scan_state["target"] = target_url
    scan_state["started_at"] = datetime.utcnow().isoformat() + "Z"
    scan_state["progress"] = 0
    scan_state["error"] = None

    try:
        if scan_type == "full":
            # Import and run the full scanner
            sys.path.insert(0, str(DATA_DIR))
            from full_scanner import FullScanner
            scanner = FullScanner()
            result = await scanner.scan(target_url)
        else:
            # Quick scanner
            from scanner import run_scan
            result = await run_scan(target_url)

        # Save results
        with open(RESULTS_FILE, "w") as f:
            json.dump(result, f, indent=2, default=str)

        # Generate HTML report
        from app.engine.report.generator import ReportGenerator
        ReportGenerator.generate_html(result, str(REPORT_FILE))

        scan_state["status"] = "complete"
        scan_state["completed_at"] = datetime.utcnow().isoformat() + "Z"
        scan_state["progress"] = 100
        scan_state["result"] = result
        logger.info("scan.complete", target=target_url, findings=result.get("total_findings", 0))

    except Exception as e:
        scan_state["status"] = "failed"
        scan_state["error"] = str(e)
        logger.error("scan.failed", target=target_url, error=str(e))


# ══════════════════════════════════════════════════════════════
# FastAPI App
# ══════════════════════════════════════════════════════════════
app = FastAPI(
    title="SentinelGraph API",
    description="AI-Powered Web Application Security Assessment Platform",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── System Routes ────────────────────────────────────────────
@app.get("/", tags=["System"])
async def root():
    return {
        "name": "SentinelGraph API",
        "version": "0.1.0",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "scan": "POST /api/v1/scan",
            "status": "GET /api/v1/scan/status",
            "results": "GET /api/v1/results",
            "report": "GET /api/v1/report",
        },
    }



@app.get("/health", tags=["System"])
async def health():
    return {"status": "healthy", "service": "SentinelGraph", "version": "0.1.0"}


# ── Config Routes ────────────────────────────────────────────
# In-memory config that can be updated via API
app_config = {
    "ai_mode": os.environ.get("AI_MODE", "rule_based"),
    "hf_model": os.environ.get("HF_MODEL_NAME", "mistralai/Mistral-7B-Instruct-v0.3"),
    "max_rps": int(os.environ.get("MAX_REQUESTS_PER_SECOND", "10")),
    "max_depth": int(os.environ.get("MAX_CRAWL_DEPTH", "10")),
    "timeout": int(os.environ.get("DEFAULT_REQUEST_TIMEOUT", "30")),
    "user_agent": os.environ.get("USER_AGENT", "SentinelGraph/0.1.0 (Security Assessment)"),
}

# Load .env file if it exists
_env_file = DATA_DIR.parent / ".env"
if _env_file.exists():
    with open(_env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())


@app.get("/api/v1/config", tags=["Configuration"])
async def get_config():
    """Get current configuration and token status."""
    hf_token = os.environ.get("HF_API_TOKEN", "")
    return {
        "ai_mode": app_config["ai_mode"],
        "hf_token_configured": bool(hf_token and len(hf_token) > 5),
        "hf_model": app_config["hf_model"],
        "max_rps": app_config["max_rps"],
        "max_depth": app_config["max_depth"],
        "timeout": app_config["timeout"],
        "user_agent": app_config["user_agent"],
    }


@app.post("/api/v1/config", tags=["Configuration"])
async def update_config(config: dict):
    """Update configuration."""
    if "ai_mode" in config:
        app_config["ai_mode"] = config["ai_mode"]
    if "hf_token" in config and config["hf_token"]:
        os.environ["HF_API_TOKEN"] = config["hf_token"]
    if "hf_model" in config:
        app_config["hf_model"] = config["hf_model"]
    if "max_rps" in config:
        app_config["max_rps"] = config["max_rps"]
    if "max_depth" in config:
        app_config["max_depth"] = config["max_depth"]
    if "timeout" in config:
        app_config["timeout"] = config["timeout"]
    if "user_agent" in config:
        app_config["user_agent"] = config["user_agent"]
    return {"status": "updated", "config": app_config}


# ── Scan Routes ──────────────────────────────────────────────
@app.post("/api/v1/scan", tags=["Scanning"])
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan."""
    if scan_state["status"] == "running":
        raise HTTPException(400, "A scan is already running. Wait for it to complete.")

    background_tasks.add_task(run_scan_task, req.target_url, req.scan_type)
    
    return {
        "message": "Scan started",
        "target": req.target_url,
        "scan_type": req.scan_type,
        "status_url": "/api/v1/scan/status",
    }


@app.get("/api/v1/scan/status", tags=["Scanning"], response_model=ScanStatus)
async def scan_status():
    """Get current scan status."""
    return ScanStatus(
        status=scan_state["status"],
        target=scan_state["target"],
        started_at=scan_state["started_at"],
        completed_at=scan_state["completed_at"],
        progress=scan_state["progress"],
        current_phase=scan_state["current_phase"],
        total_findings=scan_state["result"].get("total_findings", len(scan_state["result"].get("findings", []))) if scan_state["result"] else 0,
        error=scan_state["error"],
    )


# ── Results Routes ───────────────────────────────────────────
@app.get("/api/v1/results", tags=["Results"])
async def get_results():
    """Get latest scan results."""
    if not scan_state["result"]:
        if RESULTS_FILE.exists():
            with open(RESULTS_FILE) as f:
                return json.load(f)
        raise HTTPException(404, "No scan results available. Run a scan first.")
    return scan_state["result"]


@app.get("/api/v1/results/findings", tags=["Results"])
async def get_findings(
    severity: Optional[str] = None,
    category: Optional[str] = None,
):
    """Get findings with optional filters."""
    if not scan_state["result"]:
        raise HTTPException(404, "No results available.")

    findings = scan_state["result"].get("findings", [])
    
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if category:
        findings = [f for f in findings if f.get("category") == category]
    
    return {"total": len(findings), "findings": findings}


@app.get("/api/v1/results/summary", tags=["Results"])
async def get_summary():
    """Get scan summary statistics."""
    if not scan_state["result"]:
        raise HTTPException(404, "No results available.")
    
    r = scan_state["result"]
    return {
        "target": r.get("target"),
        "status": r.get("status"),
        "duration": r.get("duration_seconds"),
        "technologies": r.get("technologies"),
        "headers_grade": r.get("headers_grade"),
        "ssl_info": r.get("ssl_info"),
        "severity_counts": r.get("severity_counts"),
        "total_findings": r.get("total_findings"),
        "urls_discovered": r.get("urls_discovered"),
        "parameters_found": r.get("parameters_found"),
    }


# ── Report Routes ────────────────────────────────────────────
@app.get("/api/v1/report", tags=["Reports"])
async def get_report():
    """Get HTML report."""
    if REPORT_FILE.exists():
        return FileResponse(str(REPORT_FILE), media_type="text/html", filename="sentinelgraph_report.html")
    raise HTTPException(404, "No report generated yet. Run a scan first.")


@app.get("/api/v1/report/sarif", tags=["Reports"])
async def get_sarif():
    """Get SARIF report for CI/CD integration."""
    sarif_file = DATA_DIR / "cyberhackathon_report.sarif"
    if sarif_file.exists():
        return FileResponse(str(sarif_file), media_type="application/json", filename="sentinelgraph.sarif")
    raise HTTPException(404, "No SARIF report available.")


# ══════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print()
    print("=" * 60)
    print("  🛡️  SentinelGraph API Server")
    print("  http://localhost:8000")
    print("  Swagger Docs: http://localhost:8000/docs")
    print("=" * 60)
    print()
    
    uvicorn.run(
        "run_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
