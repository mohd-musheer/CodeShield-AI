import re
import json
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from app.api.routes.repository import router as repository_router
from app.api.routes.scan import router as scan_router
from app.api.routes.report import router as report_router
from app.api.routes.websocket import router as ws_router
from app.api.routes.health import router as health_router

from app.utils.progress import ProgressTracker
from app.utils.scan_state import ScanStateManager
from app.services.pipeline.manager import REPORTS_CACHE, REPORTS_CACHE_LOCK
from app.models.repository import ScanReport

app = FastAPI(
    title="CodeShield AI",
    description="AI-Powered Code Repository Security Analyzer",
    version="1.0.0"
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for local usability
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(repository_router)
app.include_router(scan_router)
app.include_router(report_router)
app.include_router(ws_router)
app.include_router(health_router)

# Mount the static files directory if it exists
static_path = Path("static")
static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
def startup_recovery():
    """On server start, recover completed scan states from disk and load reports into cache.
    
    This ensures that a server restart doesn't lose track of previously completed scans.
    Interrupted (non-terminal) scans are automatically marked as 'FAILED' by ScanStateManager.
    """
    print("[Startup] CodeShield AI server starting...")
    
    state_manager = ScanStateManager()
    completed_scans = state_manager.get_all_completed()
    
    recovered = 0
    for scan_state in completed_scans:
        scan_id = scan_state.get("scan_id")
        report_path = scan_state.get("report_path", "")
        
        if scan_id and report_path and scan_id not in REPORTS_CACHE:
            report_file = Path(report_path)
            if report_file.exists():
                try:
                    with open(report_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        report = ScanReport(**data)
                        with REPORTS_CACHE_LOCK:
                            REPORTS_CACHE[scan_id] = report
                        recovered += 1
                except Exception as e:
                    print(f"[Startup] Failed to recover report {scan_id}: {e}")
    
    # Clean up old state entries (older than 72 hours)
    state_manager.cleanup_old_states(max_age_hours=72)
    
    print(f"[Startup] Recovered {recovered} completed scan reports from disk")
    print("[Startup] Server ready.")


@app.get("/scan/status/{scan_id}")
def get_scan_status(scan_id: str):
    """Root-level scan status endpoint. Survives router reloads.
    
    This is the primary polling endpoint for frontend state synchronization.
    Returns current progress, status, and stage information for a scan.
    """
    if not re.match(r"^[\w\-]+$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    return ProgressTracker().get_progress(scan_id)


@app.get("/")
def read_root():
    """Serves the main frontend dashboard at the root path."""
    index_file = static_path / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {
        "message": "Welcome to CodeShield AI Backend. Frontend index.html not found yet. Place index.html in the 'static/' directory.",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "clone": "/repository/clone",
            "chunk": "/repository/chunk",
            "scan": "/repository/scan",
            "analyze": "/repository/analyze",
            "report": "/repository/report"
        }
    }