import uuid
import re
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

from app.schemas.request import RepositoryAnalyzeRequest, RepositoryScanRequest
from app.services.pipeline.manager import PipelineManager, REPORTS_CACHE
from app.utils.progress import ProgressTracker
from app.utils.scan_state import ScanStateManager
from app.utils.history import HistoryManager
from app.utils.path_safety import get_safe_repository_path
from app.utils.cancel_manager import CancelManager

router = APIRouter(
    prefix="/repository",
    tags=["Scan & Analyze"],
)


@router.post("/analyze")
def analyze_repository(
    request: RepositoryAnalyzeRequest,
    background_tasks: BackgroundTasks,
    sync: bool = Query(False, description="If true, runs synchronously and waits for results. If false, runs in background.")
):
    """Triggers the full pipeline (clone + scan + scoring + report) for a repository."""
    if not request.repository_url and not request.repository_name and not request.local_path:
        raise HTTPException(
            status_code=400,
            detail="Either repository_url, repository_name, or local_path must be provided."
        )

    custom_path = None
    repo_name = request.repository_name
    repo_url = request.repository_url

    if request.local_path:
        local_path = Path(request.local_path)
        if not local_path.exists() or not local_path.is_dir():
            raise HTTPException(
                status_code=400,
                detail=f"Local path '{request.local_path}' does not exist or is not a directory."
            )
        custom_path = str(local_path.resolve())
        repo_name = local_path.name
        repo_url = f"Local Folder: {repo_name}"

    scan_id = str(uuid.uuid4())
    
    # Register state BEFORE starting the pipeline to prevent race conditions
    state_manager = ScanStateManager()
    state_manager.register_scan(
        scan_id, 
        repository_name=repo_name or "",
        repository_url=repo_url or ""
    )
    ProgressTracker().set_progress(scan_id, "QUEUED", 0, "Waiting for scan pipeline to start...")
    
    manager = PipelineManager()

    if sync:
        try:
            report = manager.run_pipeline(
                repository_url=repo_url if not request.local_path else None,
                repository_name=repo_name,
                scan_id=scan_id,
                custom_path=custom_path
            )
            return report.model_dump(mode="json")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        # Run in background
        background_tasks.add_task(
            manager.run_pipeline,
            repo_url if not request.local_path else None,
            repo_name,
            scan_id,
            custom_path
        )
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": "Security scan analysis pipeline triggered in background."
        }


@router.post("/scan")
def scan_repository(
    request: RepositoryScanRequest,
    background_tasks: BackgroundTasks,
    sync: bool = Query(False, description="If true, runs synchronously. If false, runs in background.")
):
    """Triggers security scans on an already cloned local repository."""
    scan_id = str(uuid.uuid4())
    
    # Register state BEFORE starting the pipeline
    state_manager = ScanStateManager()
    state_manager.register_scan(scan_id, repository_name=request.repository_name)
    ProgressTracker().set_progress(scan_id, "QUEUED", 0, "Waiting for local scan to start...")
    
    manager = PipelineManager()

    if sync:
        try:
            report = manager.run_pipeline(
                repository_name=request.repository_name,
                scan_id=scan_id
            )
            return {
                "scan_id": scan_id,
                "repository_name": request.repository_name,
                "findings": [f.model_dump(mode="json") for f in report.findings],
                "score": report.score.model_dump(mode="json")
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        background_tasks.add_task(
            manager.run_pipeline,
            None,
            request.repository_name,
            scan_id
        )
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan for '{request.repository_name}' triggered in background."
        }


@router.get("/progress/{scan_id}")
def get_scan_progress(scan_id: str):
    """Retrieves progress percentage and status for an ongoing background scan."""
    if not re.match(r"^[\w\-]+$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
        
    progress = ProgressTracker().get_progress(scan_id)
    return progress


@router.post("/cancel/{scan_id}")
def cancel_scan(scan_id: str):
    """Cancels an active background scan pipeline execution."""
    if not re.match(r"^[\w\-]+$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
        
    state = ScanStateManager().get_state(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan ID not found")
        
    status = state.get("status")
    if status in ["COMPLETED", "FAILED", "CANCELLED"]:
        return {"status": "error", "message": f"Scan is already in a terminal state: {status}"}
        
    CancelManager().cancel_scan(scan_id)
    # Immediately update state to CANCELLED
    ScanStateManager().update_state(
        scan_id=scan_id,
        status="CANCELLED",
        progress=100,
        stage="CANCELLED",
        message="Scan cancelled by user."
    )
    ProgressTracker().set_progress(scan_id, "CANCELLED", 100, "Scan cancelled by user.")
    return {"status": "cancelled", "message": "Scan cancellation request registered successfully."}


@router.get("/history/{repository_name}")
def get_repository_history(repository_name: str):
    """Retrieves comparative scan history metrics and deltas for a repository."""
    try:
        # Sanitize path to prevent traversal checks
        get_safe_repository_path(repository_name)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid repository name format (path traversal blocked)"
        )
        
    summary = HistoryManager().get_repository_history(repository_name)
    return summary


@router.get("/recent")
def get_recent_repositories():
    """Retrieves list of recently scanned repositories with their scores and timestamps."""
    history = HistoryManager()._load_history()
    recent_map = {}
    for entry in history:
        repo = entry.get("repository_name")
        if repo:
            recent_map[repo] = {
                "repository_name": repo,
                "repository_url": entry.get("repository_url", ""),
                "score": entry.get("score", 100),
                "timestamp": entry.get("timestamp", ""),
                "scan_id": entry.get("scan_id", "")
            }
            
    recent_list = list(recent_map.values())
    recent_list.sort(key=lambda x: x["timestamp"], reverse=True)
    return recent_list[:10]
