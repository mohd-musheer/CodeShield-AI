import threading
from typing import Dict, Any, List, Optional
from app.utils.scan_state import ScanStateManager

class ProgressTracker:
    """Thread-safe global tracker for scan progress and stage status mapping."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ProgressTracker, cls).__new__(cls)
                cls._instance._active_websockets = []
                cls._instance._state_manager = ScanStateManager()
            return cls._instance

    def _get_initial_stages(self) -> Dict[str, str]:
        return {
            "clone_or_upload": "pending",
            "repository_analysis": "pending",
            "dependency_detection": "pending",
            "smart_chunking": "pending",
            "static_scan": "pending",
            "ai_security_review": "pending",
            "cross_file_analysis": "pending",
            "security_scoring": "pending",
            "generate_report": "pending"
        }

    def _map_state_to_stages(self, status: str) -> Dict[str, str]:
        stages = self._get_initial_stages()
        sequence = [
            ("INITIALIZING", "clone_or_upload"),
            ("CLONING", "clone_or_upload"),
            ("LOADING", "repository_analysis"),
            ("ANALYZING", "dependency_detection"),
            ("CHUNKING", "smart_chunking"),
            ("STATIC_SCAN", "static_scan"),
            ("AI_SCAN", "ai_security_review"),
            ("REASONING", "cross_file_analysis"),
            ("SCORING", "security_scoring"),
            ("GENERATING_REPORT", "generate_report")
        ]

        if status == "COMPLETED":
            return {k: "completed" for k in stages}
        if status in ("FAILED", "CANCELLED"):
            # Mark all as completed up to failure, and mark failed
            return {k: "failed" for k in stages}

        active_stage = None
        for state_val, stage_val in sequence:
            if status == state_val:
                active_stage = stage_val
                break

        found_active = False
        for _, stage_val in sequence:
            if stage_val == active_stage:
                stages[stage_val] = "running"
                found_active = True
            elif not found_active:
                stages[stage_val] = "completed"
            else:
                stages[stage_val] = "pending"

        return stages

    def set_progress(
        self, 
        scan_id: str, 
        status: str, 
        percent: int, 
        message: str, 
        extra: Optional[Dict[str, Any]] = None
    ):
        """Sets the progress and stage representation, and persists to disk."""
        # Convert lowercase parameters to status-compatible uppercase
        status_upper = status.upper() if status else "QUEUED"
        
        # Flush to persistent ScanStateManager
        self._state_manager.update_state(
            scan_id=scan_id,
            status=status_upper,
            progress=percent,
            stage=status_upper,
            message=message,
            error=extra.get("error") if extra else None
        )
        print(f"[Scan Progress] {scan_id}: {status_upper} ({percent}%) - {message}")

    def get_progress(self, scan_id: str) -> Dict[str, Any]:
        """Retrieves progress, returning a structured representation for the frontend."""
        state = self._state_manager.get_state(scan_id)
        if not state:
            return {
                "status": "unknown",
                "percent": 0,
                "message": "Waiting for backend...",
                "stages": self._get_initial_stages()
            }

        status = state.get("status", "QUEUED")
        stages = self._map_state_to_stages(status)

        # Standardize representation for frontend (lowercase status for compatibility)
        return {
            "status": status.lower(),
            "percent": state.get("progress", 0),
            "message": state.get("message", "Processing..."),
            "stages": stages
        }

    def register_websocket(self, websocket):
        """Registers a websocket client."""
        with self._lock:
            self._active_websockets.append(websocket)

    def unregister_websocket(self, websocket):
        """Unregisters a websocket client."""
        with self._lock:
            if websocket in self._active_websockets:
                self._active_websockets.remove(websocket)
