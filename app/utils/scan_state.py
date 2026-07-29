import json
import os
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List

from app.core.config import SCAN_STATE_DIR


class ScanStateManager:
    """Thread-safe state manager that persists scan lifecycle state to disk."""

    _instance = None
    _lock = threading.Lock()

    # Valid state machine states (forward-only, no skipping or going backwards)
    STATES_PIPELINE = [
        "QUEUED",
        "INITIALIZING",
        "CLONING",
        "LOADING",
        "ANALYZING",
        "CHUNKING",
        "STATIC_SCAN",
        "AI_SCAN",
        "REASONING",
        "SCORING",
        "GENERATING_REPORT",
        "COMPLETED"
    ]
    
    TERMINAL_STATES = {"COMPLETED", "FAILED", "CANCELLED"}

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._states: Dict[str, Dict[str, Any]] = {}
                cls._instance._file_lock = threading.Lock()
                cls._instance._state_file = Path(SCAN_STATE_DIR) / "scan_state.json"
                cls._instance._state_file.parent.mkdir(parents=True, exist_ok=True)
                cls._instance._load_from_disk()
            return cls._instance

    def _load_from_disk(self):
        """Loads scan states from disk on startup."""
        try:
            if self._state_file.exists():
                with open(self._state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._states = data
                        # Mark non-terminal scans as failed due to restart
                        for scan_id, state in self._states.items():
                            if state.get("status") not in self.TERMINAL_STATES:
                                state["status"] = "FAILED"
                                state["message"] = "Scan interrupted by server restart"
                                state["finished_at"] = time.time()
                        self._flush_to_disk()
        except Exception as e:
            print(f"[ScanStateManager] Error loading state from disk: {e}")
            self._states = {}

    def _flush_to_disk(self):
        """Flushes current state to disk."""
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._state_file, "w", encoding="utf-8") as f:
                json.dump(self._states, f, indent=2)
        except Exception as e:
            print(f"[ScanStateManager] Error flushing state to disk: {e}")


    def register_scan(self, scan_id: str, repository_name: str = "", repository_url: str = ""):
        """Registers a new scan in the QUEUED state."""
        with self._file_lock:
            self._states[scan_id] = {
                "scan_id": scan_id,
                "status": "QUEUED",
                "progress": 0,
                "stage": "QUEUED",
                "started_at": time.time(),
                "finished_at": None,
                "error": None,
                "report_path": "",
                "repository_name": repository_name,
                "repository_url": repository_url
            }
            self._flush_to_disk()

    def update_state(
        self,
        scan_id: str,
        status: str,
        progress: int,
        stage: str,
        message: str = "",
        error: Optional[str] = None,
        report_path: Optional[str] = None
    ):
        """Updates the state of a scan enforcing forward-only transitions."""
        with self._file_lock:
            state = self._states.get(scan_id)
            if not state:
                # Register if not exists
                state = {
                    "scan_id": scan_id,
                    "status": "QUEUED",
                    "progress": 0,
                    "stage": "QUEUED",
                    "started_at": time.time(),
                    "finished_at": None,
                    "error": None,
                    "report_path": "",
                    "repository_name": "",
                    "repository_url": ""
                }
                self._states[scan_id] = state

            current_status = state["status"]
            if current_status in self.TERMINAL_STATES:
                # Do not transition out of terminal state
                return

            # Check if transition is valid (no backwards movement)
            if current_status in self.STATES_PIPELINE and status in self.STATES_PIPELINE:
                curr_idx = self.STATES_PIPELINE.index(current_status)
                new_idx = self.STATES_PIPELINE.index(status)
                if new_idx < curr_idx:
                    # Do not allow moving backward in the pipeline
                    return

            state["status"] = status
            state["progress"] = progress
            state["stage"] = stage
            state["message"] = message

            if error:
                state["error"] = error
            if report_path:
                state["report_path"] = report_path

            if status in self.TERMINAL_STATES:
                state["finished_at"] = time.time()

            self._states[scan_id] = state
            self._flush_to_disk()

    def get_state(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the state of a scan."""
        with self._file_lock:
            return self._states.get(scan_id)

    def get_all_completed(self) -> List[Dict[str, Any]]:
        """Retrieves all completed/terminal scans."""
        with self._file_lock:
            return [s for s in self._states.values() if s.get("status") in self.TERMINAL_STATES]

    def cleanup_old_states(self, max_age_hours: int = 72):
        """Cleans up states older than max_age_hours."""
        with self._file_lock:
            cutoff = time.time() - (max_age_hours * 3600)
            to_delete = []
            for scan_id, state in self._states.items():
                finished_at = state.get("finished_at")
                if finished_at and finished_at < cutoff:
                    to_delete.append(scan_id)
            for scan_id in to_delete:
                del self._states[scan_id]
            if to_delete:
                self._flush_to_disk()
