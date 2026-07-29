import threading
from typing import Set


class CancelManager:
    """Thread-safe manager to track active scan cancellation requests."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._cancelled_scans: Set[str] = set()
            return cls._instance

    def cancel_scan(self, scan_id: str):
        """Flags a scan ID as cancelled."""
        with self._lock:
            self._cancelled_scans.add(scan_id)

    def is_cancelled(self, scan_id: str) -> bool:
        """Checks if a scan ID has been cancelled."""
        with self._lock:
            return scan_id in self._cancelled_scans

    def remove_scan(self, scan_id: str):
        """Cleans up scan cancellation flag after completion/failure/cancellation."""
        with self._lock:
            self._cancelled_scans.discard(scan_id)
