import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class HistoryManager:
    """Manages local scan history logs and calculates security posture differences."""

    def __init__(self):
        self.history_file = Path("reports") / "history.json"

    def _load_history(self) -> List[Dict[str, Any]]:
        if not self.history_file.exists():
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_history(self, history: List[Dict[str, Any]]):
        try:
            self.history_file.parent.mkdir(exist_ok=True)
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            print(f"[History Error] Failed to write history file: {e}")

    def save_scan(self, report: Any) -> Dict[str, Any]:
        """Saves a ScanReport summary and calculates progress deltas."""
        history = self._load_history()
        repo_name = report.repository_name
        
        # Calculate delta score
        previous_scan = self.get_latest_scan(repo_name)
        delta_score = 0
        critical_fixed = 0
        new_issues = 0

        if previous_scan:
            delta_score = report.score.overall_score - previous_scan.get("score", 100)
            
            # Compare findings if previous full report exists
            prev_report_path = Path("reports") / f"{previous_scan['scan_id']}.json"
            if prev_report_path.exists():
                try:
                    with open(prev_report_path, "r", encoding="utf-8") as f:
                        prev_data = json.load(f)
                        prev_findings = prev_data.get("findings", [])
                        
                        curr_keys = {(f.file_path, f.title) for f in report.findings}
                        prev_keys = {(f.get("file_path"), f.get("title")) for f in prev_findings}
                        
                        fixed_findings = [f for f in prev_findings if (f.get("file_path"), f.get("title")) not in curr_keys]
                        critical_fixed = sum(1 for f in fixed_findings if f.get("severity") in ["CRITICAL", "HIGH"])
                        
                        new_findings = [f for f in report.findings if (f.file_path, f.title) not in prev_keys]
                        new_issues = len(new_findings)
                except Exception:
                    pass
        else:
            new_issues = len(report.findings)

        # Record entry
        entry = {
            "scan_id": report.scan_id,
            "repository_name": repo_name,
            "repository_url": report.repository_url,
            "timestamp": report.timestamp.isoformat() if hasattr(report.timestamp, "isoformat") else str(report.timestamp),
            "score": report.score.overall_score,
            "findings_count": len(report.findings),
            "delta_score": delta_score,
            "critical_fixed": critical_fixed,
            "new_issues": new_issues
        }
        
        history.append(entry)
        self._save_history(history)
        return entry

    def get_latest_scan(self, repo_name: str) -> Optional[Dict[str, Any]]:
        """Retrieves the most recent scan entry for a repository."""
        history = self._load_history()
        for entry in reversed(history):
            if entry.get("repository_name") == repo_name:
                return entry
        return None

    def get_score_delta(self, repo_name: str) -> int:
        """Returns the score delta between the last scan and the one before it."""
        history = self._load_history()
        repo_entries = [e for e in history if e.get("repository_name") == repo_name]
        if len(repo_entries) < 2:
            return 0
        return repo_entries[-1].get("delta_score", 0)

    def get_repository_history(self, repo_name: str) -> Dict[str, Any]:
        """Provides comparative summary metrics for the dashboard."""
        history = self._load_history()
        repo_entries = [e for e in history if e.get("repository_name") == repo_name]
        
        if len(repo_entries) == 0:
            return {
                "last_scan": "Never",
                "previous_scan": "Never",
                "score_change": 0,
                "critical_fixed": 0,
                "new_issues": 0
            }
            
        if len(repo_entries) < 2:
            last = repo_entries[-1]
            try:
                last_dt = datetime.fromisoformat(last["timestamp"])
                last_str = last_dt.strftime("%Y-%m-%d %H:%M")
            except Exception:
                last_str = "Today"
            return {
                "last_scan": last_str,
                "previous_scan": "Never",
                "score_change": 0,
                "critical_fixed": 0,
                "new_issues": last.get("new_issues", 0)
            }
            
        last = repo_entries[-1]
        prev = repo_entries[-2]
        
        try:
            last_dt = datetime.fromisoformat(last["timestamp"])
            last_str = last_dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            last_str = "Today"
            
        try:
            prev_dt = datetime.fromisoformat(prev["timestamp"])
            prev_str = prev_dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            prev_str = "Yesterday"

        return {
            "last_scan": last_str,
            "previous_scan": prev_str,
            "score_change": last.get("delta_score", 0),
            "critical_fixed": last.get("critical_fixed", 0),
            "new_issues": last.get("new_issues", 0)
        }
