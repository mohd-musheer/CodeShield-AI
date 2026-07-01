import os
import shutil
import stat
from pathlib import Path
from git import Repo
from fastapi import HTTPException
from app.core.config import CLONE_DIRECTORY


class GitHubCloner:

    @staticmethod
    def _remove_readonly(func, path, excinfo):
        """Helper to force deletion of read-only files on Windows."""
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    def clone(self, repo_url: str, scan_id: str = None):
        """Clones a repository to a scan-specific temp folder to isolate concurrent scans."""
        if not repo_url or not repo_url.strip():
            raise HTTPException(status_code=400, detail="Repository URL cannot be empty")

        url_stripped = repo_url.strip().rstrip("/")
        if url_stripped.endswith(".git"):
            url_stripped = url_stripped[:-4]
        
        repo_name = url_stripped.split("/")[-1]
        if not repo_name:
            raise HTTPException(status_code=400, detail="Invalid repository URL structure")

        # Destination structure: CLONE_DIRECTORY / scan_id / repo_name
        clone_base = Path(CLONE_DIRECTORY)
        clone_base.mkdir(parents=True, exist_ok=True)
        
        if scan_id:
            destination = clone_base / scan_id / repo_name
        else:
            destination = clone_base / repo_name

        if destination.exists():
            try:
                shutil.rmtree(destination, onerror=self._remove_readonly)
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to clear existing local repository folder: {str(e)}"
                )

        try:
            Repo.clone_from(
                repo_url,
                destination,
                multi_options=["--depth=1"]  # Shallow clone to speed up scanning
            )
        except Exception as e:
            if destination.exists():
                shutil.rmtree(destination, onerror=self._remove_readonly)
            raise HTTPException(
                status_code=400,
                detail=f"Git clone failed. Ensure URL is correct: {str(e)}"
            )

        return {
            "repository_name": repo_name,
            "repository_path": str(destination.resolve()),
            "status": "cloned"
        }