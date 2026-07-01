import os
import stat
from pathlib import Path
from fastapi import HTTPException
from app.core.config import CLONE_DIRECTORY


def get_safe_repository_path(repository_name: str, scan_id: str = None) -> Path:
    """Resolves and validates a repository name to prevent path traversal.
    
    Ensures that the resolved path is strictly within the designated clone directory.
    If scan_id is provided, checks within CLONE_DIRECTORY / scan_id.
    """
    if not repository_name or not repository_name.strip():
        raise HTTPException(status_code=400, detail="Repository name cannot be empty")
        
    normalized_name = Path(repository_name).name
    
    if normalized_name in ["", ".", ".."]:
        raise HTTPException(status_code=400, detail="Invalid repository name structure")
        
    clone_dir = Path(CLONE_DIRECTORY).resolve()
    
    if scan_id:
        target_path = (clone_dir / scan_id / normalized_name).resolve()
    else:
        target_path = (clone_dir / normalized_name).resolve()
    
    try:
        if not target_path.is_relative_to(clone_dir):
            raise HTTPException(
                status_code=400,
                detail="Access denied: target path is outside the allowed directories."
            )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Access denied: target path traversal detected."
        )
        
    return target_path


def remove_readonly(func, path, excinfo):
    """OnError callback for shutil.rmtree to override read-only locks on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass
