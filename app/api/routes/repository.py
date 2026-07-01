import os
import shutil
import uuid
import zipfile
import stat
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app.schemas.request import RepositoryRequest, RepositoryChunkRequest
from app.utils.path_safety import get_safe_repository_path, remove_readonly
from app.services.clone.github import GitHubCloner
from app.services.parser.file_loader import FileLoader
from app.services.chunking.chunker import CodeChunker
from app.services.pipeline.manager import PipelineManager, REPORTS_CACHE, FILE_CONTENTS_CACHE
from app.utils.progress import ProgressTracker
from app.utils.scan_state import ScanStateManager
from app.core.config import CLONE_DIRECTORY

router = APIRouter(
    prefix="/repository",
    tags=["Repository"],
)


@router.post("/clone")
def clone_repository(request: RepositoryRequest):
    """Clones a GitHub repository locally."""
    return GitHubCloner().clone(request.repository_url)


@router.post("/upload")
def upload_zip_repository(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Uploads a repository as a ZIP archive and triggers background scanning.
    
    Extracts the zip safely to a scan-specific temp workspace outside the project root.
    """
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP archives are supported")
        
    scan_id = str(uuid.uuid4())
    
    # Save zip and extract to CLONE_DIRECTORY / scan_id (outside of project root to prevent reload)
    scan_dir = Path(CLONE_DIRECTORY) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    zip_path = scan_dir / "upload.zip"
    extract_path = scan_dir / "workspace"
    
    try:
        # Save uploaded zip
        with open(zip_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
            
        # Extract zip content safely
        with zipfile.ZipFile(zip_path, "r") as z:
            for name in z.namelist():
                # Prevent Zip Slip path traversal vulnerabilities
                if ".." in name or name.startswith("/") or name.startswith("\\"):
                    raise HTTPException(
                        status_code=400, 
                        detail="Malicious directory path detected inside ZIP archive (Zip Slip)"
                    )
            z.extractall(extract_path)
            
        # Remove the zip file immediately
        try:
            os.remove(zip_path)
        except Exception:
            pass
            
        # Locate scan target: unwrap nested folder if ZIP contains a single root folder
        children = list(extract_path.iterdir())
        if len(children) == 1 and children[0].is_dir():
            scan_target = children[0]
        else:
            scan_target = extract_path
            
    except HTTPException:
        raise
    except Exception as e:
        if scan_dir.exists():
            try:
                shutil.rmtree(scan_dir, onerror=remove_readonly)
            except Exception:
                pass
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to process and extract ZIP archive: {str(e)}"
        )
        
    # Register scan state BEFORE starting background task
    state_manager = ScanStateManager()
    state_manager.register_scan(scan_id, repository_name=file.filename[:-4], repository_url=f"ZIP: {file.filename}")
    ProgressTracker().set_progress(scan_id, "QUEUED", 0, "Waiting for ZIP scan pipeline to start...")
    
    # Trigger scan pipeline in background thread
    manager = PipelineManager()
    background_tasks.add_task(
        manager.run_pipeline,
        None,                        # repository_url
        file.filename[:-4],          # repository_name
        scan_id,
        str(scan_target.resolve())   # custom_path (direct extracted folder)
    )
    
    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "ZIP archive uploaded and extracted. Scan pipeline triggered in background."
    }


@router.post("/chunk")
def chunk_repository(request: RepositoryChunkRequest):
    """Loads a repository and partitions its source files into logical chunks."""
    repo_path = get_safe_repository_path(request.repository_name)
    if not repo_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Repository '{request.repository_name}' not found locally. Please clone it first."
        )

    loader = FileLoader()
    metadata = loader.load_repository(str(repo_path))

    chunker = CodeChunker()
    all_chunks = []
    
    for repo_file in metadata.files:
        chunks = chunker.chunk_file(repo_file)
        all_chunks.extend(chunks)

    return {
        "repository_name": request.repository_name,
        "total_files": len(metadata.files),
        "total_chunks": len(all_chunks),
        "chunks": all_chunks
    }


@router.get("/file-content")
def get_file_content(scan_id: str, file_path: str):
    """Retrieves file content from the cache of the active scan."""
    import re
    # Validate scan_id format to prevent injection
    if not re.match(r"^[\w\-]+$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
        
    file_path_clean = file_path.replace("\\", "/")
    
    # Check memory cache first
    if scan_id in FILE_CONTENTS_CACHE:
        scan_files = FILE_CONTENTS_CACHE[scan_id]
        if file_path_clean in scan_files:
            return PlainTextResponse(content=scan_files[file_path_clean])
            
    raise HTTPException(status_code=404, detail=f"File '{file_path}' not found in scan content cache")