from typing import Optional
from pydantic import BaseModel


class RepositoryRequest(BaseModel):
    repository_url: str


class RepositoryAnalyzeRequest(BaseModel):
    repository_url: Optional[str] = None
    repository_name: Optional[str] = None
    local_path: Optional[str] = None


class RepositoryChunkRequest(BaseModel):
    repository_name: str


class RepositoryScanRequest(BaseModel):
    repository_name: str