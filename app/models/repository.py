from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class RepositoryFile(BaseModel):
    name: str
    extension: str
    relative_path: str
    absolute_path: str
    size: int
    modified_time: datetime


class LanguageStatistics(BaseModel):
    language: str
    files: int
    size: int


class RepositoryMetadata(BaseModel):
    repository_name: str
    repository_path: str
    total_files: int
    total_size: int
    files: List[RepositoryFile] = Field(default_factory=list)
    languages: List[LanguageStatistics] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    configs: List[str] = Field(default_factory=list)
    scan_duration_sec: float = 0.0



class RepositoryChunk(BaseModel):
    chunk_id: str
    file_path: str
    chunk_type: str  # function, class, module, config, general
    name: str
    content: str
    start_line: int
    end_line: int


class Finding(BaseModel):
    finding_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: str  # HIGH, MEDIUM, LOW
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    explanation: str
    fix_suggestion: str
    category: str
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    attack_scenario: Optional[str] = None
    business_impact: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    patch: Optional[str] = None



class SecurityScore(BaseModel):
    overall_score: int  # 0 to 100
    severity_breakdown: Dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    )
    category_scores: Dict[str, int] = Field(default_factory=dict)
    risk_summary: str


class ScanReport(BaseModel):
    scan_id: str
    repository_name: str
    repository_url: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: RepositoryMetadata
    findings: List[Finding] = Field(default_factory=list)
    score: SecurityScore
    status: str = "completed"