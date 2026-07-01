import os
import uuid
import shutil
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import threading

from app.models.repository import RepositoryMetadata, ScanReport, Finding, SecurityScore, RepositoryChunk

from app.services.clone.github import GitHubCloner
from app.services.parser.file_loader import FileLoader
from app.services.parser.language_detector import LanguageDetector
from app.services.parser.dependency_detector import DependencyDetector
from app.services.chunking.chunker import CodeChunker
from app.services.scanners.secret_scanner import SecretScanner
from app.services.scanners.config_scanner import ConfigScanner
from app.services.scanners.dependency_scanner import DependencyScanner
from app.services.ai.groq_client import GroqAIScanner, GroqRateLimitException
from app.services.pipeline.cross_file_reasoner import CrossFileReasoner
from app.services.pipeline.scorer import SecurityScorer
from app.services.reports.exporter import ReportExporter
from app.utils.progress import ProgressTracker
from app.utils.scan_state import ScanStateManager
from app.utils.path_safety import get_safe_repository_path, remove_readonly
from app.utils.history import HistoryManager
from app.utils.cancel_manager import CancelManager
from app.core.config import CLONE_DIRECTORY, SCAN_LOG_DIR

class ScanCancelledException(Exception):
    """Exception raised when a scan is cancelled by user request."""
    pass


# Thread-safe in-memory cache to store scan reports
REPORTS_CACHE: Dict[str, ScanReport] = {}
REPORTS_CACHE_LOCK = threading.Lock()

# Thread-safe in-memory cache to store file contents for the code viewer
FILE_CONTENTS_CACHE: Dict[str, Dict[str, str]] = {}
FILE_CONTENTS_CACHE_LOCK = threading.Lock()



class ScanLogger:
    """Simple file logger dedicated to tracking a specific scan's lifecycle."""
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.log_path = Path(SCAN_LOG_DIR) / f"{scan_id}.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, level: str, message: str):
        timestamp = datetime.utcnow().isoformat()
        log_line = f"[{timestamp}] [{level}] {message}\n"
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception as e:
            print(f"[ScanLogger Error] Failed to write scan log: {e}")
        # Print to stdout/console for standard terminal logging too
        print(f"[{level}] [Scan {self.scan_id[:8]}] {message}")

    def info(self, msg: str): self.log("INFO", msg)
    def warning(self, msg: str): self.log("WARN", msg)
    def error(self, msg: str): self.log("ERROR", msg)


class PipelineManager:
    """Orchestrates the entire repository cloning, scanning, scoring, and reporting pipeline."""

    def __init__(self):
        self.cloner = GitHubCloner()
        self.loader = FileLoader()
        self.lang_detector = LanguageDetector()
        self.dep_detector = DependencyDetector()
        self.chunker = CodeChunker()
        
        self.secret_scanner = SecretScanner()
        self.config_scanner = ConfigScanner()
        self.dependency_scanner = DependencyScanner()
        self.ai_scanner = GroqAIScanner()
        
        self.reasoner = CrossFileReasoner()
        self.scorer = SecurityScorer()
        self.exporter = ReportExporter()
        self.tracker = ProgressTracker()
        self.state_manager = ScanStateManager()
        self.history = HistoryManager()

    def _cleanup_old_repositories(self):
        """Deletes cloned repositories that are older than 24 hours to prevent disk space leaks."""
        try:
            clone_dir = Path(CLONE_DIRECTORY)
            if not clone_dir.exists():
                return
                
            now = datetime.now().timestamp()
            for path in clone_dir.iterdir():
                if path.is_dir():
                    stat_info = path.stat()
                    mtime = stat_info.st_mtime
                    # 24 hours = 86400 seconds
                    if now - mtime > 86400:
                        shutil.rmtree(path, onerror=remove_readonly)
                        print(f"[Cleanup] Pruned old repository workspace: {path.name}")
        except Exception as e:
            print(f"[Cleanup Error] Failed to prune old workspaces: {e}")

    def run_pipeline(
        self,
        repository_url: Optional[str] = None,
        repository_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        custom_path: Optional[str] = None
    ) -> ScanReport:
        """Executes the full CodeShield scan pipeline following the strict lifecycle machine."""
        if not scan_id:
            scan_id = str(uuid.uuid4())

        slog = ScanLogger(scan_id)
        slog.info("Starting scan pipeline")
        
        # Initialize execution stats
        t_start_total = time.time()
        
        repo_path = None
        repo_name = None
        ai_skipped = False
        ai_skipped_reason = ""
        is_zip_upload = (custom_path is not None)

        try:
            # Clean up old repositories first
            self._cleanup_old_repositories()

            # State: INITIALIZING
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: INITIALIZING")
            self.tracker.set_progress(scan_id, "INITIALIZING", 5, "Initializing scan pipeline...")

            # State: CLONING
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: CLONING")
            self.tracker.set_progress(scan_id, "CLONING", 10, "Setting up workspace and cloning repository...")

            if repository_url:
                slog.info(f"Cloning from remote URL: {repository_url}")
                clone_res = self.cloner.clone(repository_url, scan_id=scan_id)
                repo_path = clone_res["repository_path"]
                repo_name = clone_res["repository_name"]
            elif custom_path:
                slog.info(f"Using provided workspace custom path: {custom_path}")
                repo_path = custom_path
                repo_name = repository_name or Path(custom_path).name
            elif repository_name:
                slog.info(f"Using local repository name: {repository_name}")
                repo_name = repository_name
                repo_path = str(get_safe_repository_path(repo_name, scan_id=scan_id))
            else:
                raise ValueError("Either repository_url, repository_name, or custom_path must be provided")

            if not repo_path or not Path(repo_path).exists():
                raise FileNotFoundError(f"Repository directory does not exist: {repo_path}")

            slog.info(f"Workspace path set: {repo_path}")

            # State: LOADING
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: LOADING")
            self.tracker.set_progress(scan_id, "LOADING", 20, "Loading files and indexing workspace...")
            metadata = self.loader.load_repository(repo_path)
            metadata.repository_name = repo_name

            # Populate FILE_CONTENTS_CACHE for interactive code previewer
            file_contents = {}
            for repo_file in metadata.files:
                try:
                    with open(repo_file.absolute_path, "r", encoding="utf-8", errors="ignore") as f:
                        file_contents[repo_file.relative_path.replace("\\", "/")] = f.read()
                except Exception as e:
                    slog.warning(f"Failed to read file {repo_file.relative_path} into cache: {e}")
            with FILE_CONTENTS_CACHE_LOCK:
                FILE_CONTENTS_CACHE[scan_id] = file_contents


            # State: ANALYZING
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: ANALYZING")
            self.tracker.set_progress(scan_id, "ANALYZING", 30, "Detecting technologies, frameworks, and manifests...")
            metadata = self.lang_detector.detect(metadata)
            metadata = self.dep_detector.detect(metadata)

            # State: CHUNKING
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: CHUNKING")
            self.tracker.set_progress(scan_id, "CHUNKING", 40, "Building logical codebase chunks...")
            all_chunks = []
            for f in metadata.files:
                chunks = self.chunker.chunk_file(f)
                all_chunks.extend(chunks)
            slog.info(f"Total chunks generated: {len(all_chunks)}")

            # State: STATIC_SCAN
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: STATIC_SCAN")
            self.tracker.set_progress(scan_id, "STATIC_SCAN", 50, "Running credential and config static scanners...")
            findings: List[Finding] = []


            # Run secret and configuration static scanners
            for f in metadata.files:
                findings.extend(self.secret_scanner.scan_file(f))
                findings.extend(self.config_scanner.scan_file(f))

            # Run dependency scanner
            findings.extend(self.dependency_scanner.scan_metadata(metadata))
            slog.info(f"Static scanners completed. Identified findings: {len(findings)}")

            # State: AI_SCAN
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: AI_SCAN")
            self.tracker.set_progress(scan_id, "AI_SCAN", 65, "Performing semantic security review with Groq LLM...")
            
            ai_target_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".cs", ".cpp"}
            
            # Performance Optimization: Group and merge multiple chunks of the same file
            from collections import defaultdict
            file_chunks = defaultdict(list)
            for c in all_chunks:
                if Path(c.file_path).suffix.lower() in ai_target_extensions:
                    file_chunks[c.file_path].append(c)

            merged_chunks = []
            for file_path, chunks in file_chunks.items():
                chunks.sort(key=lambda x: x.start_line)
                
                # Merge chunks sequentially up to 15,000 characters
                current_group = []
                current_len = 0
                for c in chunks:
                    if current_len + len(c.content) > 15000:
                        merged = self._create_merged_chunk(current_group, file_path)
                        merged_chunks.append(merged)
                        current_group = [c]
                        current_len = len(c.content)
                    else:
                        current_group.append(c)
                        current_len += len(c.content)
                if current_group:
                    merged = self._create_merged_chunk(current_group, file_path)
                    merged_chunks.append(merged)

            # Priority sorting for merged chunks
            sensitive_keywords = ["query", "select", "insert", "auth", "login", "password", "encrypt", "decrypt", "jwt", "exec", "system", "cookie", "upload"]
            def merged_chunk_priority(chunk):
                score = 0
                content_lower = chunk.content.lower()
                for kw in sensitive_keywords:
                    if kw in content_lower:
                        score += 1
                return score

            merged_chunks.sort(key=merged_chunk_priority, reverse=True)
            # Scan top 6 merged chunks (typically covers the entire codebase with 2-4 files in 10s)
            ai_scan_limit = 6
            ai_chunks_to_scan = merged_chunks[:ai_scan_limit]

            if ai_chunks_to_scan and self.ai_scanner.api_key:
                total_ai = len(ai_chunks_to_scan)
                slog.info(f"Scanning {total_ai} prioritized merged chunks using Groq AI")
                for i, chunk in enumerate(ai_chunks_to_scan, 1):
                    if CancelManager().is_cancelled(scan_id):
                        raise ScanCancelledException()
                    slog.info(f"AI scanning merged chunk {i}/{total_ai}: {chunk.file_path} ({chunk.name})")
                    self.tracker.set_progress(
                        scan_id, 
                        "AI_SCAN", 
                        65 + int((i / total_ai) * 15), 
                        f"Analyzing security context in code file {i}/{total_ai}..."
                    )
                    try:
                        ai_findings = self.ai_scanner.scan_chunk(chunk)
                        findings.extend(ai_findings)
                    except GroqRateLimitException as e:
                        slog.warning(f"Groq API rate limit hit: {e}")
                        ai_skipped = True
                        ai_skipped_reason = "AI analysis skipped due to provider rate limit."
                        break
                    except Exception as e:
                        slog.error(f"Error scanning chunk with AI: {e}")
            else:
                if not self.ai_scanner.api_key:
                    slog.warning("AI Scanner skipped: Groq API Key not configured")
                    ai_skipped = True
                    ai_skipped_reason = "AI analysis skipped: Groq API Key not configured."
                else:
                    slog.info("AI Scanner skipped: No compatible code files found in codebase")

            # State: REASONING
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: REASONING")
            self.tracker.set_progress(scan_id, "REASONING", 85, "Running cross-file security correlation...")
            correlated_findings = self.reasoner.analyze(findings, metadata)

            # State: SCORING
            if CancelManager().is_cancelled(scan_id):
                raise ScanCancelledException()
            slog.info("Transition to state: SCORING")
            self.tracker.set_progress(scan_id, "SCORING", 90, "Calculating security posture score...")
            score = self.scorer.calculate_score(correlated_findings)


            # State: GENERATING_REPORT
            slog.info("Transition to state: GENERATING_REPORT")
            self.tracker.set_progress(scan_id, "GENERATING_REPORT", 95, "Generating final security report files...")
            
            repo_url = repository_url if repository_url else (f"Uploaded ZIP: {repo_name}" if is_zip_upload else f"Local: {repo_name}")
            metadata.scan_duration_sec = round(time.time() - t_start_total, 2)

            report = ScanReport(
                scan_id=scan_id,
                repository_name=repo_name,
                repository_url=repo_url,
                timestamp=datetime.utcnow(),
                metadata=metadata,
                findings=correlated_findings,
                score=score,
                status="completed"
            )

            # Append the AI rate limit or skip note to the report if applicable
            if ai_skipped:
                # Add a custom tag or append it to the risk summary
                report.score.risk_summary = f"{report.score.risk_summary} Note: {ai_skipped_reason}"

            # Atomic completion step 1: Generate & Save report files
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            report_json_path = reports_dir / f"{scan_id}.json"

            report_json = self.exporter.to_json(report)
            with open(report_json_path, "w", encoding="utf-8") as f:
                f.write(report_json)
                
            report_html = self.exporter.to_html(report)
            with open(reports_dir / f"{scan_id}.html", "w", encoding="utf-8") as f:
                f.write(report_html)

            report_md = self.exporter.to_markdown(report)
            with open(reports_dir / f"{scan_id}.md", "w", encoding="utf-8") as f:
                f.write(report_md)

            # Write extra report assets
            try:
                with open(reports_dir / f"{scan_id}.sarif", "w", encoding="utf-8") as f:
                    f.write(self.exporter.to_sarif(report))
                with open(reports_dir / f"{scan_id}.csv", "w", encoding="utf-8") as f:
                    f.write(self.exporter.to_csv(report))
                with open(reports_dir / f"fix_prompt_{scan_id}.json", "w", encoding="utf-8") as f:
                    f.write(self.exporter.to_fix_prompt_json(report))
                with open(reports_dir / f"fix_prompt_{scan_id}.md", "w", encoding="utf-8") as f:
                    f.write(self.exporter.to_fix_prompt_markdown(report))
                with open(reports_dir / f"fix_prompt_{scan_id}.txt", "w", encoding="utf-8") as f:
                    f.write(self.exporter.to_fix_prompt_text(report))
                with open(reports_dir / f"patch_{scan_id}.diff", "w", encoding="utf-8") as f:
                    f.write(self.exporter.to_patch_diff(report))
            except Exception as e:
                slog.error(f"Failed to write additional report assets: {e}")


            slog.info(f"Reports successfully saved to reports/{scan_id}.*")

            # Atomic completion step 2: Save scan state
            self.state_manager.update_state(
                scan_id=scan_id,
                status="COMPLETED",
                progress=100,
                stage="COMPLETED",
                message="Security scan completed successfully.",
                report_path=str(report_json_path)
            )
            slog.info("Scan state updated in persistent database")

            # Atomic completion step 3: Save history
            self.history.save_scan(report)
            slog.info("Scan metrics successfully added to local history database")

            # Atomic completion step 4: Cache report in memory
            with REPORTS_CACHE_LOCK:
                REPORTS_CACHE[scan_id] = report
                if len(REPORTS_CACHE) > 20:
                    oldest_key = next(iter(REPORTS_CACHE))
                    REPORTS_CACHE.pop(oldest_key, None)

            # Atomic completion step 5: Mark COMPLETED (this will trigger websocket message dispatch)
            self.tracker.set_progress(
                scan_id, 
                "COMPLETED", 
                100, 
                "Security scan completed successfully.",
                extra={"ai_skipped": ai_skipped, "ai_skipped_reason": ai_skipped_reason}
            )
            
            slog.info(f"Total scan pipeline finished in {time.time() - t_start_total:.2f} seconds")

            # Workspace cleanup is ALWAYS the final step
            slog.info("Performing post-scan workspace cleanup")
            self._cleanup_workspace_files(repo_path, scan_id, is_zip_upload)

            return report

        except ScanCancelledException as e:
            slog.warning("Scan was cancelled by user request.")
            # Set state to CANCELLED in persistent state manager and progress tracker
            self.state_manager.update_state(
                scan_id=scan_id,
                status="CANCELLED",
                progress=100,
                stage="CANCELLED",
                message="Scan cancelled by user."
            )
            self.tracker.set_progress(scan_id, "CANCELLED", 100, "Scan cancelled by user.")
            
            # Clean up workspace
            self._cleanup_workspace_files(repo_path, scan_id, is_zip_upload)
            CancelManager().remove_scan(scan_id)
            return None
        except Exception as e:
            error_message = f"Pipeline execution failed: {str(e)}"
            slog.error(f"Execution Error: {error_message}")
            slog.error(traceback.format_exc())

            self.tracker.set_progress(scan_id, "FAILED", 100, error_message, extra={"error": error_message})
            
            # Clean up workspace even on failure
            self._cleanup_workspace_files(repo_path, scan_id, is_zip_upload)
            raise e


    def _cleanup_workspace_files(self, repo_path: Optional[str], scan_id: str, is_zip: bool):
        """Cleans up workspace directories safely, ensuring we never delete code or databases."""
        try:
            if repo_path and Path(repo_path).exists():
                shutil.rmtree(repo_path, onerror=remove_readonly)
                print(f"[Cleanup] Cleaned up repository folder: {repo_path}")

            # Also delete the scan parent subfolder CLONE_DIRECTORY / scan_id if it exists
            scan_parent_dir = Path(CLONE_DIRECTORY) / scan_id
            if scan_parent_dir.exists():
                shutil.rmtree(scan_parent_dir, onerror=remove_readonly)
                print(f"[Cleanup] Cleaned up scan parent directory: {scan_parent_dir}")
        except Exception as e:
            print(f"[Cleanup Warning] Error cleaning up scan directory: {e}")

    def _create_merged_chunk(self, chunks: List[RepositoryChunk], file_path: str) -> RepositoryChunk:
        """Merges multiple code chunks from the same file into a single virtual chunk to reduce API requests."""
        if len(chunks) == 1:
            return chunks[0]

        merged_content = []
        for i, c in enumerate(chunks, 1):
            merged_content.append(f"// --- Code Segment {i} (Lines {c.start_line}-{c.end_line}) ---")
            merged_content.append(c.content)
            merged_content.append("")

        return RepositoryChunk(
            chunk_id=f"merged-{file_path}-{chunks[0].start_line}",
            file_path=file_path,
            chunk_type="merged",
            name=f"Merged Context ({len(chunks)} segments)",
            content="\n".join(merged_content),
            start_line=chunks[0].start_line,
            end_line=chunks[-1].end_line
        )

