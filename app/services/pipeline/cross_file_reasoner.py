import re
from typing import List, Dict, Set
from app.models.repository import Finding, RepositoryMetadata


class CrossFileReasoner:
    """Performs cross-file security analysis and deduplication on scanner findings."""

    def analyze(self, findings: List[Finding], metadata: RepositoryMetadata) -> List[Finding]:
        # 1. Deduplicate findings
        deduplicated = self._deduplicate(findings)

        # 2. Apply False Positive reduction (e.g., testing files and mocks)
        reduced = self._reduce_false_positives(deduplicated)

        # 3. Perform Cross-File security logic
        cross_findings = self._reason_cross_file(reduced, metadata)

        return reduced + cross_findings

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Merges findings that are duplicate or overlap significantly on the same code line."""
        unique_findings = []
        # Key: (file_path, line_number, category) or (file_path, title)
        seen_keys = set()
        
        for f in findings:
            # Create a unique key. If line_number is None, use file and title.
            if f.line_number is not None:
                key = (f.file_path, f.line_number, f.category)
            else:
                key = (f.file_path, f.title)

            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)
            else:
                # Merge logic: if we already saw it, let's keep the one with higher severity
                existing = next(
                    (x for x in unique_findings if (
                        (x.file_path == f.file_path and x.line_number == f.line_number and x.category == f.category)
                        if f.line_number is not None else
                        (x.file_path == f.file_path and x.title == f.title)
                    )),
                    None
                )
                if existing:
                    # Update explanation if the new one is longer/more detailed
                    if len(f.explanation) > len(existing.explanation):
                        existing.explanation = f.explanation
                    if len(f.fix_suggestion) > len(existing.fix_suggestion):
                        existing.fix_suggestion = f.fix_suggestion
                        
                    # Upgrade severity/confidence to the highest between the two
                    severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    if severity_map.get(f.severity, 0) > severity_map.get(existing.severity, 0):
                        existing.severity = f.severity
                        
                    confidence_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    if confidence_map.get(f.confidence, 0) > confidence_map.get(existing.confidence, 0):
                        existing.confidence = f.confidence
                        
        return unique_findings

    def _reduce_false_positives(self, findings: List[Finding]) -> List[Finding]:
        """Identifies testing, mockup, or configuration template files and downgrades severity."""
        for f in findings:
            path_lower = f.file_path.lower()
            # If the finding is in test folders or files starting with test_
            if (
                "test" in path_lower or
                "mock" in path_lower or
                "spec" in path_lower or
                "fixture" in path_lower
            ):
                # Downgrade secret exposure in tests since they are usually mock tokens
                if f.category in ["secret_exposure", "hardcoded_credentials"]:
                    f.severity = "LOW"
                    f.confidence = "LOW"
                    f.title = f"[TEST DATA] {f.title}"
                    f.description = f"Detected potential hardcoded test data in mock/test file: {f.description}"
                    f.explanation = f"This credential was found in a test resource ({f.file_path}). While it should still be verified, it is likely a mock token rather than a live production secret."
        return findings

    def _reason_cross_file(self, findings: List[Finding], metadata: RepositoryMetadata) -> List[Finding]:
        """Cross-references findings and repository metadata to detect architectural issues."""
        cross_findings = []

        # Find files by role (database, routing, authentication, config)
        db_files = []
        auth_files = []
        routing_files = []
        config_files = []

        for rf in metadata.files:
            path_lower = rf.relative_path.lower()
            if any(term in path_lower for term in ["db", "database", "sql", "models"]):
                db_files.append(rf.relative_path)
            if any(term in path_lower for term in ["auth", "login", "jwt", "session", "permission"]):
                auth_files.append(rf.relative_path)
            if any(term in path_lower for term in ["route", "controller", "endpoint", "api", "view"]):
                routing_files.append(rf.relative_path)
            if any(term in path_lower for term in ["config", "setting", "env", "properties"]):
                config_files.append(rf.relative_path)

        # Heuristic 1: Authentication Middleware present but some routes lack Auth checks
        has_auth_middleware = len(auth_files) > 0
        has_routes = len(routing_files) > 0
        
        # Check if we have specific route-related findings or if AI/config scanner flagged weak security
        has_weak_auth_findings = any(f.category in ["broken_authentication", "broken_authorization"] for f in findings)

        if has_auth_middleware and has_routes:
            # Let's see if any route files do NOT contain imports of auth or references to auth checks
            # This is a cross-file security pattern
            unprotected_routes = []
            for rf_path in routing_files:
                # Find matching RepositoryFile object to examine contents
                meta_file = next((f for f in metadata.files if f.relative_path == rf_path), None)
                if not meta_file:
                    continue
                
                try:
                    with open(meta_file.absolute_path, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()
                    
                    # If this is a route file, check if it references auth keywords
                    # Common keywords: auth, login, jwt, session, guard, secure, Permission, Token
                    auth_keywords = ["auth", "login", "jwt", "session", "guard", "secure", "permission", "token"]
                    if not any(kw in code.lower() for kw in auth_keywords):
                        unprotected_routes.append(rf_path)
                except Exception:
                    pass

            if unprotected_routes:
                routes_list = ", ".join(unprotected_routes[:3])
                if len(unprotected_routes) > 3:
                    routes_list += f" (+{len(unprotected_routes)-3} more)"
                    
                cross_findings.append(
                    Finding(
                        finding_id="cross-file-missing-auth",
                        title="Architectural Risk: Route Files Lacking Authentication References",
                        description=f"Route files ({routes_list}) were detected that make no reference to authentication mechanisms, while an authentication system was found in {auth_files[0]}.",
                        severity="HIGH",
                        confidence="MEDIUM",
                        file_path=unprotected_routes[0],
                        line_number=None,
                        code_snippet=None,
                        explanation=(
                            f"An authentication system is implemented in '{auth_files[0]}', but route configuration files "
                            f"({routes_list}) do not import or reference any auth controls. This architectural pattern suggests "
                            "endpoints in these files may be exposed without authentication checks."
                        ),
                        fix_suggestion="Ensure all API route definitions require authentication. Implement global route guards or import and apply authorization middlewares in routing files.",
                        category="broken_authentication",
                    )
                )

        # Heuristic 2: Database secrets hardcoded in configurations AND database queries in separate source files
        db_secrets = [f for f in findings if f.category == "secret_exposure" and any(term in f.file_path.lower() for term in ["config", "setting", "env", "properties"])]
        if db_secrets and db_files:
            cross_findings.append(
                Finding(
                    finding_id="cross-file-exposed-db-pipeline",
                    title="Exposed Database Pipeline: Config Credentials + Code References",
                    description="Hardcoded configuration credentials coincide with database access code in separate source files.",
                    severity="CRITICAL",
                    confidence="HIGH",
                    file_path=db_secrets[0].file_path,
                    line_number=db_secrets[0].line_number,
                    code_snippet=db_secrets[0].code_snippet,
                    explanation=(
                        f"Database credentials are exposed in the configuration file '{db_secrets[0].file_path}'. "
                        f"Meanwhile, files like '{db_files[0]}' handle database queries. If these credentials are leaked, "
                        "attackers gain direct, unauthenticated access to the database containing application data."
                    ),
                    fix_suggestion="Remove database credentials from the settings files immediately. Inject them dynamically using environment variables or a secret vault.",
                    category="secret_exposure",
                )
            )

        # Heuristic 3: CORS Allowed-All origins with Auth endpoints
        cors_wildcards = [f for f in findings if f.category == "dangerous_cors"]
        if cors_wildcards and auth_files:
            cross_findings.append(
                Finding(
                    finding_id="cross-file-cors-auth-exposure",
                    title="CORS Wildcard with Authentication System",
                    description="Wildcard CORS settings are defined, potentially exposing sensitive authentication routes.",
                    severity="HIGH",
                    confidence="HIGH",
                    file_path=cors_wildcards[0].file_path,
                    line_number=cors_wildcards[0].line_number,
                    code_snippet=cors_wildcards[0].code_snippet,
                    explanation=(
                        f"The repository configures wildcard CORS (Access-Control-Allow-Origin: '*') at '{cors_wildcards[0].file_path}'. "
                        f"Because the repository contains authentication routes ({auth_files[0]}), this combination allows "
                        "malicious sites to perform Cross-Site Request Forgery (CSRF) or cross-origin credential stealing."
                    ),
                    fix_suggestion="Do not use wildcard '*' CORS configurations in combination with credentials. Restrict Access-Control-Allow-Origin to specific, validated domains.",
                    category="dangerous_cors",
                )
            )

        return cross_findings
