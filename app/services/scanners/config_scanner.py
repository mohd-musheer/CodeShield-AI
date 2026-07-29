import re
from pathlib import Path
from typing import List
from app.models.repository import Finding, RepositoryFile


class ConfigScanner:
    """Deterministic config scanner to check Dockerfiles, CI/CD, and App Settings."""

    def __init__(self):
        # List of rules for config files
        self.DOCKER_RULES = [
            {
                "id": "docker_run_as_root",
                "title": "Docker Container Running as Root",
                "description": "The Dockerfile does not specify a non-root USER, causing the container to run as root by default.",
                "regex": r"(?im)^USER\s+root\b",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "explanation": "Running containers as root increases security risks; if container isolation is breached, the attacker gains root access to the host machine.",
                "fix_suggestion": "Add a non-root user and switch to it using the 'USER' directive in your Dockerfile (e.g., USER appuser).",
            },
            {
                "id": "docker_wildcard_expose",
                "title": "Exposed Privileged Ports in Docker",
                "description": "The Dockerfile exposes privileged or debug ports directly.",
                "regex": r"(?im)^EXPOSE\s+(?:22|3306|5432|27017|9200|5005)\b",
                "severity": "HIGH",
                "confidence": "HIGH",
                "explanation": "Exposing ports for databases, SSH, or debug services (e.g. 5005) in Docker exposes them to internal and external networks.",
                "fix_suggestion": "Only expose necessary web/application ports. Handle databases and admin tools via secure network bridge configurations or local bindings.",
            },
            {
                "id": "docker_unsafe_base",
                "title": "Unpinned Base Image Version",
                "description": "The Dockerfile uses 'latest' or an unpinned base image version.",
                "regex": r"(?im)^FROM\s+[\w\-\./]+:latest\b|FROM\s+[\w\-\./]+(?:\s+as\s+\w+)?$",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "explanation": "Using unpinned base images (like ':latest' or no tag) can result in unexpected container builds and untracked vulnerabilities when base images are updated.",
                "fix_suggestion": "Pin the base image to a specific version or hash (e.g., FROM python:3.11-slim or FROM node:18-alpine).",
            }
        ]

        self.CI_CD_RULES = [
            {
                "id": "github_actions_pull_request_target",
                "title": "Vulnerable pull_request_target Usage",
                "description": "The GitHub Action workflow uses the pull_request_target trigger, which can allow code execution from forks with write access.",
                "regex": r"(?im)pull_request_target\s*:",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "explanation": "The 'pull_request_target' trigger executes workflows in the context of the base repository. When combined with checking out untrusted code from the fork, it can lead to token theft and repository compromise.",
                "fix_suggestion": "Use 'pull_request' instead of 'pull_request_target' unless explicitly necessary, and never checkout the pull request code with write access.",
            }
        ]

        self.APP_CONFIG_RULES = [
            {
                "id": "django_debug_enabled",
                "title": "Django Debug Mode Enabled",
                "description": "Django DEBUG is set to True in settings.",
                "regex": r"(?i)\bDEBUG\s*=\s*True\b",
                "severity": "HIGH",
                "confidence": "HIGH",
                "explanation": "Leaving debug mode enabled in production exposes detailed error pages, stack traces, and internal settings which leak sensitive secrets and database structures.",
                "fix_suggestion": "Set DEBUG to False in production, or read it from an environment variable (e.g., DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True').",
            },
            {
                "id": "cors_allow_all",
                "title": "Permissive Wildcard CORS Configuration",
                "description": "CORS headers are set to allow all origins ('*').",
                "regex": r"(?i)(?:cors_origins|allow_origins|allow_origin|access-control-allow-origin)\s*[:=]\s*[\"']\*[\"']|allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "explanation": "Allowing all origins via CORS (*) lets malicious websites execute requests against this API and retrieve responses if credentials are also sent or if it is an internal service.",
                "fix_suggestion": "Limit CORS origins to trusted domains, or dynamically validate origins. Avoid using wildcard origins in production environments.",
            },
            {
                "id": "flask_debug_enabled",
                "title": "Flask Debug Mode Enabled",
                "description": "Flask app is configured to run in debug/development mode.",
                "regex": r"(?i)\bapp\.run\(.*debug\s*=\s*True.*\)|app\.config\[[\"']DEBUG[\"']\]\s*=\s*True",
                "severity": "HIGH",
                "confidence": "HIGH",
                "explanation": "Flask debug mode includes an interactive debugger that allows arbitrary Python code execution on the server.",
                "fix_suggestion": "Disable debug mode in production. Run Flask with a production WSGI server like Gunicorn or uWSGI.",
            }
        ]

    def scan_file(self, repo_file: RepositoryFile) -> List[Finding]:
        findings = []
        filepath = Path(repo_file.absolute_path)
        if not filepath.exists():
            return []

        # Read file
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return []

        file_name_lower = repo_file.name.lower()
        rel_path = repo_file.relative_path

        # Determine which rules to run
        rules_to_run = []
        category = "insecure_config"
        
        if "dockerfile" in file_name_lower:
            rules_to_run = self.DOCKER_RULES
            category = "insecure_docker_setup"
            
            # Check for USER root vs missing user
            has_user_directive = False
            for line in lines:
                if re.match(r"(?im)^USER\s+", line):
                    has_user_directive = True
                    break
            
            if not has_user_directive:
                # Add finding for missing user directive (runs as root by default)
                findings.append(
                    Finding(
                        finding_id=f"config-missing-user-{rel_path}",
                        title="Missing USER Directive in Dockerfile",
                        description="The Dockerfile does not contain a USER directive, causing the container to run as root by default.",
                        severity="MEDIUM",
                        confidence="HIGH",
                        file_path=rel_path,
                        line_number=1,
                        code_snippet="[Entire File]",
                        explanation="By default, Docker runs containers as root. If an attacker compromises the application inside, they get root access on the container, facilitating kernel exploit attacks on the host.",
                        fix_suggestion="Create a non-root group and user, then activate them: RUN groupadd -r app && useradd -r -g app appuser && USER appuser",
                        category="insecure_docker_setup",
                    )
                )
        elif ".github/workflows" in rel_path.replace("\\", "/"):
            rules_to_run = self.CI_CD_RULES
            category = "insecure_ci_cd_settings"
        else:
            rules_to_run = self.APP_CONFIG_RULES
            category = "insecure_config"

        # Apply rules
        for rule in rules_to_run:
            pattern = re.compile(rule["regex"])
            for idx, line in enumerate(lines, 1):
                match = pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            finding_id=f"config-{rule['id']}-{rel_path}-{idx}",
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            file_path=rel_path,
                            line_number=idx,
                            code_snippet=line.strip(),
                            explanation=rule["explanation"],
                            fix_suggestion=rule["fix_suggestion"],
                            category=rule.get("category", category),
                        )
                    )

        return findings
