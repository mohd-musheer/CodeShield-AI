import re
from pathlib import Path
from typing import List
from app.models.repository import Finding, RepositoryFile, RepositoryMetadata


class DependencyScanner:
    """Offline scanner that matches parsed dependencies against known vulnerable patterns/versions."""

    def __init__(self):
        # Dictionary mapping package patterns to vulnerabilities
        # Format: (package_name, operator, version) -> vulnerability_details
        # For a simple, readable, and lightweight scanner, we will use a list of common vulnerable packages
        self.VULN_DB = [
            {
                "package": "log4j",
                "pattern": r"^log4j:log4j$|^org\.apache\.logging\.log4j:log4j-core$",
                "version_regex": r"^(?:[0-1]\..*|2\.(?:[0-9]|1[0-4])\..*)$",  # < 2.15.0
                "title": "Log4Shell Remote Code Execution (RCE)",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "explanation": "Apache Log4j2 versions up to 2.14.1 are vulnerable to a remote code execution vulnerability (CVE-2021-44228) via JNDI injection.",
                "fix_suggestion": "Upgrade Log4j to version 2.17.1 or higher.",
            },
            {
                "package": "django",
                "pattern": r"^django$",
                "version_regex": r"^(?:[0-2]\..*|3\.[0-1]\..*|3\.2\.(?:[0-9]|1[0-2])|4\.0\.[0-3])$",  # Various old CVEs
                "title": "Outdated Django Version with Known Vulnerabilities",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "explanation": "The Django version in use is outdated and has known security vulnerabilities (including SQL injection and cache poisoning).",
                "fix_suggestion": "Upgrade Django to a supported version (e.g., 4.2 LTS or 5.0+).",
            },
            {
                "package": "urllib3",
                "pattern": r"^urllib3$",
                "version_regex": r"^(?:1\.(?:[0-9]|[0-1][0-9]|2[0-5]|26\.[0-9]|26\.1[0-6]))$",  # < 1.26.17
                "title": "urllib3 Cookie Leakage & Request Smuggling",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "explanation": "urllib3 before 1.26.17/2.0.6 is vulnerable to request smuggling or HTTP request splitting when using proxies.",
                "fix_suggestion": "Upgrade urllib3 to version 1.26.18 or 2.0.7 or higher.",
            },
            {
                "package": "express",
                "pattern": r"^express$",
                "version_regex": r"^(?:[0-3]\..*|4\.(?:[0-9]|1[0-8])\..*)$",  # < 4.19.0
                "title": "Express.js Open Redirect / Safe Routing Issue",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "explanation": "Versions of Express.js prior to 4.19.2 have open redirect vulnerabilities and potential request handling issues.",
                "fix_suggestion": "Upgrade express to version 4.19.2 or higher.",
            },
            {
                "package": "axios",
                "pattern": r"^axios$",
                "version_regex": r"^(?:0\..*|1\.(?:[0-5]\..*|6\.0))$",  # < 1.6.1
                "title": "Axios Server-Side Request Forgery (SSRF)",
                "severity": "HIGH",
                "confidence": "HIGH",
                "explanation": "Axios versions prior to 1.6.1 are vulnerable to Server-Side Request Forgery (SSRF) when parsing relative URLs.",
                "fix_suggestion": "Upgrade axios to version 1.6.1 or higher.",
            },
            {
                "package": "jsonwebtoken",
                "pattern": r"^jsonwebtoken$",
                "version_regex": r"^(?:[0-8]\..*)$",  # < 9.0.0
                "title": "jsonwebtoken Key Confusion / Verification Bypass",
                "severity": "HIGH",
                "confidence": "HIGH",
                "explanation": "jsonwebtoken prior to 9.0.0 is vulnerable to verification bypass where public keys can be confused with secret keys.",
                "fix_suggestion": "Upgrade jsonwebtoken to version 9.0.0 or higher.",
            },
            {
                "package": "fastapi",
                "pattern": r"^fastapi$",
                "version_regex": r"^(?:0\.(?:[0-9]|[0-9][0-9]|10[0-8])\..*)$",  # < 0.109.0
                "title": "FastAPI Outdated Version - Potential ReDos or Dependency issues",
                "severity": "MEDIUM",
                "confidence": "LOW",
                "explanation": "The FastAPI version in use is outdated. Older versions depend on Pydantic/Starlette versions with known ReDos or parsing bugs.",
                "fix_suggestion": "Upgrade fastapi to version 0.109.0 or higher.",
            }
        ]

    def scan_metadata(self, metadata: RepositoryMetadata) -> List[Finding]:
        """Scans detected dependencies from metadata against our vulnerability database."""
        findings = []
        
        # Metadata contains dependency strings like: package==version or group:artifact==version
        for dep in metadata.configs:
            # We can scan the configuration files themselves, but let's scan the metadata dependencies
            pass

        for dep_str in metadata.dependencies:
            # Parse package and version
            # E.g. django==3.2.5 or axios==1.4.0
            if "==" in dep_str:
                pkg_part, ver_part = dep_str.split("==", 1)
            elif ":" in dep_str and "==" in dep_str:
                # Java Maven format: org.apache.logging.log4j:log4j-core==2.14.1
                pkg_part, ver_part = dep_str.split("==", 1)
            else:
                pkg_part = dep_str
                ver_part = "latest"

            pkg_name = pkg_part.strip().lower()
            pkg_ver = ver_part.strip().strip('"').strip("'")

            # Check matches in database
            for vuln in self.VULN_DB:
                # Match package name pattern
                if re.search(vuln["pattern"], pkg_name, re.IGNORECASE):
                    # Match version regex
                    if re.search(vuln["version_regex"], pkg_ver):
                        # Locate which file declared this (heuristics)
                        declaring_file = "requirements.txt"
                        if ":" in pkg_part or "pom.xml" in metadata.configs:
                            declaring_file = "pom.xml"
                        elif "package.json" in metadata.configs:
                            declaring_file = "package.json"

                        # Find matching file metadata
                        ref_file = declaring_file
                        for f in metadata.files:
                            if f.name.lower() == declaring_file.lower():
                                ref_file = f.relative_path
                                break

                        findings.append(
                            Finding(
                                finding_id=f"dependency-{vuln['package']}-{pkg_ver}",
                                title=vuln["title"],
                                description=f"Vulnerable dependency detected: {pkg_part} version {pkg_ver}",
                                severity=vuln["severity"],
                                confidence=vuln["confidence"],
                                file_path=ref_file,
                                line_number=None,
                                code_snippet=f"{pkg_part}=={pkg_ver}",
                                explanation=vuln["explanation"],
                                fix_suggestion=vuln["fix_suggestion"],
                                category="vulnerable_dependencies",
                            )
                        )

        return findings
