import re
import uuid
from pathlib import Path
from typing import List
from app.models.repository import Finding, RepositoryFile


class SecretScanner:
    """Deterministic scanner to search for exposed secrets, private keys, and passwords."""

    def __init__(self):
        self.RULES = [
            {
                "id": "aws_access_key",
                "title": "AWS Access Key ID Exposure",
                "description": "An AWS Access Key ID was found hardcoded in the file.",
                "regex": r"AKIA[0-9A-Z]{16}",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "secret_exposure",
                "explanation": "Hardcoding cloud credentials exposes the infrastructure to full compromise if the code is public or leaked.",
                "fix_suggestion": "Remove the hardcoded AWS Access Key ID. Use IAM Roles, AWS Secrets Manager, or environment variables.",
            },
            {
                "id": "aws_secret_key",
                "title": "AWS Secret Access Key Exposure",
                "description": "An AWS Secret Access Key was found hardcoded.",
                "regex": r"(?i)aws_secret_access_key\s*[:=]\s*[\"']([a-zA-Z0-9/+=]{40})[\"']",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "secret_exposure",
                "explanation": "Hardcoding cloud credentials exposes the infrastructure to full compromise.",
                "fix_suggestion": "Remove the secret key immediately, rotate the credentials, and use environment variables.",
            },
            {
                "id": "private_key",
                "title": "Private Cryptographic Key Exposure",
                "description": "A private cryptographic key block was found in the file.",
                "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "secret_exposure",
                "explanation": "Exposing private keys allows attackers to decrypt traffic, sign malicious payloads, or impersonate services.",
                "fix_suggestion": "Remove the private key from source control immediately. Use secure vault storage.",
            },
            {
                "id": "db_connection_string",
                "title": "Database Connection String Exposure",
                "description": "A database connection string containing credentials was found.",
                "regex": r"(mongodb(?:\+srv)?|postgres|postgresql|mysql|sqlite|mssql|redis):\/\/([^:]+):([^@]+)@([\w\.-]+)(?::\d+)?\/(\w+)",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "secret_exposure",
                "explanation": "Exposing database credentials allows direct database access and unauthorized data exfiltration or modification.",
                "fix_suggestion": "Remove the connection string credentials. Use placeholders and inject credentials at runtime using environment variables.",
            },
            {
                "id": "generic_credential",
                "title": "Hardcoded API Key or Secret",
                "description": "A potential hardcoded secret, API key, token, or password was detected.",
                "regex": r"(?i)(?:api_key|apikey|secret_key|private_key|auth_token|client_secret|db_password|db_pwd|jwt_secret)\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.\=\+\/\@]{16,})[\"']",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "category": "hardcoded_credentials",
                "explanation": "Hardcoding API keys, passwords, or secrets makes credential rotation difficult and risks exposure in repositories.",
                "fix_suggestion": "Inject these configurations from environment variables or load them from a key management vault.",
            },
            {
                "id": "slack_token",
                "title": "Slack API Token Exposure",
                "description": "A Slack Bot or User token was found hardcoded.",
                "regex": r"xox[bapr]-[0-9a-zA-Z\-]{10,}",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "secret_exposure",
                "explanation": "Slack tokens allow unauthorized interaction with team workspaces, potential data exfiltration, or social engineering attacks.",
                "fix_suggestion": "Rotate the Slack token immediately and move it to a safe secrets configuration.",
            }
        ]

    def scan_file(self, repo_file: RepositoryFile) -> List[Finding]:
        findings = []
        filepath = Path(repo_file.absolute_path)
        if not filepath.exists():
            return []

        # Read file lines
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        for rule in self.RULES:
            pattern = re.compile(rule["regex"])
            for idx, line in enumerate(lines, 1):
                match = pattern.search(line)
                if match:
                    # Capture exact snippet and replace secret with asterisks for security in findings
                    full_match = match.group(0)
                    # Obfuscate secret in the code snippet
                    if len(match.groups()) > 0 and match.group(1):
                        secret = match.group(1)
                        obfuscated = secret[:3] + "*" * (len(secret) - 6) + secret[-3:] if len(secret) > 6 else "*" * len(secret)
                        snippet = line.replace(secret, obfuscated).strip()
                    else:
                        snippet = line.strip()[:100] + "..." if len(line.strip()) > 100 else line.strip()

                    findings.append(
                        Finding(
                            finding_id=f"secret-{rule['id']}-{repo_file.relative_path}-{idx}",
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            file_path=repo_file.relative_path,
                            line_number=idx,
                            code_snippet=snippet,
                            explanation=rule["explanation"],
                            fix_suggestion=rule["fix_suggestion"],
                            category=rule["category"],
                        )
                    )

        return findings
