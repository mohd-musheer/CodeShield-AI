from typing import List, Dict
from app.models.repository import Finding, SecurityScore


class SecurityScorer:
    """Computes a detailed security score from 100, penalizing critical/high issues."""

    def __init__(self):
        # Deductions by severity
        self.DEDUCTIONS = {
            "CRITICAL": 20,
            "HIGH": 12,
            "MEDIUM": 6,
            "LOW": 2,
        }

        # Mapping of fine-grained categories to high-level dashboard score categories
        self.MAP_HIGH_LEVEL = {
            "sql_injection": "Input Validation",
            "command_injection": "Input Validation",
            "path_traversal": "Input Validation",
            "xss": "Input Validation",
            "csrf": "Input Validation",
            "unsafe_file_upload": "Input Validation",
            "ssrf": "Input Validation",
            "missing_input_validation": "Input Validation",
            "unsafe_shell_usage": "Input Validation",
            
            "broken_authentication": "Authentication",
            "broken_authorization": "Authentication",
            "weak_jwt_handling": "Authentication",
            
            "secret_exposure": "Secrets",
            "hardcoded_credentials": "Secrets",
            
            "vulnerable_dependencies": "Dependencies",
            
            "insecure_config": "Configuration",
            "dangerous_cors": "Configuration",
            "insecure_ci_cd_settings": "Configuration",
            "exposed_debug_endpoints": "Configuration",
            
            "insecure_docker_setup": "Docker",
            
            "weak_crypto": "Cryptography",
            "insecure_deserialization": "Cryptography",
        }

        self.HIGH_LEVEL_CATEGORIES = [
            "Authentication",
            "Secrets",
            "Dependencies",
            "Configuration",
            "Docker",
            "Input Validation",
            "Logging",
            "Cryptography"
        ]

    def calculate_score(self, findings: List[Finding]) -> SecurityScore:
        overall_score = 100
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        # Track deductions per high-level category
        category_deductions = {cat: 0 for cat in self.HIGH_LEVEL_CATEGORIES}

        for f in findings:
            sev = f.severity.upper()
            if sev not in self.DEDUCTIONS:
                sev = "MEDIUM"

            if sev in severity_breakdown:
                severity_breakdown[sev] += 1

            deduction = self.DEDUCTIONS[sev]
            overall_score -= deduction
            
            # Map low-level category to high-level dashboard category
            cat = f.category.lower()
            high_level_cat = self.MAP_HIGH_LEVEL.get(cat, "Configuration")
            
            if high_level_cat in category_deductions:
                category_deductions[high_level_cat] += deduction

        # Make sure overall score is bounded between 0 and 100
        overall_score = max(0, min(100, overall_score))

        # Calculate score for each category (starts at 100, deducts up to 100)
        category_scores = {}
        for cat in self.HIGH_LEVEL_CATEGORIES:
            deduct = category_deductions[cat]
            # Bounded between 0 and 100
            category_scores[cat] = max(0, 100 - deduct)

        # Detailed risk summary
        risk_summary = self._generate_summary(overall_score, severity_breakdown)

        return SecurityScore(
            overall_score=overall_score,
            severity_breakdown=severity_breakdown,
            category_scores=category_scores,
            risk_summary=risk_summary,
        )

    def _generate_summary(self, score: int, breakdown: Dict[str, int]) -> str:
        total_issues = sum(breakdown.values())
        
        if total_issues == 0:
            return "No security issues were found. The codebase follows good security practices and configuration guidelines."

        summary_parts = []
        if score >= 90:
            summary_parts.append(
                f"Secure (Score {score}/100). The repository has a strong security posture. Only minor issues were detected."
            )
        elif score >= 70:
            summary_parts.append(
                f"Moderate Risk (Score {score}/100). The repository is generally solid but contains {breakdown.get('HIGH', 0)} High and {breakdown.get('MEDIUM', 0)} Medium vulnerability findings."
            )
        elif score >= 40:
            summary_parts.append(
                f"High Risk (Score {score}/100). Multiple significant security vulnerabilities have been identified. We detected {breakdown.get('CRITICAL', 0)} Critical and {breakdown.get('HIGH', 0)} High severity issues."
            )
        else:
            summary_parts.append(
                f"Critical Risk (Score {score}/100). The codebase contains critical security flaws or exposed credentials ({breakdown.get('CRITICAL', 0)} Critical issues found). Remediation is required immediately."
            )

        details = []
        if breakdown.get("CRITICAL", 0) > 0:
            details.append(f"{breakdown['CRITICAL']} Critical credentials or RCE risks")
        if breakdown.get("HIGH", 0) > 0:
            details.append(f"{breakdown['HIGH']} High severity exposures")
        if breakdown.get("MEDIUM", 0) > 0:
            details.append(f"{breakdown['MEDIUM']} Medium severity bugs")
        if breakdown.get("LOW", 0) > 0:
            details.append(f"{breakdown['LOW']} Low severity suggestions")

        if details:
            summary_parts.append("Key findings include: " + ", ".join(details) + ".")

        return " ".join(summary_parts)
