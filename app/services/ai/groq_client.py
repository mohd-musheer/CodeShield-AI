import json
import logging
import os
import requests
import time
from typing import List, Dict, Any, Optional
from app.core.config import GROQ_API_KEY, GROQ_MODEL
from app.models.repository import RepositoryChunk, Finding

logger = logging.getLogger("CodeShieldAI.GroqClient")


class GroqRateLimitException(Exception):
    """Exception raised when Groq API rate limit is exceeded after retrying."""
    pass


class GroqAIScanner:
    """Uses Groq's LLM to semantically analyze code chunks for vulnerabilities."""

    def __init__(self):
        self.api_key = GROQ_API_KEY
        self.model = GROQ_MODEL
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"

    def scan_chunk(self, chunk: RepositoryChunk) -> List[Finding]:
        """Scans a single repository code chunk using Groq LLM API with 429 rate limit retry logic."""
        if not self.api_key:
            logger.warning("Groq API key not set. Skipping semantic scan.")
            return []

        if len(chunk.content.strip()) < 40:
            return []

        # Construct prompt
        system_prompt = (
            "You are a Senior Application Security Engineer. Your task is to analyze the provided code chunk for security vulnerabilities. "
            "Scan for the following security risks:\n"
            "- SQL injection\n"
            "- Command injection\n"
            "- Path traversal\n"
            "- Cross-Site Scripting (XSS)\n"
            "- Cross-Site Request Forgery (CSRF)\n"
            "- Broken authentication or authorization\n"
            "- Insecure deserialization\n"
            "- Weak cryptographic algorithms\n"
            "- Unsafe file uploads\n"
            "- Server-Side Request Forgery (SSRF)\n"
            "- Insecure CORS settings\n"
            "- Exposed debug endpoints\n"
            "- Weak JWT handling (e.g., no verification, HS256 with weak key)\n"
            "- Hardcoded credentials or tokens\n"
            "- Missing input validation or sanitization\n"
            "- Unsafe shell executions\n\n"
            "You MUST respond ONLY with a JSON object. Do not include markdown formatting like ```json or any explanations outside the JSON structure. "
            "The JSON structure must match this schema:\n"
            "{\n"
            "  \"findings\": [\n"
            "    {\n"
            "      \"title\": \"Short descriptive title\",\n"
            "      \"description\": \"Brief description of the finding\",\n"
            "      \"severity\": \"CRITICAL\" or \"HIGH\" or \"MEDIUM\" or \"LOW\",\n"
            "      \"confidence\": \"HIGH\" or \"MEDIUM\" or \"LOW\",\n"
            "      \"line_number\": 12, (estimate line number relative to the start of this chunk, or null if unknown)\n"
            "      \"code_snippet\": \"The specific code line triggering the vulnerability\",\n"
            "      \"explanation\": \"Detailed explanation of the risk and how an attacker can exploit it\",\n"
            "      \"fix_suggestion\": \"Clear code instructions on how to patch the issue\",\n"
            "      \"category\": \"One of: sql_injection, command_injection, path_traversal, xss, csrf, broken_authentication, broken_authorization, secret_exposure, insecure_deserialization, weak_crypto, unsafe_file_upload, ssrf, insecure_config, vulnerable_dependencies, exposed_debug_endpoints, dangerous_cors, weak_jwt_handling, hardcoded_credentials, missing_input_validation, unsafe_shell_usage\",\n"
            "      \"owasp\": \"OWASP Top 10 category reference, e.g. A01:2021-Broken Access Control (or null)\",\n"
            "      \"cwe\": \"CWE reference number, e.g. CWE-89 (or null)\",\n"
            "      \"attack_scenario\": \"Step-by-step exploit scenario indicating how it can be attacked\",\n"
            "      \"business_impact\": \"Direct operational or safety impact to the business system\",\n"
            "      \"references\": [\"List of relevant external URLs or documentation references\"],\n"
            "      \"patch\": \"Unified git diff format patch content starting with --- and +++ representing the file modification\"\n"
            "    }\n"
            "  ]\n"
            "}"
        )

        user_prompt = (
            f"File Path: {chunk.file_path}\n"
            f"Chunk Type: {chunk.chunk_type}\n"
            f"Chunk Block Name: {chunk.name}\n"
            f"Start Line Number: {chunk.start_line}\n"
            f"Code Content:\n"
            f"```\n"
            f"{chunk.content}\n"
            f"```"
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

        # Attempt up to 2 times total (1 retry) on 429
        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(self.api_url, headers=headers, json=payload, timeout=20)
                
                if response.status_code == 429:
                    if attempt < max_attempts:
                        # Wait for a short backoff (2 seconds) and retry once
                        time.sleep(2)
                        continue
                    else:
                        raise GroqRateLimitException("Groq API rate limit exceeded after retrying.")

                if response.status_code != 200:
                    logger.error(f"Groq API returned error {response.status_code}: {response.text}")
                    return []

                res_data = response.json()
                llm_text = res_data["choices"][0]["message"]["content"].strip()
                parsed = json.loads(llm_text)
                raw_findings = parsed.get("findings", [])
                
                findings = []
                for item in raw_findings:
                    rel_line = item.get("line_number")
                    abs_line = chunk.start_line
                    if rel_line is not None:
                        try:
                            rel_val = int(rel_line)
                            if rel_val < chunk.start_line:
                                abs_line = chunk.start_line + rel_val - 1
                            else:
                                abs_line = rel_val
                        except ValueError:
                            pass
                    
                    finding_id = f"ai-{item.get('category')}-{chunk.file_path}-{abs_line}"
                    
                    findings.append(
                        Finding(
                            finding_id=finding_id,
                            title=item.get("title", "AI Vulnerability Finding"),
                            description=item.get("description", "Vulnerability detected by LLM analysis."),
                            severity=item.get("severity", "MEDIUM").upper(),
                            confidence=item.get("confidence", "MEDIUM").upper(),
                            file_path=chunk.file_path,
                            line_number=abs_line,
                            code_snippet=item.get("code_snippet"),
                            explanation=item.get("explanation", ""),
                            fix_suggestion=item.get("fix_suggestion", ""),
                            category=item.get("category", "insecure_config"),
                            owasp=item.get("owasp"),
                            cwe=item.get("cwe"),
                            attack_scenario=item.get("attack_scenario"),
                            business_impact=item.get("business_impact"),
                            references=item.get("references") or [],
                            patch=item.get("patch")
                        )
                    )
                return findings

            except requests.exceptions.Timeout:
                logger.error(f"Timeout scanning chunk {chunk.chunk_id} with Groq.")
                return []
            except GroqRateLimitException as e:
                # Re-raise rate limit exception to be handled by the pipeline manager
                raise e
            except Exception as e:
                logger.error(f"Error scanning chunk {chunk.chunk_id} with Groq: {str(e)}")
                return []

        return []
