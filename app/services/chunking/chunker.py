import ast
import re
import uuid
from pathlib import Path
from typing import List
from app.models.repository import RepositoryChunk, RepositoryFile


class CodeChunker:
    """Splits source code and config files into logical chunks (functions, classes, modules, configs)."""

    def chunk_file(self, repo_file: RepositoryFile) -> List[RepositoryChunk]:
        filepath = Path(repo_file.absolute_path)
        if not filepath.exists():
            return []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        if not content.strip():
            return []

        ext = repo_file.extension
        relative_path = repo_file.relative_path

        if ext == ".py":
            return self._chunk_python(content, relative_path)
        elif ext in [".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".cpp", ".c", ".cs", ".php"]:
            return self._chunk_brace_languages(content, relative_path, ext)
        elif ext in [".json", ".yaml", ".yml", ".toml", ".ini", ".conf"]:
            return self._chunk_config_file(content, relative_path)
        else:
            return self._chunk_text_fallback(content, relative_path)

    def _chunk_python(self, content: str, relative_path: str) -> List[RepositoryChunk]:
        """Uses Python's AST to partition code into Classes, Functions, and Module level code."""
        chunks = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # If there's a syntax error, fallback to line-based brace or text fallback
            return self._chunk_text_fallback(content, relative_path)

        lines = content.splitlines()

        # Helper to extract chunk content
        def get_lines_content(start_idx: int, end_idx: int) -> str:
            # AST line numbers are 1-based and inclusive
            return "\n".join(lines[start_idx - 1 : end_idx])

        # Track what lines have been chunked
        chunked_lines = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Skip nested functions (they will be captured inside their parent)
                if any(isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)) for parent in ast.walk(node)):
                    # Wait, walk goes top-down. If we find a function inside another function,
                    # the parent function will already capture it. But let's check:
                    pass
                
                # Check if this function is inside a class
                # We'll just define it as a standalone chunk if it's top-level, or part of class
                # Actually, capturing both classes and functions is fine, we just want smart divisions.
                start = node.lineno
                end = getattr(node, "end_lineno", start) # end_lineno is Python 3.8+
                
                # Double check to prevent duplicates if already covered by another chunk
                chunk_lines_range = range(start, end + 1)
                if not any(l in chunked_lines for l in chunk_lines_range):
                    chunk_content = get_lines_content(start, end)
                    if chunk_content.strip():
                        chunks.append(
                            RepositoryChunk(
                                chunk_id=f"{relative_path}#fn-{node.name}-{start}",
                                file_path=relative_path,
                                chunk_type="function",
                                name=node.name,
                                content=chunk_content,
                                start_line=start,
                                end_line=end,
                            )
                        )
                        chunked_lines.update(chunk_lines_range)

            elif isinstance(node, ast.ClassDef):
                start = node.lineno
                end = getattr(node, "end_lineno", start)
                chunk_lines_range = range(start, end + 1)
                if not any(l in chunked_lines for l in chunk_lines_range):
                    chunk_content = get_lines_content(start, end)
                    if chunk_content.strip():
                        chunks.append(
                            RepositoryChunk(
                                chunk_id=f"{relative_path}#class-{node.name}-{start}",
                                file_path=relative_path,
                                chunk_type="class",
                                name=node.name,
                                content=chunk_content,
                                start_line=start,
                                end_line=end,
                            )
                        )
                        chunked_lines.update(chunk_lines_range)

        # Grab remaining module level code (globals, imports, etc.) in blocks of up to 100 lines
        uncovered = []
        start_line = None
        
        for i, line in enumerate(lines, 1):
            if i not in chunked_lines:
                if start_line is None:
                    start_line = i
                uncovered.append(line)
                
                if len(uncovered) >= 100 or i == len(lines):
                    chunk_content = "\n".join(uncovered)
                    if chunk_content.strip():
                        chunks.append(
                            RepositoryChunk(
                                chunk_id=f"{relative_path}#module-{start_line}",
                                file_path=relative_path,
                                chunk_type="module",
                                name="module_scope",
                                content=chunk_content,
                                start_line=start_line,
                                end_line=i,
                            )
                        )
                    uncovered = []
                    start_line = None
            else:
                if uncovered:
                    chunk_content = "\n".join(uncovered)
                    if chunk_content.strip():
                        chunks.append(
                            RepositoryChunk(
                                chunk_id=f"{relative_path}#module-{start_line}",
                                file_path=relative_path,
                                chunk_type="module",
                                name="module_scope",
                                content=chunk_content,
                                start_line=start_line,
                                end_line=i - 1,
                            )
                        )
                    uncovered = []
                    start_line = None

        return chunks

    def _chunk_brace_languages(self, content: str, relative_path: str, ext: str) -> List[RepositoryChunk]:
        """Heuristic brace-matching chunker for C++, Java, JS, TS, Go, PHP."""
        chunks = []
        lines = content.splitlines()
        
        # Regex to detect class/function signatures
        # Examples: function name(x) {, class Name {, Name.prototype.func = {, public void name() {
        signature_regex = re.compile(
            r"(class\s+\w+|function\s+\w+|\w+\s+\w+\s*\(.*\)\s*\{|const\s+\w+\s*=\s*\(.*\)\s*=>\s*\{|\w+\.prototype\.\w+|func\s+\(.*\)\s+\w+|\w+\s+func\s+\w+)"
        )

        current_chunk_lines = []
        start_line = 1
        brace_count = 0
        in_structural_block = False
        block_name = "general"
        block_type = "module"

        for idx, line in enumerate(lines, 1):
            current_chunk_lines.append(line)
            
            # Simple brace counting
            brace_count += line.count("{")
            brace_count -= line.count("}")

            # Look for function/class signatures to start a structural block
            if not in_structural_block and brace_count > 0:
                match = signature_regex.search(line)
                if match:
                    in_structural_block = True
                    matched_str = match.group(0)
                    if "class " in matched_str:
                        block_type = "class"
                        block_name = re.search(r"class\s+(\w+)", matched_str).group(1) if re.search(r"class\s+(\w+)", matched_str) else "Class"
                    else:
                        block_type = "function"
                        block_name = re.search(r"(?:function|func)\s+(\w+)", matched_str).group(1) if re.search(r"(?:function|func)\s+(\w+)", matched_str) else "function"

            # End of structural block (brace count returns to zero or less)
            if in_structural_block and brace_count <= 0:
                chunk_content = "\n".join(current_chunk_lines)
                if chunk_content.strip():
                    chunks.append(
                        RepositoryChunk(
                            chunk_id=f"{relative_path}#{block_type}-{block_name}-{start_line}",
                            file_path=relative_path,
                            chunk_type=block_type,
                            name=block_name,
                            content=chunk_content,
                            start_line=start_line,
                            end_line=idx,
                        )
                    )
                current_chunk_lines = []
                start_line = idx + 1
                brace_count = 0
                in_structural_block = False
                block_name = "general"
                block_type = "module"
                
            # If a generic chunk grows too large (e.g. 120 lines), cut it
            elif not in_structural_block and len(current_chunk_lines) >= 120:
                chunk_content = "\n".join(current_chunk_lines)
                if chunk_content.strip():
                    chunks.append(
                        RepositoryChunk(
                            chunk_id=f"{relative_path}#module-{start_line}",
                            file_path=relative_path,
                            chunk_type="module",
                            name="module_scope",
                            content=chunk_content,
                            start_line=start_line,
                            end_line=idx,
                        )
                    )
                current_chunk_lines = []
                start_line = idx + 1
                brace_count = 0

        # Handle remaining lines
        if current_chunk_lines:
            chunk_content = "\n".join(current_chunk_lines)
            if chunk_content.strip():
                chunks.append(
                    RepositoryChunk(
                        chunk_id=f"{relative_path}#module-{start_line}",
                        file_path=relative_path,
                        chunk_type=block_type if in_structural_block else "module",
                        name=block_name if in_structural_block else "module_scope",
                        content=chunk_content,
                        start_line=start_line,
                        end_line=len(lines),
                    )
                )

        return chunks

    def _chunk_config_file(self, content: str, relative_path: str) -> List[RepositoryChunk]:
        """Divides JSON, YAML, TOML config files by top-level sections or groups."""
        chunks = []
        lines = content.splitlines()

        # For YAML/TOML, split by top-level blocks or headings
        # Examples: [section] in TOML, or key: in YAML at indent 0
        current_chunk_lines = []
        start_line = 1
        section_name = "root"

        for idx, line in enumerate(lines, 1):
            # Check for header indicators
            toml_match = re.match(r"^\[([\w\-\.\s]+)\]", line)
            yaml_match = re.match(r"^([\w\-]+):\s*$", line) or re.match(r"^([\w\-]+):\s*\{", line)
            
            is_new_section = False
            new_section_name = ""

            if toml_match:
                is_new_section = True
                new_section_name = toml_match.group(1)
            elif yaml_match:
                is_new_section = True
                new_section_name = yaml_match.group(1)

            if is_new_section and current_chunk_lines:
                chunk_content = "\n".join(current_chunk_lines)
                if chunk_content.strip():
                    chunks.append(
                        RepositoryChunk(
                            chunk_id=f"{relative_path}#config-{section_name}-{start_line}",
                            file_path=relative_path,
                            chunk_type="config",
                            name=section_name,
                            content=chunk_content,
                            start_line=start_line,
                            end_line=idx - 1,
                        )
                    )
                current_chunk_lines = [line]
                start_line = idx
                section_name = new_section_name
            else:
                current_chunk_lines.append(line)

            # Max size for config blocks
            if len(current_chunk_lines) >= 150:
                chunk_content = "\n".join(current_chunk_lines)
                if chunk_content.strip():
                    chunks.append(
                        RepositoryChunk(
                            chunk_id=f"{relative_path}#config-{section_name}-{start_line}",
                            file_path=relative_path,
                            chunk_type="config",
                            name=section_name,
                            content=chunk_content,
                            start_line=start_line,
                            end_line=idx,
                        )
                    )
                current_chunk_lines = []
                start_line = idx + 1
                section_name = f"section-{idx+1}"

        if current_chunk_lines:
            chunk_content = "\n".join(current_chunk_lines)
            if chunk_content.strip():
                chunks.append(
                    RepositoryChunk(
                        chunk_id=f"{relative_path}#config-{section_name}-{start_line}",
                        file_path=relative_path,
                        chunk_type="config",
                        name=section_name,
                        content=chunk_content,
                        start_line=start_line,
                        end_line=len(lines),
                    )
                )

        return chunks

    def _chunk_text_fallback(self, content: str, relative_path: str) -> List[RepositoryChunk]:
        """Simple line-count fallback for HTML, CSS, MD, or unknown files."""
        chunks = []
        lines = content.splitlines()
        chunk_size = 100
        
        for i in range(0, len(lines), chunk_size):
            chunk_lines = lines[i : i + chunk_size]
            chunk_content = "\n".join(chunk_lines)
            start_line = i + 1
            end_line = min(i + chunk_size, len(lines))
            
            if chunk_content.strip():
                chunks.append(
                    RepositoryChunk(
                        chunk_id=f"{relative_path}#block-{start_line}",
                        file_path=relative_path,
                        chunk_type="general",
                        name="code_block",
                        content=chunk_content,
                        start_line=start_line,
                        end_line=end_line,
                    )
                )
        return chunks
