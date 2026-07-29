import json
import re
from pathlib import Path
from typing import List, Tuple
from app.models.repository import RepositoryMetadata


class DependencyDetector:
    """Detects dependencies, frameworks, and configs in a repository."""

    def __init__(self):
        # Maps configuration file names/patterns to descriptive names
        self.CONFIG_PATTERNS = {
            r"dockerfile.*": "Dockerfile",
            r"docker-compose.*\.ya?ml": "Docker Compose",
            r"package\.json": "NPM Config",
            r"requirements\.txt": "Pip Requirements",
            r"pyproject\.toml": "Python Project Settings",
            r"pom\.xml": "Maven Config",
            r"build\.gradle": "Gradle Config",
            r"go\.mod": "Go Module Config",
            r"cargo\.toml": "Cargo Config",
            r"\.env.*": "Environment File",
            r"k8s.*\.ya?ml": "Kubernetes Manifest",
            r"deployment.*\.ya?ml": "Kubernetes Manifest",
            r"service.*\.ya?ml": "Kubernetes Manifest",
        }

    def detect(self, metadata: RepositoryMetadata) -> RepositoryMetadata:
        repo_path = Path(metadata.repository_path)
        
        detected_configs = []
        detected_deps = []
        detected_frameworks = []

        # Find CI/CD configuration files
        github_workflows = repo_path / ".github" / "workflows"
        if github_workflows.exists() and github_workflows.is_dir():
            for f in github_workflows.glob("*.yml"):
                detected_configs.append(f"GitHub Action: {f.name}")
            for f in github_workflows.glob("*.yaml"):
                detected_configs.append(f"GitHub Action: {f.name}")

        # Scan files in repository
        for repo_file in metadata.files:
            file_name_lower = repo_file.name.lower()
            rel_path = repo_file.relative_path

            # Detect config files by name/pattern
            for pattern, name in self.CONFIG_PATTERNS.items():
                if re.match(pattern, file_name_lower):
                    detected_configs.append(f"{name} ({rel_path})")

            # Parse packages and framework hints
            abs_path = Path(repo_file.absolute_path)
            if not abs_path.exists():
                continue

            try:
                if file_name_lower == "package.json":
                    deps, frameworks = self._parse_package_json(abs_path)
                    detected_deps.extend(deps)
                    detected_frameworks.extend(frameworks)
                elif file_name_lower == "requirements.txt":
                    deps, frameworks = self._parse_requirements_txt(abs_path)
                    detected_deps.extend(deps)
                    detected_frameworks.extend(frameworks)
                elif file_name_lower == "pyproject.toml":
                    deps, frameworks = self._parse_pyproject_toml(abs_path)
                    detected_deps.extend(deps)
                    detected_frameworks.extend(frameworks)
                elif file_name_lower == "go.mod":
                    deps, frameworks = self._parse_go_mod(abs_path)
                    detected_deps.extend(deps)
                    detected_frameworks.extend(frameworks)
                elif file_name_lower == "pom.xml":
                    deps, frameworks = self._parse_pom_xml(abs_path)
                    detected_deps.extend(deps)
                    detected_frameworks.extend(frameworks)
            except Exception:
                # Silently catch parsing errors to avoid crashing the analyzer
                pass

        # Deduplicate results
        metadata.configs = sorted(list(set(detected_configs)))
        metadata.dependencies = sorted(list(set(detected_deps)))
        
        # Deduplicate frameworks and add basic language-based defaults if empty
        deduped_frameworks = list(set(detected_frameworks))
        
        # General heuristics if no frameworks were found in dependency files
        has_python = any(f.extension == ".py" for f in metadata.files)
        has_js = any(f.extension in [".js", ".jsx", ".ts", ".tsx"] for f in metadata.files)
        
        if not deduped_frameworks:
            if has_python:
                deduped_frameworks.append("Python Codebase")
            if has_js:
                deduped_frameworks.append("NodeJS Codebase")
                
        metadata.frameworks = sorted(deduped_frameworks)
        return metadata

    def _parse_package_json(self, path: Path) -> Tuple[List[str], List[str]]:
        deps = []
        frameworks = []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
            # Combine dependencies and devDependencies
            all_deps = {}
            if "dependencies" in data and isinstance(data["dependencies"], dict):
                all_deps.update(data["dependencies"])
            if "devDependencies" in data and isinstance(data["devDependencies"], dict):
                all_deps.update(data["devDependencies"])

            for dep, ver in all_deps.items():
                deps.append(f"{dep}=={ver}")
                # Framework indicators
                if dep == "express":
                    frameworks.append("Express.js")
                elif dep == "react":
                    frameworks.append("React")
                elif dep in ["next", "next-auth"]:
                    frameworks.append("Next.js")
                elif dep == "@nestjs/core":
                    frameworks.append("NestJS")
                elif dep == "vue":
                    frameworks.append("Vue.js")
                elif dep == "angular":
                    frameworks.append("Angular")
        return deps, frameworks

    def _parse_requirements_txt(self, path: Path) -> Tuple[List[str], List[str]]:
        deps = []
        frameworks = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Normalize line (split on comment, split on comparison)
                line_clean = line.split("#")[0].strip()
                if not line_clean:
                    continue
                deps.append(line_clean)
                
                # Check framework indicators (case insensitive)
                line_lower = line_clean.lower()
                if "fastapi" in line_lower:
                    frameworks.append("FastAPI")
                elif "django" in line_lower:
                    frameworks.append("Django")
                elif "flask" in line_lower:
                    frameworks.append("Flask")
                elif "tornado" in line_lower:
                    frameworks.append("Tornado")
        return deps, frameworks

    def _parse_pyproject_toml(self, path: Path) -> Tuple[List[str], List[str]]:
        deps = []
        frameworks = []
        # Fallback to simple regex parsing if toml library is not installed
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Rough parser for toml dependency blocks
        # Look for lines in [tool.poetry.dependencies] or [project.dependencies]
        in_dep_section = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and ("dependencies" in line or "requires" in line):
                in_dep_section = True
                continue
            elif line.startswith("["):
                in_dep_section = False
                
            if in_dep_section and line and "=" in line and not line.startswith("#"):
                parts = line.split("=")
                dep_name = parts[0].strip().strip('"').strip("'")
                dep_ver = parts[1].split("#")[0].strip().strip('"').strip("'")
                deps.append(f"{dep_name}=={dep_ver}")

                dep_lower = dep_name.lower()
                if "fastapi" in dep_lower:
                    frameworks.append("FastAPI")
                elif "django" in dep_lower:
                    frameworks.append("Django")
                elif "flask" in dep_lower:
                    frameworks.append("Flask")
        return deps, frameworks

    def _parse_go_mod(self, path: Path) -> Tuple[List[str], List[str]]:
        deps = []
        frameworks = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("require"):
                    # Single line requirement: require github.com/gin-gonic/gin v1.7.0
                    parts = line.split()
                    if len(parts) >= 3:
                        deps.append(f"{parts[1]}=={parts[2]}")
                        if "gin-gonic/gin" in parts[1]:
                            frameworks.append("Gin (Go)")
                        elif "fiber" in parts[1]:
                            frameworks.append("Fiber (Go)")
                elif line.startswith(")") or line.startswith("module") or line.startswith("go "):
                    continue
                else:
                    # Inside a require ( ... ) block
                    parts = line.split()
                    if len(parts) >= 2:
                        deps.append(f"{parts[0]}=={parts[1]}")
                        if "gin-gonic/gin" in parts[0]:
                            frameworks.append("Gin (Go)")
                        elif "fiber" in parts[0]:
                            frameworks.append("Fiber (Go)")
        return deps, frameworks

    def _parse_pom_xml(self, path: Path) -> Tuple[List[str], List[str]]:
        deps = []
        frameworks = []
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Simple regex extraction of group and artifact IDs
        dependencies = re.findall(r"<dependency>([\s\S]*?)</dependency>", content)
        for dep in dependencies:
            group_id = re.search(r"<groupId>([^<]+)</groupId>", dep)
            artifact_id = re.search(r"<artifactId>([^<]+)</artifactId>", dep)
            version = re.search(r"<version>([^<]+)</version>", dep)
            
            g = group_id.group(1).strip() if group_id else ""
            a = artifact_id.group(1).strip() if artifact_id else ""
            v = version.group(1).strip() if version else "latest"
            
            if g and a:
                deps.append(f"{g}:{a}=={v}")
                if "spring-boot" in a or "spring-framework" in g:
                    frameworks.append("Spring Boot")
        return deps, frameworks
