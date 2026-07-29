from collections import defaultdict

from app.models.repository import (
    RepositoryMetadata,
    LanguageStatistics,
)


class LanguageDetector:

    EXTENSION_MAP = {

        ".py": "Python",

        ".js": "JavaScript",

        ".jsx": "React",

        ".ts": "TypeScript",

        ".tsx": "React TypeScript",

        ".java": "Java",

        ".kt": "Kotlin",

        ".cpp": "C++",

        ".cc": "C++",

        ".c": "C",

        ".h": "C/C++",

        ".hpp": "C++",

        ".cs": "C#",

        ".go": "Go",

        ".rs": "Rust",

        ".php": "PHP",

        ".rb": "Ruby",

        ".swift": "Swift",

        ".scala": "Scala",

        ".dart": "Dart",

        ".html": "HTML",

        ".css": "CSS",

        ".scss": "SCSS",

        ".sass": "SASS",

        ".json": "JSON",

        ".yaml": "YAML",

        ".yml": "YAML",

        ".xml": "XML",

        ".toml": "TOML",

        ".md": "Markdown",

        ".sql": "SQL",

        ".sh": "Shell",

        ".bat": "Batch",

        ".ps1": "PowerShell",

        ".dockerfile": "Dockerfile",
    }

    def detect(
        self,
        metadata: RepositoryMetadata,
    ) -> RepositoryMetadata:

        stats = defaultdict(
            lambda: {
                "files": 0,
                "size": 0,
            }
        )

        for file in metadata.files:

            language = self.EXTENSION_MAP.get(
                file.extension,
                "Unknown"
            )

            stats[language]["files"] += 1

            stats[language]["size"] += file.size

        metadata.languages = [

            LanguageStatistics(
                language=language,
                files=data["files"],
                size=data["size"],
            )

            for language, data in stats.items()

        ]

        return metadata