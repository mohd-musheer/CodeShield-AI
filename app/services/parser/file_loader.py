import os
from pathlib import Path
from datetime import datetime

from app.models.repository import (
    RepositoryFile,
    RepositoryMetadata,
)


class FileLoader:

    IGNORE_DIRECTORIES = {
        ".git",
        "__pycache__",
        ".idea",
        ".vscode",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        ".pytest_cache",
        "coverage",  # added to ignore test coverage dir
    }

    def load_repository(
        self,
        repository_path: str,
    ) -> RepositoryMetadata:

        repository = Path(repository_path)

        files = []
        total_size = 0

        for file in repository.rglob("*"):
            # Skip non-files
            if not file.is_file():
                continue

            # Skip ignored directories
            if any(ignored in file.parts for ignored in self.IGNORE_DIRECTORIES):
                continue

            # Ensure file is readable; skip if cannot be opened
            try:
                with open(file, "r", encoding="utf-8", errors="ignore") as f_check:
                    f_check.read(1)
                stat_info = file.stat()
            except Exception:
                continue
            # Skip large files (>2MB)
            if stat_info.st_size > 2 * 1024 * 1024:
                continue

            # Read a small chunk to detect binary (null byte)
            try:
                with open(file, "rb") as f:
                    chunk = f.read(1024)
                if b"\x00" in chunk:
                    continue
            except Exception:
                continue

            # Verify file can be opened in text mode (skip unreadable files on Windows)
            try:
                with open(file, "r", encoding="utf-8", errors="ignore") as f_text:
                    f_text.read(1)
            except Exception:
                continue

            total_size += stat_info.st_size

            files.append(
                RepositoryFile(
                    name=file.name,
                    extension=file.suffix.lower(),
                    relative_path=str(file.relative_to(repository)),
                    absolute_path=str(file.resolve()),
                    size=stat_info.st_size,
                    modified_time=datetime.fromtimestamp(stat_info.st_mtime),
                )
            )

        return RepositoryMetadata(
            repository_name=repository.name,
            repository_path=str(repository.resolve()),
            total_files=len(files),
            total_size=total_size,
            files=files,
        )