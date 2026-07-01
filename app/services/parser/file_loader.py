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
    }

    def load_repository(
        self,
        repository_path: str,
    ) -> RepositoryMetadata:

        repository = Path(repository_path)

        files = []
        total_size = 0

        for file in repository.rglob("*"):

            if not file.is_file():
                continue

            if any(
                ignored in file.parts
                for ignored in self.IGNORE_DIRECTORIES
            ):
                continue

            stat = file.stat()

            total_size += stat.st_size

            files.append(
                RepositoryFile(
                    name=file.name,
                    extension=file.suffix.lower(),
                    relative_path=str(
                        file.relative_to(repository)
                    ),
                    absolute_path=str(
                        file.resolve()
                    ),
                    size=stat.st_size,
                    modified_time=datetime.fromtimestamp(
                        stat.st_mtime
                    ),
                )
            )

        return RepositoryMetadata(
            repository_name=repository.name,
            repository_path=str(repository.resolve()),
            total_files=len(files),
            total_size=total_size,
            files=files,
        )