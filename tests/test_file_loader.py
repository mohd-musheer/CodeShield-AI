import os
import tempfile
import shutil
from pathlib import Path

import pytest

from app.services.parser.file_loader import FileLoader

@pytest.fixture
def temp_repo(tmp_path: Path):
    # Create a temporary repository structure
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    # Create a normal text file
    (repo_root / "file.txt").write_text("Hello World")
    # Create a binary file (contains null byte)
    binary_path = repo_root / "binary.bin"
    binary_path.write_bytes(b"\x00\x01\x02")
    # Create a large file (>2MB)
    large_path = repo_root / "large.txt"
    large_path.write_bytes(b"a" * (2 * 1024 * 1024 + 1))
    # Create ignored directory
    ignored_dir = repo_root / "coverage"
    ignored_dir.mkdir()
    (ignored_dir / "ignore.txt").write_text("should be ignored")
    return repo_root

def test_file_loader_filters(temp_repo: Path):
    loader = FileLoader()
    metadata = loader.load_repository(str(temp_repo))
    # Should include only the regular text file
    file_paths = {f.relative_path for f in metadata.files}
    assert "file.txt" in file_paths
    assert "binary.bin" not in file_paths
    assert "large.txt" not in file_paths
    assert "coverage/ignore.txt" not in file_paths

def test_file_loader_handles_permission_error(tmp_path: Path, monkeypatch):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    secret = repo_root / "secret.txt"
    secret.write_text("secret")
    # Remove read permissions
    secret.chmod(0o000)
    loader = FileLoader()
    # Should not raise and simply skip the file
    metadata = loader.load_repository(str(repo_root))
    file_paths = {f.relative_path for f in metadata.files}
    assert "secret.txt" not in file_paths
    # Restore permissions for cleanup
    secret.chmod(0o644)
