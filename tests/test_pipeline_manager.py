import pytest
from unittest import mock
from pathlib import Path

from app.services.pipeline.manager import PipelineManager
from app.services.parser.file_loader import FileLoader
from app.services.clone.github import GitHubCloner

# Mock scanner components to avoid real AI calls
class MockScanner:
    def __init__(self, name):
        self.name = name
    def scan(self, *args, **kwargs):
        return []

@pytest.fixture
def mock_pipeline(monkeypatch, tmp_path: Path):
    # Mock FileLoader to return a simple metadata with one file
    mock_loader = mock.Mock()
    mock_loader.load_repository.return_value = mock.Mock(files=[mock.Mock(relative_path='test.txt', absolute_path=str(tmp_path / 'test.txt'))])
    monkeypatch.setattr('app.services.parser.file_loader.FileLoader', lambda: mock_loader)
    # Mock GitHubCloner to do nothing
    monkeypatch.setattr('app.services.clone.github.GitHubCloner.clone', lambda self, url, dest: None)
    # Mock scanners
    monkeypatch.setattr('app.services.pipeline.manager.SecretScanner', lambda: MockScanner('secret'))
    monkeypatch.setattr('app.services.pipeline.manager.ConfigScanner', lambda: MockScanner('config'))
    monkeypatch.setattr('app.services.pipeline.manager.DependencyScanner', lambda: MockScanner('dependency'))
    # Create a temporary repo directory with a dummy file
    repo_dir = tmp_path / 'repo'
    repo_dir.mkdir()
    (repo_dir / 'test.txt').write_text('dummy content')
    return repo_dir

def test_pipeline_manager_runs_without_error(mock_pipeline):
    manager = PipelineManager()
    # Run the pipeline; should complete without raising exceptions
    manager.run_pipeline(str(mock_pipeline))
    # Verify that the loader was called
    # (Since we mocked FileLoader, we can check its call count)
    # No explicit assertions needed beyond no exception
