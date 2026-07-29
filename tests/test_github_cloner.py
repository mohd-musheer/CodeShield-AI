import pytest
from unittest import mock
from app.services.clone.github import GitHubCloner

@pytest.fixture
def mock_repo(monkeypatch):
    mock_repo = mock.Mock()
    monkeypatch.setattr('git.Repo.clone_from', mock_repo)
    return mock_repo

def test_clone_valid_url(mock_repo):
    cloner = GitHubCloner()
    cloner.clone('https://github.com/example/repo.git', '/tmp/repo')
    mock_repo.assert_called_once()
    args, kwargs = mock_repo.call_args
    assert args[0] == 'https://github.com/example/repo.git'
    assert args[1] == '/tmp/repo'
    assert kwargs.get('depth') == 1

def test_clone_invalid_url(monkeypatch):
    cloner = GitHubCloner()
    with pytest.raises(ValueError):
        cloner.clone('invalid_url', '/tmp/repo')
