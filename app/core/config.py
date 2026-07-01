import os
import tempfile
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[2]

# Workspace directory for cloned/extracted repositories.
# MUST be outside the project root to prevent uvicorn watchfiles from
# triggering a server reload when files are created during scanning.
_default_clone_dir = os.path.join(tempfile.gettempdir(), "CodeShieldAI", "workspaces")
CLONE_DIRECTORY = os.getenv("CLONE_DIRECTORY", _default_clone_dir)

# Persistent state directory — survives server restarts
SCAN_STATE_DIR = os.getenv("SCAN_STATE_DIR", str(BASE_DIR / "runtime"))

# Per-scan log directory
SCAN_LOG_DIR = os.getenv("SCAN_LOG_DIR", str(BASE_DIR / "runtime" / "logs"))

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")