#!/bin/bash
# CodeShield AI Production Startup Helper Script

echo "=========================================================="
echo "🛡️ CodeShield AI - Production Startup Control"
echo "=========================================================="

# Check env file
if [ ! -f ".env" ]; then
    echo "[!] Warning: .env file not found. Copying from .env.example..."
    cp .env.example .env
    echo "[*] Created .env from template. Please configure your GROQ_API_KEY in .env"
fi

# Check Docker compose availability
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "[*] Docker and Docker Compose detected. Starting in container mode..."
    docker-compose up --build -d
    echo "[*] Container launched successfully. Access application at: http://localhost:8000"
    echo "[*] Logs are mapped to: runtime/logs/ and reports to: reports/"
    exit 0
fi

# Local python mode fallback
echo "[!] Docker/Docker Compose not detected. Falling back to local python server..."

# Check python installation
if ! command -v python &> /dev/null; then
    echo "[ERROR] Python is not installed or not in PATH. Please install Python 3.11."
    exit 1
fi

# Create python virtual environment if not exists
if [ ! -d "venv" ] && [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python -m venv venv
    source venv/bin/activate
    echo "[*] Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    if [ -d "venv" ]; then
        source venv/bin/activate
    elif [ -d ".venv" ]; then
        source .venv/bin/activate
    fi
fi

# Check if port 8000 is already in use
if command -v lsof &> /dev/null; then
    PORT_BUSY=$(lsof -i :8000)
    if [ ! -z "$PORT_BUSY" ]; then
        echo "[ERROR] Port 8000 is already in use. Please terminate the conflicting process."
        exit 1
    fi
fi

echo "[*] Starting CodeShield AI Production Server locally..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
