# CodeShield AI Production Startup Helper Script (Windows PowerShell)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🛡️ CodeShield AI - Production Startup Control (Windows)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check env file
if (-not (Test-Path ".env")) {
    Write-Host "[!] Warning: .env file not found. Copying from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "[*] Created .env from template. Please configure your GROQ_API_KEY in .env" -ForegroundColor Green
}

# Check Docker availability
$dockerAvailable = $null
$composeAvailable = $null

try {
    $dockerCheck = Get-Command docker -ErrorAction SilentlyContinue
    $composeCheck = Get-Command docker-compose -ErrorAction SilentlyContinue
    if ($dockerCheck -and $composeCheck) {
        $dockerAvailable = $true
        $composeAvailable = $true
    }
} catch {}

if ($dockerAvailable -and $composeAvailable) {
    Write-Host "[*] Docker and Docker Compose detected. Starting in container mode..." -ForegroundColor Green
    docker-compose up --build -d
    Write-Host "[*] Container launched successfully. Access application at: http://localhost:8000" -ForegroundColor Green
    Write-Host "[*] Logs are mapped to: runtime/logs/ and reports to: reports/" -ForegroundColor Green
    Exit
}

# Local python mode fallback
Write-Host "[!] Docker/Docker Compose not detected. Falling back to local python server..." -ForegroundColor Yellow

# Check python
$pythonCheck = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCheck) {
    Write-Host "[ERROR] Python is not installed or not in PATH. Please install Python 3.11." -ForegroundColor Red
    Exit 1
}

# Create virtual environment if not exists
if (-not (Test-Path "venv") -and -not (Test-Path ".venv")) {
    Write-Host "[*] Creating virtual environment..." -ForegroundColor Green
    python -m venv venv
    & .\venv\Scripts\Activate.ps1
    Write-Host "[*] Installing dependencies..." -ForegroundColor Green
    python -m pip install --upgrade pip
    pip install -r requirements.txt
} else {
    if (Test-Path "venv") {
        & .\venv\Scripts\Activate.ps1
    } elseif (Test-Path ".venv") {
        & .\.venv\Scripts\Activate.ps1
    }
}

# Check if port 8000 is already in use or not
$portCheck = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($portCheck) {
    Write-Host "[ERROR] Port 8000 is already in use. Please terminate the conflicting process." -ForegroundColor Red
    Exit 1
}

Write-Host "[*] Starting CodeShield AI Production Server locally..." -ForegroundColor Green
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
