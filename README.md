# CodeShield AI 🛡️

[![CI Pipeline](https://github.com/mohd-musheer/CodeShield-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/mohd-musheer/CodeShield-AI/actions/workflows/ci.yml)
[![Security Scan](https://github.com/mohd-musheer/CodeShield-AI/actions/workflows/security.yml/badge.svg)](https://github.com/mohd-musheer/CodeShield-AI/actions/workflows/security.yml)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker Support](https://img.shields.io/badge/Docker-Supported-blue.svg?logo=docker)](Dockerfile)

CodeShield AI is a state-of-the-art, enterprise-quality codebase security analyzer. It automates remote repository cloning, dependency mapping, code structural analysis, and leverages Groq's Large Language Models (LLMs) alongside static scanners to detect, score, and automatically remediate vulnerabilities.

---

## 🛠️ Architecture

```text
               ┌───────────────────────────────────────────────┐
               │              Web Dashboard / CLI              │
               └──────────────────────┬────────────────────────┘
                                      │
                                      ▼
               ┌───────────────────────────────────────────────┐
               │           FastAPI Web API Endpoints           │
               └──────────────────────┬────────────────────────┘
                                      │
                                      ▼
               ┌───────────────────────────────────────────────┐
               │      ScanStateManager (Disk Persistence)      │
               └──────────────────────┬────────────────────────┘
                                      │
                                      ▼
               ┌───────────────────────────────────────────────┐
               │     PipelineManager (Background Worker)       │
               └─┬──────────────────┬──────────────────────┬───┘
                 │                  │                      │
                 ▼                  ▼                      ▼
        ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
        │  GitHub/GitLab │ │ Code Chunker & │ │ Static Regex & │
        │ Cloner Service │ │ Compatible     │ │ LLM Semantic   │
        │                │ │ Merger (Groq)  │ │ Scanner        │
        └────────────────┘ └────────────────┘ └────────────────┘
```

---

## 🚀 Key Features

- **Multi-Source Code Loading**: Scan remote public GitHub/GitLab repositories, local directories, or ZIP archive uploads with drag-and-drop.
- **Smart Chunk Grouping**: Groups compatible code segments by file into unified prompts (up to 15,000 characters) to optimize Groq LLM context windows, bypass HTTP 429 rate limits, and run scans in under 10 seconds.
- **Disk-Backed State Machine**: Remembers scan progress across server restarts and connection interruptions.
- **Interactive Code Modals**: Provides full code highlighting alongside side-by-side vulnerable vs. remediated code views.
- **Unified Diff Patches**: Generates drop-in `.diff` patches and pre-formated AI prompt logs (`fix_prompt.json`, `.md`, `.txt`) to fix codebase security flaws.
- **Multi-Format Reports**: Downloader supports SARIF, CSV, JSON, Markdown, HTML, and Mock PDF formats.

---

## 🐳 Docker Deployment

### 1. Build and Run via Docker Compose (Recommended)
Launch the full container stack (including mounted volumes for logs and reports):
```bash
# Provide your GROQ API Key in the shell environment or in .env
export GROQ_API_KEY="your_groq_api_key"

# Build and start services
docker-compose up --build -d
```
Access the application at `http://localhost:8000`.

### 2. Manual Docker Build
Build and run the container locally in detached mode (`-d`), specifying your `GROQ_API_KEY` and `GROQ_MODEL` configuration:
```bash
# Build the Docker image
docker build -t codeshield-ai .

# Run the container in detached mode
docker run -d -p 8000:8000 -e GROQ_API_KEY="your_groq_api_key_here" -e GROQ_MODEL="llama-3.3-70b-versatile" codeshield-ai
```

### 3. Pull Published Release Image
CodeShield AI automatically publishes container builds to GitHub Container Registry (GHCR) on tagged releases. Pull and run the official image:
```bash
# Pull the latest image
docker pull ghcr.io/mohd-musheer/codeshield-ai:latest

# Run the container in detached mode
docker run -d -p 8000:8000 -e GROQ_API_KEY="your_groq_api_key_here" -e GROQ_MODEL="llama-3.3-70b-versatile" ghcr.io/mohd-musheer/codeshield-ai:latest
```


---

## 💻 Local Installation (Development)

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/mohd-musheer/CodeShield-AI.git
   cd CodeShield-AI
   ```

2. **Configure Environment Settings**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and paste your `GROQ_API_KEY`.

3. **Start the Production Service**:
   Run the quick-start script:
   - **Linux / macOS**:
     ```bash
     chmod +x start.sh
     ./start.sh
     ```
   - **Windows (PowerShell)**:
     ```powershell
     .\start.ps1
     ```

---

## 📘 API Documentation

CodeShield AI exposes REST endpoints for integration:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/repository/analyze` | Triggers background codebase security scans. |
| `POST` | `/repository/upload` | Uploads a ZIP codebase archive for parsing. |
| `POST` | `/repository/cancel/{scan_id}` | Aborts a running scan and cleans up disk cache. |
| `GET` | `/scan/status/{scan_id}` | Retrieves active progress metrics and current stage. |
| `GET` | `/repository/report` | Downloads report in `json`, `html`, `markdown`, `sarif`, `csv`, `pdf`, `patch_diff`, or `fix_prompt`. |
| `GET` | `/health` | Server status and API liveness metrics. |

---

## ⚡ Performance Benchmarks

| Project Size | Total Chunks | Merged Groq Calls | Total Scan Duration |
| :--- | :--- | :--- | :--- |
| Small (1-50 Files) | 3-10 | 1 | 2-4 seconds |
| Medium (50-200 Files) | 30-80 | 3-5 | 6-9 seconds |
| Large (200+ Files) | 200+ | 12-15 | 15-20 seconds |

---

## 🗺️ Roadmap

- [ ] Support private repositories via SSH Keys and Git Credential Helper.
- [ ] Add native Semgrep rules integration alongside Groq semantic scans.
- [ ] Implement multi-tenant users management and workspace segregation.
- [ ] Provide slack and webhook notification alerts on completed scans.

---

## 📜 License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
