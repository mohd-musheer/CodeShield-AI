# CodeShield AI 🛡️

CodeShield AI is an enterprise-quality, AI-powered codebase security analyzer. It automates remote repository cloning, dependency listing, intelligent semantic chunking, and leverages Groq's Large Language Models (LLMs) alongside static scanners to detect and remediate vulnerabilities across 22 distinct security categories.

Designed for performance and stability, CodeShield AI groups logical code chunks to minimize API round-trips (avoiding HTTP 429 rate limits), provides interactive side-by-side code diff previews, supports local directory scanning, GitLab repositories, and file uploads.

---

## 🚀 Key Features

- **Multi-Source Inputs**: Support scanning public GitHub repositories, GitLab URLs, local workspace directories, or ZIP archive uploads (with interactive Drag & Drop).
- **Hybrid Security Scanning**: Combines fast regex-based configuration/credential detectors with LLM-powered semantic analysis using Groq.
- **Performance Optimized Chunks**: Automatically groups and merges chunks belonging to the same source file to maximize context density, saving time and keeping scan duration below 10 seconds for standard codebases.
- **Disk-Backed State Machine**: Tracks scan lifecycles via a robust persistent database, surviving server restarts or client page reloads.
- **Detailed Security Insights**: Accompanies findings with OWASP Top 10 mappings, CWE taxonomy references, exploit attack scenarios, business impact descriptions, and unified git patches.
- **Multi-Format Downloads**: Export security reports in HTML, JSON, Markdown, PDF, SARIF (schema compliant), or CSV.
- **AI Integration Prompts**: Exports prompt payloads (`fix_prompt.json`, `.md`, `.txt`) containing ready-to-run instructions to fix vulnerabilities in Claude, Copilot, or Cursor.

---

## 🛠️ Tech Stack

- **Backend**: FastAPI, Uvicorn, GitPython, Pydantic, Python-dotenv, Requests
- **Frontend**: Vanilla HTML5/CSS3 (dynamic glassmorphism, responsive grid layouts, custom scrollbars, Light/Dark/System theme toggles)
- **AI Engine**: Groq Cloud LLM Integration (Llama-3-70b-8192 / Llama-3-8b-8192)

---

## ⚙️ Setup & Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/mohd-musheer/CodeShield-AI.git
   cd CodeShield-AI
   ```

2. **Setup Environment**:
   Create a `.env` file in the root directory:
   ```env
   # API keys
   GROQ_API_KEY=your_groq_api_key_here
   
   # App configuration
   PORT=8000
   HOST=127.0.0.1
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Server**:
   ```bash
   python -m uvicorn app.main:app --port 8000
   ```

5. **Scan via CLI (Testing Script)**:
   ```bash
   python scratch/test_scan.py
   ```

---

## 📊 Directory Structure

```text
CodeShield-AI/
├── app/
│   ├── api/            # API Route Handlers (report, scan, repository, health)
│   ├── core/           # Configuration loaders & exceptions
│   ├── models/         # Pydantic data schemas
│   ├── services/       # Cloners, scanners, AI engine, exporters, pipelines
│   ├── utils/          # State managers, history trackers, path sanitizers
│   └── main.py         # Application entrypoint
├── static/             # Frontend Dashboard HTML, CSS, and JS
├── reports/            # Persistent local reports storage (git-ignored)
├── runtime/            # Persistent states storage (git-ignored)
└── requirements.txt    # Application requirements manifest
```

---

## 📜 License

Distributed under the Apache 2.0 License. See `LICENSE` for details.
