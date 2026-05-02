# VulnScan — Manual Web Vulnerability Scanner

A full-stack web application for automated vulnerability scanning, built with **React** and **FastAPI** using a lightweight manual scanning engine.

---

## Project Structure

```
vuln-scanner/
├── backend/
│   ├── main.py               # FastAPI app & scan orchestration
│   ├── manual_scanner.py     # BFS crawler + manual vulnerability checks
│   ├── report_generator.py   # PDF report generation (ReportLab)
│   └── requirements.txt
└── frontend/
    ├── public/
    │   └── index.html
    ├── src/
    │   ├── index.js
    │   ├── index.css
    │   ├── App.jsx            # Main React component
    │   └── App.css
    └── package.json
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.9+ | Backend runtime |
| Node.js | 18+ | Frontend runtime |
## Step 1 — Start the FastAPI Backend

```bash
cd vuln-scanner/backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload --port 8000
```

The API is now available at http://localhost:8000

Swagger docs: http://localhost:8000/docs

---

## Step 2 — Start the React Frontend

```bash
cd vuln-scanner/frontend

# Install dependencies
npm install

# Start development server
npm start
```

Open http://localhost:3000 in your browser.

---

## How It Works

```
Browser (React)
     │
     │  POST /scan/start  { target_url, vulnerabilities }
     ▼
FastAPI (port 8000)
     │
     │  1. Validates URL
     │  2. Starts background task
     │  3. Crawls the target with BFS
     │  4. Runs manual checks for the selected vulnerability classes
     │  5. Returns normalized findings to the frontend
     ▼
Browser renders results table
     │
     │  GET /scan/report/{id}
     ▼
FastAPI generates PDF (ReportLab) → browser downloads
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/scan/start` | Start a new scan |
| GET | `/scan/status/{id}` | Poll scan progress |
| GET | `/scan/results/{id}` | Fetch final results |
| GET | `/scan/report/{id}` | Download PDF report |

### Example request

```bash
curl -X POST http://localhost:8000/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "vulnerabilities": ["sql_injection", "xss"]
  }'
```

---

## Vulnerability Categories & Manual Checks

| Category | Heuristic Used |
|----------|---------------|
| SQL Injection | Inject simple SQL payloads into discovered query parameters and look for SQL errors / server faults |
| XSS | Reflect a script payload through query params or forms and check whether it comes back unescaped |
| CSRF | Inspect POST forms for missing CSRF-style hidden tokens |
| Broken Authentication | Check for insecure login forms, session IDs in URLs, and weak session cookie flags |
| Directory Traversal | Probe file-like parameters with traversal payloads and look for known sensitive file markers |

---

## Configuration

| Setting | Location | Default |
|---------|----------|---------|
| Backend URL | `frontend/.env` (create if needed) | `http://localhost:8000` |

To change the backend URL for the frontend:
```bash
# frontend/.env
REACT_APP_API_URL=http://localhost:8000
```

---

## Testing Against Safe Targets

Use these intentionally vulnerable sites for testing:

- **DVWA** (local): https://github.com/digininja/DVWA
- **WebGoat** (local): https://github.com/WebGoat/WebGoat
- **testphp.vulnweb.com** (Acunetix demo site — scan at your own risk)

> ⚠️ **Only scan systems you own or have explicit written permission to test.**

---

## Troubleshooting

**"Scan failed"**
→ Ensure the backend is running and that the target site is reachable from the machine running FastAPI.

**CORS errors in browser**
→ Ensure FastAPI is running on port 8000 and the `proxy` in `package.json` matches.

**Spider / scan times out**
→ Increase `timeout` values in `main.py` `_wait_for_spider` / `_wait_for_active_scan`.

**PDF download fails**
→ `reportlab` not installed. Run `pip install reportlab` inside your venv.

---

## Built With

- [React 18](https://react.dev) — Frontend UI
- [FastAPI](https://fastapi.tiangolo.com) — Backend API
- [ReportLab](https://www.reportlab.com) — PDF generation
- [DM Sans](https://fonts.google.com/specimen/DM+Sans) + [Space Mono](https://fonts.google.com/specimen/Space+Mono) — Typography
