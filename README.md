# VulnScan — OWASP ZAP Vulnerability Scanner

A full-stack web application for automated vulnerability scanning, built with **React**, **FastAPI**, and **OWASP ZAP**.

---

## Project Structure

```
vuln-scanner/
├── backend/
│   ├── main.py               # FastAPI app & scan orchestration
│   ├── zap_scanner.py        # All ZAP API communication
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
| OWASP ZAP | 2.14+ | Security scanner |
| Java | 11+ | Required by ZAP |

---

## Step 1 — Start ZAP in Daemon Mode

ZAP must be running **before** you start the backend.

```bash
# Linux / macOS
zap.sh -daemon -port 8080 -host 127.0.0.1 \
       -config api.key=changeme \
       -config api.addrs.addr.name=.* \
       -config api.addrs.addr.regex=true

# Windows
zap.bat -daemon -port 8080 -host 127.0.0.1 \
        -config api.key=changeme \
        -config api.addrs.addr.name=.* \
        -config api.addrs.addr.regex=true
```

> **Tip:** `zap.sh` / `zap.bat` lives in your ZAP installation directory.
> On macOS with Homebrew it may be at `/Applications/ZAP.app/Contents/Java/zap.sh`.

Verify ZAP is running:
```bash
curl "http://127.0.0.1:8080/JSON/core/view/version/?apikey=changeme"
# Should return {"version":"2.x.x"}
```

---

## Step 2 — Start the FastAPI Backend

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

## Step 3 — Start the React Frontend

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
     │
     │  ZAP REST API (port 8080)
     │  ├─ spider/action/scan        → crawl all pages
     │  ├─ ascan/action/disableAll   → disable all rules
     │  ├─ ascan/action/enable       → enable chosen rules only
     │  ├─ ascan/action/scan         → active attack scan
     │  └─ core/view/alerts          → fetch findings
     │
     │  3. Filter alerts by selected vuln types
     │  4. Enrich with plain-English explanations
     │  5. Return JSON to frontend
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

## Vulnerability Categories & ZAP Rules

| Category | ZAP Plugin IDs |
|----------|---------------|
| SQL Injection | 40018, 40019, 40020, 40021, 40022, 40024, 90018 |
| XSS | 40012, 40014, 40016, 40017 |
| CSRF | 20012 |
| Broken Authentication | 10105, 10200, 10202, 40003 |
| Directory Traversal | 6, 33 |

---

## Configuration

| Setting | Location | Default |
|---------|----------|---------|
| ZAP host/port | `backend/zap_scanner.py` | `127.0.0.1:8080` |
| ZAP API key | `backend/.env` or project `.env` | none |
| Backend URL | `frontend/.env` (create if needed) | `http://localhost:8000` |

To configure the backend ZAP API key:
```bash
# backend/.env
ZAP_API_KEY=your-zap-api-key
```

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

**"Cannot connect to ZAP"**
→ ZAP is not running. Follow Step 1.

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
- [OWASP ZAP](https://www.zaproxy.org) — Security scanning engine
- [ReportLab](https://www.reportlab.com) — PDF generation
- [DM Sans](https://fonts.google.com/specimen/DM+Sans) + [Space Mono](https://fonts.google.com/specimen/Space+Mono) — Typography
