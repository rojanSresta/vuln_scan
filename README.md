# WAVS

WAVS is a React + FastAPI vulnerability scanner with:

- user signup and login
- Postgres-backed sessions and scan history
- PDF report regeneration for past scans
- Docker Compose for a one-command full stack

## Quick Start (Docker — recommended)

Requires [Docker](https://docs.docker.com/get-docker/) and Docker Compose.

```bash
# From the project root
cp .env.example .env   # optional; defaults work for local use
docker compose up --build
```

When all services are healthy:

| Service  | URL |
|----------|-----|
| App      | http://localhost:3000 |
| API      | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

Default admin (created on first startup):

- Email: `admin@wavs.local`
- Password: `admin12345`

For production, edit `.env` before the first startup and replace the database
password, admin password, public API URL, and CORS origins.

Stop the stack:

```bash
docker compose down
```

Remove database data as well:

```bash
docker compose down -v
```

## Manual Setup (without Docker)

### 1. Start Postgres

```bash
docker compose up -d postgres
```

This starts Postgres 16 on `localhost:5432` with:

- database: `wavs`
- username: `wavs`
- password: `wavs`

### 2. Start the Backend

```bash
bash run_backend.sh
```

The backend expects `DATABASE_URL` to point at Postgres. The default matches the Docker Postgres service:

```bash
postgresql+psycopg://wavs:wavs@localhost:5432/wavs
```

Backend URLs:

- API: http://localhost:8000
- Swagger: http://localhost:8000/docs

### 3. Start the Frontend

```bash
bash run_frontend.sh
```

The React dev server runs on http://localhost:3000.

## Project Layout (OOP)

```text
vuln_scan/
├── backend/app/
│   ├── main.py                 # App entry
│   ├── config.py               # Settings
│   ├── security.py             # PasswordHasher, TokenFactory
│   ├── router.py               # Registers controllers
│   ├── controllers/            # HTTP layer (classes)
│   │   ├── auth_controller.py
│   │   ├── scan_controller.py
│   │   ├── history_controller.py
│   │   └── admin_controller.py
│   ├── services/               # Business logic (classes)
│   │   ├── auth_service.py
│   │   ├── scan_service.py
│   │   ├── history_service.py
│   │   ├── admin_service.py
│   │   └── report_service.py
│   ├── scanner/                # Vulnerability engine (classes)
│   │   ├── scan_engine.py
│   │   ├── sql_check.py, xss_check.py, path_check.py, ...
│   │   └── payloads/
│   ├── database/               # ORM models
│   │   ├── models.py
│   │   ├── connection.py
│   │   └── setup.py
│   └── schemas/                # Request/response models
├── frontend/src/
│   ├── components/             # UI (unchanged look)
│   ├── hooks/
│   └── services/api_client.js  # ApiClient class
├── docker-compose.yml
└── run_backend.sh / run_frontend.sh
```

## Main API Endpoints

Auth:

- `POST /auth/signup`
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`

Scanning:

- `POST /scan/start`
- `GET /scan/status/{scan_id}`
- `GET /scan/results/{scan_id}`
- `GET /scan/report/{scan_id}`

History:

- `GET /history`
- `GET /history/{scan_id}`

## Configuration

Environment variables are split by runtime:

- Root `.env.example` is for Docker Compose only, because Compose automatically reads `.env` from the project root.
- `backend/.env.example` is for manual backend runs.
- `frontend/.env.example` is for manual React runs and production frontend builds.

| Variable | Purpose |
|----------|---------|
| `APP_ENV` | Runtime profile label for local or production deployment tooling |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | Docker Postgres database, user, and password |
| `REACT_APP_API_URL` | API URL baked into the frontend build (use the host URL the browser will call) |
| `REACT_APP_TOKEN_KEY` / `REACT_APP_ADMIN_TOKEN_KEY` | Browser localStorage keys for user and admin sessions |
| `DATABASE_URL` | SQLAlchemy connection string for the backend |
| `CORS_ORIGINS` | Comma-separated browser origins allowed by the API |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` / `ADMIN_FULL_NAME` | Default admin account seeded on startup |

## Notes

- Scan history is tied to the logged-in user.
- PDF reports can be downloaded again from the history screen.
- Only scan systems you own or are explicitly allowed to test.
