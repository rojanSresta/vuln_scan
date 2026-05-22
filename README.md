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

## Project Layout

```text
wavs-new/
├── backend/
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
├── docker-compose.yml
├── .env.example
├── run_backend.sh
└── run_frontend.sh
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

Environment variables are documented in `.env.example`. For Docker, copy it to `.env` and adjust values before `docker compose up`.

| Variable | Purpose |
|----------|---------|
| `REACT_APP_API_URL` | API URL baked into the frontend build (use the host URL the browser will call) |
| `DATABASE_URL` | SQLAlchemy connection string for the backend |
| `CORS_ORIGINS` | Comma-separated browser origins allowed by the API |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Default admin account seeded on startup |

## Notes

- Scan history is tied to the logged-in user.
- PDF reports can be downloaded again from the history screen.
- Only scan systems you own or are explicitly allowed to test.
