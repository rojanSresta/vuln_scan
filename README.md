# WAVS

WAVS is a React + FastAPI vulnerability scanner with:

- user signup and login
- Postgres-backed sessions and scan history
- PDF report regeneration for past scans
- a Docker Compose Postgres service for local development

## Project Layout

```text
wavs-new/
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── security.py
│   ├── scanner.py
│   ├── report_generator.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   └── package.json
└── docker-compose.yml
```

## 1. Start Postgres

```bash
docker compose up -d
```

This starts a local Postgres 16 instance on `localhost:5432` with:

- database: `wavs`
- username: `wavs`
- password: `wavs`

## 2. Start the Backend

```bash
bash run_backend.sh
```

The backend expects `DATABASE_URL` to point at Postgres. The default already matches the Docker setup:

```bash
postgresql+psycopg://wavs:wavs@localhost:5432/wavs
```

Backend URLs:

- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`

## 3. Start the Frontend

```bash
bash run_frontend.sh
```

The React app runs on `http://localhost:3000`.

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

## Notes

- Scan history is tied to the logged-in user.
- PDF reports can be downloaded again from the history screen.
- Only scan systems you own or are explicitly allowed to test.
