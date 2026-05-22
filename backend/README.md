# Backend Setup

## Database

The backend now uses Postgres for:

- user accounts
- login sessions
- persisted scan history
- report lookup metadata

Default connection string:

```bash
postgresql+psycopg://wavs:wavs@localhost:5432/wavs
```

Start Postgres from the project root:

```bash
docker compose up -d
```

## Run the API

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Key Endpoints

- `POST /auth/signup`
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/logout`
- `POST /scan/start`
- `GET /history`
- `GET /history/{scan_id}`
- `GET /scan/report/{scan_id}`

## Notes

- Tables are created automatically on startup.
- Scan execution is still asynchronous, but the scan record is now persisted immediately.
- Completed reports are regenerated on demand if the saved file path no longer exists.
