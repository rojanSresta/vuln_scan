# Backend ZAP setup

This backend now expects OWASP ZAP to run in Docker instead of requiring a locally installed desktop app.

## Configure

Create or update `.env` in this directory:

```env
ZAP_API_KEY=changeme
ZAP_BASE_URL=http://127.0.0.1:8080
```

`ZAP_BASE_URL` should stay `http://127.0.0.1:8080` when the backend runs on your host machine and ZAP runs through the included Docker Compose file.

## Start ZAP

```bash
docker compose up -d zap
```

To stop it:

```bash
docker compose stop zap
```

To inspect logs:

```bash
docker compose logs -f zap
```

## Start the backend

```bash
uvicorn main:app --reload
```

The backend will connect to the ZAP API exposed by the container on port `8080`.
