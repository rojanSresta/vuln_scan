# Deployment

## Topology

- **Frontend** → Vercel (static build of `frontend/`)
- **Backend** → Render (Docker, `backend/Dockerfile`)
- **Database** → Neon (Postgres)

## Why XSS appears to "work" locally but not in production

The XSS check (`backend/app/scanner/xss_check.py`) confirms reflected XSS by
launching headless Chromium via Playwright and waiting for an `alert()` dialog.
Three things must be true in production for this to find findings:

1. The browser can actually launch in the deployed environment.
2. The browser request from the deployed frontend can reach the deployed
   backend (CORS is configured).
3. The scan can run for as long as it needs without being killed mid-flight.

Each of these has a common failure mode that produces the "XSS doesn't work"
symptom. The fixes for all three are in this repo. Verify each one in turn
before assuming a code bug.

### 1. Chromium must be installed in the backend image

The old `backend/Dockerfile` was based on `python:3.12-slim-bookworm` and ran
`playwright install --with-deps chromium`. That call assumes Ubuntu 22.04+
package names; on Debian bookworm it either fails at build time or
"succeeds" but installs the wrong versions of `libnspr4` / `libgbm` / `libdrm`,
and Chromium then refuses to launch at runtime with a `PlaywrightError`. The
old XSS code caught that error and returned an empty finding list — so the
scan would appear to run, just never report XSS.

**Fix:** the Dockerfile now uses the official Playwright Python image
(`mcr.microsoft.com/playwright/python:v1.50.0-noble`) as its base. Chromium
and all its system dependencies are pre-installed there; we no longer need
`playwright install --with-deps` at build time. Set
`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` to make that explicit.

`requirements.txt` pins `playwright==1.50.0` to match that image. If pip
installs a newer Playwright while the image still ships 1.50 browsers,
Chromium fails to launch at runtime.

The XSS check launches Chromium with `--no-sandbox` and
`--disable-dev-shm-usage`, which are required in most container hosts
(including Render).

If you'd rather keep the slim base image, you must use a Playwright version
that has Debian-compatible `apt-get` recipes, and you must install the
following packages explicitly in the Dockerfile (this is what `--with-deps`
expands to on Ubuntu 22.04+ but is not exactly what bookworm has):

```Dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libpango-1.0-0 libcairo2 libasound2 libatspi2.0-0 fonts-liberation
```

The Playwright image is the more reliable path.

### 2. CORS must allow the Vercel frontend origin

If `CORS_ORIGINS` is not set on Render, the backend falls back to
`http://localhost:3000,http://127.0.0.1:3000`. Your Vercel frontend is at
something like `https://wavs.example.com`, and the browser will block every
request to the API with a CORS error. The frontend's `fetch` will reject
with a network error, but the scan UI's `useScanner.startScan` will surface
that as a generic "Request failed" — which can look like "XSS scan started
but no results came back." This affects every API call, not just XSS, but
you only notice it for scans because they take long enough to look at.

**Fix:** on Render, set:

| Variable | Value |
|----------|-------|
| `CORS_ORIGINS` | Your Vercel frontend URL, e.g. `https://wavs.example.com` |
| `APP_ENV` | `production` (makes the loud warning log appear if CORS is still missing) |

If you have preview deployments on Vercel, also include those
(`https://*-yourteam.vercel.app,https://your-prod-domain.com`).

### 3. The scan must not be tied to the request lifecycle

The previous `ScanController.start` used FastAPI's `BackgroundTasks`, which
queues a coroutine to run *after* the HTTP response is sent. On Render (and
most PaaS), if the worker process is recycled, restarted, or scaled, that
background coroutine can be killed. In addition, the XSS check uses
`sync_playwright`, which is fully blocking — running it inside the asyncio
event loop freezes `/health` and `/scan/status` polling for the entire scan
duration, so the UI shows "Scanning" with no progress updates.

**Fix:** the controller now starts the scan in a real OS thread
(`threading.Thread`, daemon mode) before the response is sent. The thread is
unaffected by request lifecycle and runs the blocking Playwright code
off the event loop. To keep the in-process scan state consistent, the
Dockerfile now starts uvicorn with `--workers 1`.

## Required environment variables

### Vercel (frontend)

Set **Root Directory** to `frontend` in Project Settings → General. The repo
includes `frontend/vercel.json` with `npm ci` (no `--prefix frontend`). If Root
Directory is `frontend` but the install command still uses
`npm --prefix frontend ci`, npm looks for `frontend/frontend/package-lock.json`
and the build fails.

Alternatively leave Root Directory empty and use the root `vercel.json`, which
runs `cd frontend && npm ci`.

| Variable | Value |
|----------|-------|
| `REACT_APP_API_URL` | Your Render backend URL, e.g. `https://wavs-api.onrender.com` (no trailing slash) |

`REACT_APP_API_URL` is read at **build time**. After changing it you must
redeploy. If the env var is missing the frontend console logs a clear
warning pointing at this variable.

### Render (backend)

| Variable | Value |
|----------|-------|
| `DATABASE_URL` | Neon connection string, e.g. `postgresql+psycopg://user:pass@ep-xxx.us-east-2.aws.neon.tech/wavs?sslmode=require` |
| `CORS_ORIGINS` | Your Vercel frontend origin, comma-separated for multiple envs |
| `APP_ENV` | `production` |
| `ADMIN_EMAIL` | First-run admin email |
| `ADMIN_PASSWORD` | First-run admin password |
| `ADMIN_FULL_NAME` | First-run admin display name |

Set the **Docker** runtime on Render, with `Dockerfile` path
`backend/Dockerfile` and the context directory set to `backend/` (or root if
you adjust the Dockerfile paths).

### Neon (database)

- Create a Postgres project in Neon.
- Copy the **pooled** connection string (it includes `?sslmode=require` and
  uses the `-pooler` host). The default `psycopg` driver in the backend
  supports this directly.
- Use it as `DATABASE_URL` on Render.

## Sanity checks after deploy

1. `curl https://<your-render-backend>.onrender.com/health` → `{"status":"ok"}`
   - If this times out, the cold start is in progress (free tier can take
     30-60s). Wait and retry.
   - If it returns 502/503, check the Render build logs for the Playwright
     base image pulling successfully.
2. Open the Vercel frontend, sign in. Open DevTools → Network. Start an
   XSS-only scan. You should see:
   - `POST /scan/start` → 200
   - `GET /scan/status/<id>` → 200 every 3s with `progress` incrementing
   - `GET /scan/results/<id>` → 200 with the XSS finding (for a vulnerable target)
3. If you see a CORS error in the browser console, `CORS_ORIGINS` is wrong
   on Render.
4. If you see the scan stuck at "Scanning" forever and never reaching 100%,
   check the Render service logs for a `PlaywrightError` or
   `libnspr4 / libnss3 / libgbm` errors — the Chromium base image is wrong.
5. The "XSS browser confirmation skipped" message you may now see in the
   error path is intentional: it means Playwright truly isn't available
   in that environment, and the scan honestly reports that instead of
   silently returning no findings.

## Local development

`docker compose up --build` from the repo root. The compose file already
mounts the source for hot-reload and uses the local Postgres service, so
you don't need Neon running locally.
