FROM mcr.microsoft.com/playwright/python:v1.50.0-noble

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# mcr.microsoft.com/playwright/python:* already has Chromium and all required
# system libraries installed under /ms-playwright, so we do NOT need to run
# `playwright install --with-deps chromium` here. Doing so on top of this base
# image is a no-op but on a plain python:3.12-slim image it fails on Debian
# because Playwright's `--with-deps` package list assumes Ubuntu 22.04+.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Give uvicorn enough time for slow cold starts on Render's free tier and for
# longer-running requests. FastAPI BackgroundTasks in this app can outlast a
# normal HTTP response window, so we also run with a single worker (the
# in-process scan state is not shared across workers).
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --timeout-keep-alive 75"]

