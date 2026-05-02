# Backend Setup

The backend now uses a built-in manual scanner. There is no OWASP ZAP dependency.

## Start the backend

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`.

## What the scanner does

- Crawls the target site with a small BFS crawler.
- Extracts same-origin links and forms.
- Runs five manual checks: SQL injection, XSS, CSRF, broken authentication, and directory traversal.

## Notes

- Only scan systems you own or are explicitly allowed to test.
- The scanner uses lightweight heuristics, so it favors simplicity over exhaustive coverage.
