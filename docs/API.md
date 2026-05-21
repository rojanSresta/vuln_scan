# API Documentation

## Base URL
```
http://localhost:8000/api/v1
```

## Authentication
All endpoints except login/register require a valid JWT token.

### Login
```
POST /auth/login
Body: { username, password }
Response: { token, user }
```

## Scans

### Create Scan
```
POST /scans
Body: {
  "target_url": "https://example.com",
  "vulnerabilities": ["sql_injection", "xss", ...]
}
Response: { scan_id, status, progress }
```

### Get Scan Status
```
GET /scans/{scan_id}
Response: { scan_id, target_url, status, progress, message, results }
```

### Cancel Scan
```
POST /scans/{scan_id}/cancel
Response: { scan_id, status }
```

## History

### List Scans
```
GET /history
Response: { scans: [...] }
```

### Get Scan Results
```
GET /history/{scan_id}
Response: { scan_id, results: [...] }
```

## Admin

### Get Statistics
```
GET /admin/stats
Response: { total_scans, total_vulnerabilities, ... }
```
