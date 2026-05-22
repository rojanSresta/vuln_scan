# System Architecture

## Overview
Vulnerability Scanner is a manual vulnerability assessment tool that helps identify common web application security issues.

## Backend Structure

### API Layer (`app/api/`)
- `router.py` - Main API router combining all route modules
- `routes/` - Endpoint definitions (scans, history, admin)
- `deps.py` - FastAPI dependencies (authentication, etc.)
- `exceptions.py` - Custom HTTP exceptions

### Services Layer (`app/services/`)
- `scan_jobs.py` - Scan job management and persistence
- `scanning/` - Core vulnerability scanning logic
  - `service.py` - Main scanner orchestrator
  - `base.py` - Base classes and shared utilities
  - `common.py` - Shared probe/submit functions
  - `checks/` - Individual vulnerability checks

### Database Layer (`app/db/`)
- `models.py` - SQLAlchemy models
- `session.py` - Database session management
- `repositories/` - Data access layer (ScanRepository, UserRepository)

### Configuration (`app/config.py`, `app/constants.py`)
- `config.py` - Environment-based settings
- `constants.py` - All magic strings and constants

## Frontend Structure

### Constants (`src/constants/`)
- `api.js` - API endpoint definitions
- `vulnerability.js` - Vulnerability types and risk levels
- `messages.js` - UI messages

### Components (`src/components/`)
Organized by feature:
- `layout/` - Layout components (Topbar, Sidebar)
- `auth/` - Authentication components
- `scan/` - Scanning interface components
- `history/` - History view components
- `results/` - Results display components
- `admin/` - Admin dashboard components

### Hooks (`src/hooks/`)
- `useAuth.js` - Authentication logic
- `useScanner.js` - Scanner state management
- `useAdminPanel.js` - Admin panel logic

### Services (`src/services/`)
- API communication services

## Data Flow

```
Frontend (React)
    ↓
API Layer (FastAPI)
    ↓
Services Layer (Business Logic)
    ↓
Database Layer (SQLAlchemy)
```

## Key Design Patterns

1. **Repository Pattern** - Data access abstraction
2. **Service Pattern** - Business logic encapsulation
3. **Component Pattern** - Reusable UI components
4. **Hooks Pattern** - React state management
