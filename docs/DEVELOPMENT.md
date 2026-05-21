# Development Guide

## Backend Setup

### Prerequisites
- Python 3.9+
- pip

### Installation
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Running
```bash
cd backend
python -m uvicorn app.main:app --reload
```

### Environment Variables
Create `.env` file:
```
DATABASE_URL=sqlite:///./test.db
SECRET_KEY=your-secret-key
CORS_ORIGINS=["http://localhost:3000"]
```

## Frontend Setup

### Prerequisites
- Node.js 14+
- npm

### Installation
```bash
cd frontend
npm install
```

### Running
```bash
cd frontend
npm start
```

### Build
```bash
npm run build
```

## Code Organization

### Backend
- Keep business logic in `services/`
- API endpoints in `api/routes/`
- Database models in `db/models.py`
- All constants in `app/constants.py`

### Frontend
- Components in `src/components/`
- API calls through `src/services/`
- Constants in `src/constants/`
- Styling in `src/styles/`
