# E-Library Management System

A simple Django project for managing an e-library.

## Setup

1. Create virtual environment:
   ```bash
   python -m venv venv
   ```

2. Activate virtual environment:
   ```bash
   # Windows
   venv\Scripts\activate
   # Linux/Mac
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create `.env` file (copy from `.env.example`):
   ```bash
   cp .env.example .env
   ```

5. Run migrations:
   ```bash
   python manage.py migrate
   ```

6. Run the development server:
   ```bash
   python manage.py runserver
   ```

7. Visit http://localhost:8000/health/ for health check

## Health Check Endpoint

- **HTML UI**: http://localhost:8000/health/
- **JSON API**: `curl -H "Accept: application/json" http://localhost:8000/health/`
