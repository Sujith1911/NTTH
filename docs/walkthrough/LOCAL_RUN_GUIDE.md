# Local Run Guide

This file explains how to run the project locally in the two main ways:

- local development mode
- Docker stack mode

## 1. Local Development Mode

This mode is best when you want to work quickly on backend APIs and frontend behavior.

### Backend

From the repo root:

```powershell
cd backend
py -3 -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

What happens:

- FastAPI starts on port `8000`
- SQLite is used by default if `DATABASE_URL` is not set
- admin user is seeded if missing
- packet sniffer tries to start
- HTTP honeypot tries to start
- Cowrie watcher tries to start if the log file exists

### Frontend Web

From the repo root:

```powershell
cd flutter_app
flutter pub get
flutter run -d chrome
```

If you want the backend to serve the built frontend:

```powershell
cd flutter_app
flutter build web
```

Then restart the backend so it can serve the built files.

## 2. Docker Stack Mode

This mode is best when you want the full service stack together:

- PostgreSQL
- backend
- Cowrie

From the repo root:

```powershell
cd backend
docker compose up -d --build
```

Check status:

```powershell
docker ps
docker compose logs backend
docker compose logs cowrie
docker compose logs postgres
```

## 3. Main Local URLs

- Backend API: `http://localhost:8000`
- Swagger docs: `http://localhost:8000/docs`
- Frontend via backend: `http://localhost:8000/`
- HTTP honeypot: `http://localhost:8888/`
- Cowrie direct test: `ssh root@localhost -p 30022`

## 4. Default Credentials

- username: `admin`
- password: `changeme`

Change these before any serious deployment.

## 5. What Works Well Locally

- UI testing
- API development
- threat list rendering
- honeypot session rendering
- WebSocket live updates
- direct Cowrie testing

## 6. What Local Windows Testing Does Not Fully Prove

- real host-level nftables enforcement
- exact transparent redirect from a protected victim port
- guaranteed preservation of the real LAN attacker IP through Docker NAT

## 7. Best Local Dev Sequence

1. run backend
2. log into the frontend
3. confirm `/api/v1/system/health`
4. start Cowrie
5. test direct Cowrie SSH
6. confirm sessions appear in Honeypot page
7. then move to Ubuntu gateway lab for real interception testing
