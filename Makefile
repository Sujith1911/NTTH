# NO TIME TO HACK — Developer Makefile
# Usage: make <target>

.PHONY: help dev prod test simulate lint flutter-run flutter-build

help:
	@echo ""
	@echo "  NO TIME TO HACK — Developer Commands"
	@echo "  ────────────────────────────────────"
	@echo "  make dev          Start backend in dev mode (SQLite, hot-reload)"
	@echo "  make prod         Start all services via Docker Compose"
	@echo "  make test         Run API integration tests"
	@echo "  make simulate     Inject mixed attack simulation (100 packets)"
	@echo "  make sim-scan     Inject port scan simulation"
	@echo "  make sim-flood    Inject SYN flood simulation"
	@echo "  make lint         Run ruff + mypy on backend"
	@echo "  make flutter-run  Run Flutter app on Windows desktop"
	@echo "  make migrate      Create + apply DB migrations"
	@echo ""

dev:
	cd backend && uvicorn app.main:app --reload --port 8000 --log-level info

prod:
	cd backend && docker compose up -d

stop:
	cd backend && docker compose down

logs:
	cd backend && docker compose logs -f backend

test:
	cd backend && python test_api.py --base-url http://localhost:8000

simulate:
	cd backend && python simulate.py --scenario mixed --count 100

sim-scan:
	cd backend && python simulate.py --scenario port_scan --count 50

sim-flood:
	cd backend && python simulate.py --scenario syn_flood --count 300

sim-brute:
	cd backend && python simulate.py --scenario brute_force --count 60

lint:
	cd backend && ruff check app/ && mypy app/ --ignore-missing-imports

install:
	cd backend && pip install -r requirements.txt

migrate:
	cd backend && alembic revision --autogenerate -m "schema" && alembic upgrade head

flutter-run:
	cd flutter_app && flutter run -d windows

flutter-android:
	cd flutter_app && flutter run -d android

flutter-build-android:
	cd flutter_app && flutter build apk --release

flutter-build-windows:
	cd flutter_app && flutter build windows --release

flush-firewall:
	curl -X POST http://localhost:8000/api/v1/system/emergency-flush \
	  -H "Authorization: Bearer $$(cat /tmp/ntth_token.txt)"
