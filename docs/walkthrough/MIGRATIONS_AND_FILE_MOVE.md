# Migrations And File Move

## Database Migrations

Migration files live in:

- `backend/alembic/versions/`

Important files:

- `001_initial.py`
- `002_honeypot_flow_context.py`

## Apply Migrations

```powershell
cd backend
alembic upgrade head
```

## Create New Migrations

```powershell
cd backend
alembic revision --autogenerate -m "describe_change"
```

## Important Current Note

Some schema-equivalent changes were previously applied manually in a running Postgres instance, so if you are working with an older live database, check migration state carefully before applying everything blindly.

## If You Mean "Move Files To Ubuntu"

Use one of these:

- shared folder
- `scp`
- git clone or git pull
- zip and copy

## Simple Move Flow

1. Copy the project folder to Ubuntu
2. Keep the same folder structure
3. Rebuild Docker on Ubuntu
4. Run migrations
5. Test backend, frontend, and Cowrie again

## Example

On Windows:

```powershell
scp -r "D:\No Time To Hack" user@ubuntu-host:~/projects/
```

On Ubuntu:

```bash
cd ~/projects/No\ Time\ To\ Hack/backend
docker compose up -d --build
alembic upgrade head
```
