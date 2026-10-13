# Installation

Avron's recommended setup uses Docker Compose. It builds Nuclei into the scanner image and runs PostgreSQL, Redis, the API, and a Celery worker as separate services.

## Docker Compose

### Requirements

- Docker Engine with the Compose plugin
- Network access to download the images, Python dependencies, and Nuclei templates
- Ports 8000, 5432, and 6379 available on the local machine

### Start

1. Copy `.env.example` to `.env` and set unique values for `DB_PASSWORD` and `SCANNER_API_KEY`. Do not commit `.env`.
2. From the repository root, run:

   ```sh
   docker compose up --build -d
   docker compose ps
   ```

3. Check <http://localhost:8000/health> and open <http://localhost:8000/docs> for the REST API.

Compose binds its published ports to `127.0.0.1`. The API key is required for scan endpoints. Set `NVD_API_KEY` only if you want higher NVD request limits for CVE enrichment.

### Stop and inspect

```sh
docker compose logs -f scanner worker
docker compose down
```

Database and scan volumes persist across normal `down` and `up` commands. `docker compose down --volumes` removes that local data.

### Run tests in Docker

```sh
docker compose --profile test run --build --rm scanner-test
```

The Compose test profile runs isolated unit tests; it does not launch real scans or require a live target.

## Run from a Python environment

Use Python 3.13 or later, PostgreSQL, Redis, and a Nuclei binary on `PATH`. For production use, build from the Dockerfile so the Nuclei version is reproducible. Install packages and configure the database and broker URLs:

```sh
python -m venv .venv
python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env`, then set `SCANNER_API_KEY`, `DATABASE_URL`, `DATABASE_URL_SYNC`, and `REDIS_URL` for the local services. The database URLs must contain the correct username, password, host, and database name. Apply migrations and start the API and worker in separate terminals:

```sh
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```sh
celery -A app.celery_worker worker --loglevel=info --concurrency=2
```

Run the MCP stdio server from a trusted local MCP client only. With Compose services already running, `docker compose run --rm --no-deps -T scanner python -m app.mcp_server` uses the same database and queue configuration as the API.

## Upgrade

Pull the new source or image, install the pinned dependencies, then run `alembic upgrade head` before restarting the API and worker. Review the changelog for schema and behavior changes before upgrading a persistent deployment.
