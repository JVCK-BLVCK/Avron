# Avron

![Python 3.13](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)

**Avron is an API-first web security scanner that runs controlled Nuclei scans and returns findings through an authenticated REST API and optional MCP tools.**

## What it does

- Accepts HTTP and HTTPS targets and blocks private, reserved, and non-global addresses. The worker revalidates and pins DNS results before scanning.
- Queues scans with Celery and Redis, persists scan state and findings in PostgreSQL, and exposes status through a REST API.
- Offers MCP tools for scan submission, status, target history, CVE/EPSS enrichment, reports, and scan comparison.
- Provides API-key authentication, per-IP rate limits, health checks, and optional Prometheus metrics.
- Runs in Docker Compose with database migrations and a dedicated scanner worker.

See [the installation guide](docs/installation.md) for local and container setup, [the API and MCP reference](docs/api-cli.md) for interfaces, and [the architecture overview](docs/architecture.md) for design details.

## Quick start with Docker Compose

### Requirements

- Docker Engine and the Docker Compose plugin
- Network access for the initial image build and Nuclei template updates

### Configure and start

Copy the example environment file and replace the two required placeholder values with unique secrets. Generate a value with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

```sh
cp .env.example .env
```

In PowerShell, use `Copy-Item .env.example .env`. Edit `.env`, then start the services:

```sh
docker compose up --build -d
docker compose ps
```

The API is at <http://localhost:8000>. Interactive REST documentation is at <http://localhost:8000/docs>; the unauthenticated health check is at <http://localhost:8000/health>.

Compose publishes the API, PostgreSQL, and Redis on loopback for local development. Configure a reviewed HTTPS reverse proxy and network access controls before allowing access from other hosts.

### Submit and poll a scan

Replace the example target with a system you own or have explicit permission to assess. Avron only accepts targets that resolve to globally routable addresses.

```sh
curl -X POST http://localhost:8000/scan \
  -H "X-API-KEY: <SCANNER_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://your-authorized-domain.example"}'
```

Use the returned `scan_id` to retrieve status and findings:

```sh
curl http://localhost:8000/scan/<SCAN_ID> \
  -H "X-API-KEY: <SCANNER_API_KEY>"
```

## MCP tools

Avron also provides a standard-input/output MCP server for trusted local MCP clients. Start the Compose services first, then configure the client to launch this command from the repository directory:

```sh
docker compose run --rm --no-deps -T scanner python -m app.mcp_server
```

The tools are `scan_target`, `get_scan_status`, `get_scan_history`, `analyse_findings`, `generate_report`, and `compare_scans`. The scanner and worker must be running. See [API and MCP reference](docs/api-cli.md) for inputs and outputs. Do not expose the stdio server through an unauthenticated network bridge.

## Tests and lint

```sh
python -m venv .venv
python -m pip install -r requirements-test.txt
python -m pytest --cov=app --cov-report=term-missing
ruff check app tests
```

Or run the test image with Docker Compose:

```sh
docker compose --profile test run --build --rm scanner-test
```

## Screenshot

> **Screenshot/GIF placeholder:** Add an Avron API docs view and a redacted sample scan response before publication.

## Responsible use

Use Avron only to test systems you own or have explicit permission to assess. You are responsible for complying with applicable laws, contracts, and service terms. Scans send network traffic to targets and may affect availability. Findings can be incomplete or inaccurate and must be verified before action.

## License

Avron is distributed under the MIT License. See [LICENSE](LICENSE).
