# Avron

![Python 3.13](https://img.shields.io/badge/python-3.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-API-009688)
![Release](https://img.shields.io/badge/release-MVP-orange)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Avron is an API-first web security scanner that queues controlled Nuclei scans and returns findings through an authenticated REST API.**

## Features

- Submit a web URL for an asynchronous Nuclei scan and poll for its status and findings.
- Require an API key for scan endpoints and apply per-IP request limits.
- Reject private, reserved, and otherwise non-public target addresses; revalidate DNS before scanning and pin the resolved address.
- Store scan status and findings in PostgreSQL, with Redis and Celery handling background jobs.
- Expose health and Prometheus metrics endpoints.
- Run the application and its dependencies with Docker Compose.

## Quick start

### Requirements

- Docker Engine with the Docker Compose plugin
- A network connection for the initial image and Nuclei build

### Configure and start

Copy the sample configuration, then replace the placeholder values with unique local values. Generate a value with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

```sh
cp .env.example .env
```

In PowerShell, use `Copy-Item .env.example .env` instead. Edit `.env` and set `DB_PASSWORD` and `SCANNER_API_KEY`.

Start the API, worker, PostgreSQL, and Redis:

```sh
docker compose up --build -d
docker compose ps
```

The API is available at <http://localhost:8000>. Interactive API documentation is at <http://localhost:8000/docs>; health is at <http://localhost:8000/health>.

The published API port is bound to loopback for local use. Configure HTTPS and access controls before exposing Avron to a network.

## Usage

Replace the example URL with a target you own or are explicitly authorized to assess. The target must resolve only to globally routable addresses.

Submit a scan:

```sh
curl -X POST http://localhost:8000/scan \
  -H "X-API-KEY: <SCANNER_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://your-authorized-domain.example"}'
```

The response includes a `scan_id`. Poll for status and results:

```sh
curl http://localhost:8000/scan/<SCAN_ID> \
  -H "X-API-KEY: <SCANNER_API_KEY>"
```

For a short overview of the API request and response format, open `/docs` after starting the service.

## Run the tests

The optional test profile builds the test image and runs the unit suite:

```sh
docker compose --profile test run --build --rm scanner-test
```

Stop the services with `docker compose down`. Add `--volumes` only when you also intend to remove the local database and scan data.

## Screenshot

> **Screenshot/GIF placeholder:** Add an Avron API docs view and a redacted sample scan response before publication.

## Disclaimer

Use Avron only to test systems you own or have explicit permission to assess. You are responsible for complying with applicable laws, contracts, and service terms. Scans send network traffic to targets and may affect their availability. Findings can be incomplete or inaccurate and should be verified before taking action.

## License

Avron is distributed under the MIT License. See [LICENSE](LICENSE).
