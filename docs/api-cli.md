# API and CLI reference

## REST API

Interactive OpenAPI documentation is available at `/docs`; the schema is at `/openapi.json`.

| Method and path | Authentication | Description |
| --- | --- | --- |
| `GET /health` | None | Liveness and writable scan-directory check. |
| `GET /metrics` | None | Prometheus metrics when `METRICS_ENABLED=true`; otherwise not registered. |
| `POST /scan` | `X-API-KEY` | Validate and queue a target scan. Rate limit: 10 requests per minute per client IP. |
| `GET /scan/{scan_id}` | `X-API-KEY` | Read status and findings. Rate limit: 20 requests per minute per client IP. |

### Submit a scan

```http
POST /scan
X-API-KEY: <SCANNER_API_KEY>
Content-Type: application/json

{"target_url":"https://your-authorized-domain.example"}
```

The response is `202 Accepted` with a `scan_id`, `target`, `status`, `results`, and `error`. Only `http` and `https` URLs are accepted. Targets must resolve exclusively to globally routable addresses at submission and worker execution time.

### Retrieve a scan

```http
GET /scan/<SCAN_ID>
X-API-KEY: <SCANNER_API_KEY>
```

The status is `in_progress`, `completed`, or `failed`. Completed responses include Nuclei findings. Unknown IDs return `404`; missing or incorrect keys return `401`; rate limit violations return `429`.

## MCP tools

Run `python -m app.mcp_server` from an environment configured for the same PostgreSQL database and Redis broker as Avron. The recommended Compose command is:

```sh
docker compose run --rm --no-deps -T scanner python -m app.mcp_server
```

The server uses stdio transport and defines these tools:

| Tool | Inputs | Description |
| --- | --- | --- |
| `scan_target` | `target_url` | Validate and enqueue a scan; returns the scan ID immediately. |
| `get_scan_status` | `scan_id` | Retrieve status and findings for a scan. |
| `get_scan_history` | `target_url`, optional `limit` (default 10) | List recent scans and a simple trend summary. |
| `analyse_findings` | `scan_id` | Enrich completed CVE findings with NVD CVSS and FIRST EPSS data. |
| `generate_report` | `scan_id`, optional `include_enrichment` (default true) | Produce a risk summary and prioritized remediation list. |
| `compare_scans` | `baseline_scan_id`, `current_scan_id` | Compare findings for two completed scans of the same target. |

Enrichment calls external services and may be rate-limited or unavailable. Reports should be treated as decision support; validate findings and remediation guidance independently.

## Developer commands

| Command | Purpose |
| --- | --- |
| `alembic upgrade head` | Apply database migrations. |
| `uvicorn app.main:app --host 127.0.0.1 --port 8000` | Run the REST API locally. |
| `celery -A app.celery_worker worker --loglevel=info --concurrency=2` | Run the background scan worker locally. |
| `python -m app.mcp_server` | Run the MCP stdio server. |
| `python -m pytest --cov=app --cov-report=term-missing` | Run tests and print coverage. |
| `ruff check app tests` | Lint application and test code. |
