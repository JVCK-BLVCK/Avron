# Troubleshooting

## Compose does not start

- Run `docker compose config` to validate interpolation and YAML.
- Confirm Docker Engine is running and ports 8000, 5432, and 6379 are free.
- Check `docker compose ps` and `docker compose logs postgres migrate scanner worker` for the first failing service.
- Set non-placeholder `DB_PASSWORD` and `SCANNER_API_KEY` values in `.env`.

## API reports unhealthy or database errors

- `/health` checks that the scan directory exists and is writable; it does not verify PostgreSQL or Redis.
- Confirm PostgreSQL is healthy and the migration service completed: `docker compose ps`.
- If running Python outside Compose, set full `DATABASE_URL` and `DATABASE_URL_SYNC` strings with valid credentials. Container hostnames such as `postgres` work only inside the Compose network.

## Scan stays in progress

- Check `docker compose logs -f worker redis` and confirm the Celery worker is connected to the broker.
- Verify the worker can reach PostgreSQL and Nuclei is installed in its image.
- A scan is bounded by `SCAN_TIMEOUT_SECONDS`; a timeout or Nuclei error is stored as `failed` with an error message.
- If Redis or the worker was unavailable when a request was accepted, check API logs and the scan record for queueing errors.

## Target URL is rejected

- Use a fully qualified `http://` or `https://` URL without embedded credentials.
- Avron rejects private/reserved IP ranges and hostnames that resolve to any non-global address. This is intentional SSRF protection.
- If DNS answers changed, wait for DNS to stabilize and resubmit. The worker validates DNS again before connecting.

## Nuclei cannot scan

- Review worker logs for `Nuclei not found`, scan timeouts, or template errors.
- The Docker build installs the pinned Nuclei binary. For local runs, install the same version and ensure it is on `PATH`.
- The scanner intentionally disables redirects and excludes selected high-impact template categories. Review scanner policy before changing those defaults.

## Enrichment is missing or slow

- Enrichment applies only to CVE template findings and depends on NVD and FIRST EPSS APIs.
- `NVD_API_KEY` is optional; without it, NVD rate limits are lower. A network outage or rate limit can leave enrichment fields empty while original findings remain available.
- Use `generate_report(..., include_enrichment=false)` for a report without external lookups.

## `/metrics` returns 404

Set `METRICS_ENABLED=true` and restart the API. The endpoint is intentionally absent when metrics are disabled.

## Tests fail while connecting to external services

The unit suite mocks DNS, scan execution, and storage boundaries; it should not need Docker, PostgreSQL, Redis, live NVD/EPSS services, or a real target. Check that tests are run with the pinned packages in `requirements-test.txt` and that no local plugin or pytest option bypasses the fixtures.
