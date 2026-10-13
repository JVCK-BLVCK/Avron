# Configuration reference

Avron reads settings from process environment variables and, for local Python runs, an optional `.env` file in the working directory. Environment variable names are case-insensitive. Docker Compose reads `.env` for interpolation and passes service settings to containers.

| Setting | Required | Default | Purpose |
| --- | --- | --- | --- |
| `SCANNER_API_KEY` | Yes for API startup | — | Shared API key for `POST /scan` and `GET /scan/{scan_id}`. Use a long random value. |
| `DB_USERNAME` | Compose | `avron` | PostgreSQL user/database name used by Compose. |
| `DB_PASSWORD` | Compose | — | PostgreSQL password used by Compose. Required by Compose interpolation. |
| `DATABASE_URL` | For local Python deployments | `postgresql+asyncpg://localhost:5432/avron` | Async SQLAlchemy connection string. Compose sets this for API and worker. |
| `DATABASE_URL_SYNC` | For local Python deployments | `postgresql+psycopg2://localhost:5432/avron` | Synchronous PostgreSQL connection string used by migrations and the worker. |
| `REDIS_URL` | No | `redis://localhost:6379/0` | Celery broker and result backend. Compose uses its Redis service. |
| `NVD_API_KEY` | No | Empty | Optional NVD API key for CVE enrichment request limits. EPSS data comes from FIRST.org. |
| `SCAN_TIMEOUT_SECONDS` | No | `600` | Maximum scan duration enforced by the scanner process. |
| `METRICS_ENABLED` | No | `true` | Exposes Prometheus metrics at `/metrics` when true. |
| `SCAN_DIR` | No | Application `scans/` directory | Optional absolute writable path checked by `/health`; relative paths are rejected. |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `ENVIRONMENT` | No | `development` | `development`, `staging`, or `production`; validated at startup. |
| `TESTING` | No | `false` | Enables test-specific database behavior. Set only in tests. |

The `.env.example` file contains placeholders, not usable credentials. Replace all required values locally. Never commit `.env`, database URLs containing passwords, API keys, or production environment files.

When running outside Compose, set complete database URLs; Pydantic does not expand `${DB_USERNAME}` or `${DB_PASSWORD}` inside a URL string. For example, set `DATABASE_URL=postgresql+asyncpg://avron:<password>@127.0.0.1:5432/avron` and `DATABASE_URL_SYNC=postgresql+psycopg2://avron:<password>@127.0.0.1:5432/avron`.
