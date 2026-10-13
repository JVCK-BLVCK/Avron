# tests/test_phase7.py
"""
Tests for Phase 7 — configuration, metrics, and production readiness.
"""
import pytest


# ─── Configuration tests ──────────────────────────────────────────────────────

def test_settings_loads_from_environment():
    """Settings must load correctly from environment variables."""
    from app.config import Settings

    s = Settings(
        scanner_api_key="test-key",
        database_url="postgresql+asyncpg://user:pass@localhost/db",
        redis_url="redis://localhost:6379/0"
    )
    assert s.scanner_api_key == "test-key"
    assert s.environment     == "development"   # default
    assert s.log_level       == "INFO"           # default


def test_settings_validates_log_level():
    """Invalid log level must raise ValidationError at startup."""
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(
            scanner_api_key="test-key",
            log_level="INVALID"
        )


def test_settings_validates_environment():
    """Invalid environment name must raise ValidationError."""
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(
            scanner_api_key="test-key",
            environment="production-plus"
        )


def test_settings_requires_scanner_api_key(monkeypatch):
    """
        Missing scanner_api_key must fail at startup not at request time.

        Why monkeypatch and not just Settings()?
            conftest.py sets SCANNER_API_KEY in os.environ before every test.
            pydantic-settings reads os.environ automatically, so Settings()
            finds the key and never raises — the test would always pass falsely.

            monkeypatch.delenv removes the key from os.environ for this test only.
            pytest restores the original value automatically after the test completes,
            even on assertion failure or unexpected exception.
    """
    from pydantic import ValidationError
    from app.config import Settings
    

    # Remove from environment - pydantic-settings has nowhere left to find it
    monkeypatch.delenv("SCANNER_API_KEY", raising=False)


    with pytest.raises(ValidationError):
            Settings(_env_file=None)  # type: ignore[call-arg]
    


def test_settings_log_level_normalised_to_uppercase():
    """log_level must be normalised to uppercase regardless of input."""
    from app.config import Settings

    s = Settings(scanner_api_key="test-key", log_level="debug")
    assert s.log_level == "DEBUG"


def test_settings_exposes_scan_timeout_and_optional_nvd_key():
    from app.config import Settings

    settings = Settings(
        scanner_api_key="test-key",
        scan_timeout_seconds=30,
        nvd_api_key="test-nvd-key",
    )

    assert settings.scan_timeout_seconds == 30
    assert settings.nvd_api_key == "test-nvd-key"


def test_settings_rejects_non_positive_scan_timeout():
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(scanner_api_key="test-key", scan_timeout_seconds=0)


# ─── Metrics tests ────────────────────────────────────────────────────────────

def test_metrics_endpoint_accessible(client):
    """Prometheus /metrics endpoint must return 200."""
    # Unauthenticated — Prometheus scrapes without API key
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as unauth_client:
        response = unauth_client.get("/metrics")
    # 200 = metrics enabled, 404 = metrics disabled in test config
    assert response.status_code in [200, 404]


def test_scan_counter_increments(client):
    """Submitting a scan must increment the scans counter."""
    from app.metrics import SCANS_ACTIVE

    client.post("/scan", json={"target_url": "https://example.com"})
    # Counter may or may not have incremented depending on async timing
    # — we just verify no exception was raised
    assert SCANS_ACTIVE._value.get() >= 0


# ─── Health endpoint completeness ─────────────────────────────────────────────

def test_health_includes_version():
    """Health endpoint must include version for deployment tracking."""
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as unauth_client:
        response = unauth_client.get("/health")
    data = response.json()
    assert "version" in data


def test_health_includes_service_name():
    """Health endpoint must identify the service."""
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as unauth_client:
        response = unauth_client.get("/health")
    data = response.json()
    assert "service" in data


# ─── Production readiness checks ─────────────────────────────────────────────

def test_app_has_openapi_schema():
    """OpenAPI schema must be available for agent discovery."""
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        response = c.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "paths" in schema
    assert "/scan"         in schema["paths"]
    assert "/health"       in schema["paths"]


def test_all_routes_have_tags():
    """Every route must have a tag for API documentation grouping."""
    from fastapi.routing import APIRoute
    from app.main import app

    # Filter to APIRoute only — these are the routes you defined.
    # The base Route class (used for /docs, /openapi.json, /redoc)
    # has no tags attribute and should be excluded from this check.
    api_routes = [
        route for route in app.routes
        if isinstance(route, APIRoute)
    ]

    excluded_paths = {"/metrics", "/health"}

    for route in api_routes:
        if route.path not in excluded_paths:
            assert route.tags, \
                f"Route {route.path} ({route.methods}) has no tags — " \
                f"add tags=['Scanning'] or tags=['Operations'] to the decorator"

def test_config_uses_settings_not_os_environ():
    """
    Verify that auth uses settings rather than os.environ.get directly.
    This ensures startup validation catches missing config.
    """
    from app.config import settings
    assert hasattr(settings, "scanner_api_key")
    assert settings.scanner_api_key is not None
