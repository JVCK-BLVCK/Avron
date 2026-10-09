"""
Test configuration and fixtures for Avron.
 
Fixture design principles:
  - autouse fixtures apply globally so individual tests stay focused on assertions
  - patched_scan_dir isolates every file operation to a temp directory
  - prevent_real_nuclei_execution patches Celery dispatch so unit tests never
    start a real scan
"""

import os
import json
import socket

import pytest 
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock

# Set a test API key in the evironment variable before any tests run, 
# so that the authentication dependency can retrieve it during tests.
# This ensures that the auth mechanism is tested with a known valid key 
# and that tests don't fail due to missing configuration.

os.environ["SCANNER_API_KEY"] = "test-api-key-12345" 
os.environ["TESTING"] = "true"  # ← enables NullPool in database.py

@pytest.fixture(autouse=True)
def mock_dns_for_ssrf_check():
    """
    Mocks socket.getaddrinfo to return a public IP for any hostname.
    This ensures that _is_safe_host always returns True during tests, 
    allowing tests to focus on other logic without being blocked by SSRF checks.

        Why this is needed:
        _public_addresses() makes a live DNS call to check that a public-looking
        hostname doesn't secretly resolve to a private IP. Inside the test
        container (no internet), every external DNS lookup raises gaierror.
        _public_addresses treats gaierror as "unsafe" and returns an empty list, causing
        the validator to reject legitimate URLs like sub.example.com.

    Why this is safe:
        The SSRF tests (192.168.1.1, 127.0.0.1, 169.254.169.254) all use
        IP literals. They are classified directly by ipaddress without a DNS
        query, so this mock does not change those test results.
        Mocking DNS does not affect those tests at all.

    What the mock does:
        Returns a known public IP (93.184.216.34 = example.com) for any
        hostname that isn't explicitly private. This simulates what a real
        DNS server would return for public domains.
    """
    ALWAYS_PRIVATE = {
        "localhost",
        "ip6-localhost",
        "ip6-loopback",
        "broadcasthost"
    }

    def _fake_getaddrinfo(hostname: str, *args, **kwargs):
        if hostname in ALWAYS_PRIVATE:
            address = "127.0.0.1"
        else:
            address = "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))]

    with patch("app.models._lookup_hostname", side_effect=_fake_getaddrinfo):
        yield

# ___In_Memory storage for API tests___
# 
# API tests prove HTTP routing, response shape, auth, and rate limiting.
# They do not prove database persistence — that's storage_db's test domain.
# Using in-memory storage here:
#   - eliminates database dependency from API tests
#   - makes tests deterministic regardless of database state
#   - keeps tests fast (no network I/O)

_scan_storage: dict = {}

async def _mock_save_scan(scan_id: str, scan_data: dict) -> None:
    """Mock save_scan that stores scan data in an in-memory dictionary."""
    _scan_storage[scan_id] = scan_data

async def _mock_load_scan(scan_id: str):
    """Mock load_scan that retrieves scan data from the in-memory dictionary."""
    return _scan_storage.get(scan_id)

@pytest.fixture(autouse=True)
def use_in_memory_storage():
    """
    Automatically patch save_scan and load_scan to use in-memory storage for all tests.
    Replaces the real file-based storage functions with mocks that store and retrieve scan data from a Python dictionary.
    """
    _scan_storage.clear()  # Clear storage before each test to ensure isolation

    save_mock = AsyncMock(side_effect=_mock_save_scan)
    load_mock = AsyncMock(side_effect=_mock_load_scan)

    with patch("app.main.save_scan",                       new=save_mock), \
         patch("app.main.load_scan",                       new=load_mock), \
         patch("app.storage_db.save_scan",                 new=save_mock), \
         patch("app.storage_db.load_scan",                 new=load_mock):
        
        yield _scan_storage

# ─── Nuclei execution prevention ─────────────────────────────────────────────

@pytest.fixture(autouse=True)
def prevent_real_nuclei_execution():
    """Prevent API tests from submitting tasks to a real Redis broker."""
    from app.celery_worker import run_scan_task

    with patch.object(run_scan_task, "apply_async", return_value=MagicMock()), \
         patch.object(run_scan_task, "delay", return_value=MagicMock(), create=True):  # Prevent real Celery dispatch
        
        yield


# ___Rate limter isolation___

@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    Disable rate limiting for test by default.
    
    All tests share the same client IP so without this,
    10 POST requests anywhere in the suite exhausts 
    the limit and all subsequent POSTs get 429s, which is not what we want for most tests.

    Rate imit tests explicitly re-enable  via with_rate_limiting fixture.

    """
    from app.rate_limiter import limiter
    limiter.enabled = False 
    yield
    limiter.enabled = True 


@pytest.fixture
def with_rate_limiting():
    """
    Explicitly enable rate limiting for tests that need to verify it, 
    since it's disabled by default for most tests by the reset_rate_limiter fixture.
    Usage: Add with_rate_limiting as a parameter to any test that needs to verify rate limiting behavior,
    and it will enable the limiter for the duration of that test, 
    allowing you to test that 429 responses are returned when limits are exceeded.

    used only by rate limit specific tests.

    """
    from app.rate_limiter import limiter
    limiter.enabled = True
    yield 
    limiter.enabled = False


# ___Storage isolation___

@pytest.fixture
def temp_scan_dir(tmp_path):
    """Fixture to create a temporary scans directory for testing."""
    scan_dir = tmp_path / "scans"
    scan_dir.mkdir()
    return scan_dir


@pytest.fixture
def patched_scan_dir(temp_scan_dir, monkeypatch):
    """Fixture to patch the SCAN_DIR in storage module to use the temporary directory."""
    """Redirects storage.SCAN_DIR to the temporary directory created by temp_scan_dir fixture, 
    ensuring that all file operations during tests are isolated and do not affect the real filesystem."""
    import app.storage as storage
    monkeypatch.setattr(storage, "SCAN_DIR", temp_scan_dir)
    return temp_scan_dir


@pytest.fixture
def mock_nuclei_success():
    """Fixture to mock subprocess.run() for a successful Nuclei scan."""
    # This is the finding Nuclei would write to the output file
    sample_finding = {
        "template_id": "CVE-2021-44228",
        "name": "Log4Shell RCE",
        "severity": "critical",
        "host": "https://vulnerable.com",
        "matched_at": "https://vulnerable.com/api/login"
        }
    
    with patch("app.scanner.subprocess.run") as mock_run:
        # Mock the behavior of subprocess.run() to write the sample finding to the expected output file
        # Make subprocess.run return a successful mock result.
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # patch the file reading in scanner to simulate output 
        # We patch path.exists to return True and built-in open to return our sample finding as file content
        with patch("app.scanner.Path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                # Simulate the content of the output file as a JSONL line with our sample finding
                mock_open.return_value.__enter__.return_value = [json.dumps(sample_finding) + "\n"]
                yield {
                    "sample_finding": sample_finding,
                    "mock_run": mock_run,
                    "mock_open": mock_open
                }


@pytest.fixture
def mock_nuclei_timeout():
    """Fixture to mock subprocess.run() for a Nuclei scan that times out."""
    import subprocess
    with patch("app.scanner.subprocess.run") as mock_run:
        # Simulate a timeout by having subprocess.run raise a TimeoutExpired exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=300)
        yield mock_run


# ___HTTP test client___

@pytest.fixture
def client():
    """
    Provides a TestClient wired to an Isolated storage directory and auth headers.
    patched_scan_dir ensures every HTTP request that touches storage
    writes to the temp directory, not the real filesystem.
    """
    from app.main import app
    with TestClient(
        app,
        headers={"X-API-KEY": "test-api-key-12345"}
    ) as test_client:
        yield test_client
    

# ___Sample data fixtures___

@pytest.fixture
def sample_scan_data():
    """Returns a dictionary with sample scan metadata and results that can be used in tests to verify correct handling of scan data."""
    return {
        "scan_id": "test-scan-123",
        "target": "https://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": None,
        "results": [
            {
                "template_id": "CVE-2021-44228",
                "name": "Log4Shell RCE",
                "severity": "critical",
                "host": "https://example.com",
                "matched_at": "https://example.com/api/login"
            },
            {
                "template_id": "CVE-2020-1472",
                "name": "Log4Shell RCE",
                "severity": "critical",
                "host": "https://example.com",
                "matched_at": "https://example.com/api/login"
            }
        ]
    }


@pytest.fixture
def sample_empty_scan_data():
    """Returns a valid completed scan with zero findings - a common real world 
    scenario that we need to ensure is handled correctly."""
    return {
        "scan_id": "test-scan-empty-456",
        "target": "https://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": None,
        "results": []
    }


@pytest.fixture
def sample_failed_scan_data():
    """Returns a dictionary with sample scan metadata indicating a failed scan, useful for testing error handling and status reporting."""
    return {
        "scan_id": "test-scan-failed-789",
        "target": "https://example.com",
        "status": "failed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": "Nuclei scan timed out after 5 minutes",
        "results": []
    }


