# tests/test_mcp.py
import json
from unittest.mock import patch
import pytest



# ─── Tool definition tests ────────────────────────────────────────────────────

async def test_mcp_server_has_scan_target_tool():
    """scan_target tool must be registered on the MCP server."""
    from app.mcp_server import mcp
    tool_names = [t.name for t in await mcp.list_tools()]
    assert "scan_target" in tool_names


async def test_mcp_server_has_get_scan_status_tool():
    """get_scan_status tool must be registered on the MCP server."""
    from app.mcp_server import mcp
    tool_names = [t.name for t in await mcp.list_tools()]
    assert "get_scan_status" in tool_names


# ─── scan_target validation tests ────────────────────────────────────────────

async def test_scan_target_rejects_invalid_url():
    """Invalid URLs must return error — never reach the scanner."""
    from app.mcp_server import scan_target
    result   = await scan_target(target_url="not-a-url")
    response = json.loads(result)
    assert "error"  in response
    assert response["error"] == "Invalid URL"


async def test_scan_target_rejects_ftp_scheme():
    """Non-http/https schemes must be rejected."""
    from app.mcp_server import scan_target
    result   = await scan_target(target_url="ftp://example.com")
    response = json.loads(result)
    assert "error" in response


async def test_scan_target_rejects_empty_url():
    """Empty URL must return clear error."""
    from app.mcp_server import scan_target
    result   = await scan_target(target_url="")
    response = json.loads(result)
    assert "error" in response

async def test_scan_target_returns_scan_id_immediately(patched_scan_dir):
    """scan_target must return a scan_id immediately, without waiting for the scan to complete."""
    from app.mcp_server import scan_target

    result = await scan_target(target_url="https://example.com")
    response = json.loads(result)

    assert "scan_id" in response
    assert "error"  not in response
    assert response["status"] == "in_progress"


async def test_scan_target_dispatches_to_shared_celery_queue():
    """MCP submissions must use the same durable worker queue as REST scans."""
    from app.mcp_server import scan_target

    with patch("app.mcp_server.run_scan_task.apply_async") as enqueue:
        result = await scan_target(target_url="https://example.com")

    response = json.loads(result)
    enqueue.assert_called_once_with(
        args=[response["scan_id"], response["target"]],
        task_id=response["scan_id"],
    )


async def test_scan_target_marks_record_failed_when_queue_is_unavailable(
    use_in_memory_storage,
):
    """A broker error should not leave a scan polling forever as in progress."""
    from app.mcp_server import scan_target

    with patch(
        "app.mcp_server.run_scan_task.apply_async",
        side_effect=RuntimeError("broker unavailable"),
    ):
        result = await scan_target(target_url="https://example.com")

    response = json.loads(result)
    assert response["error"]
    assert use_in_memory_storage[response["scan_id"]]["status"] == "failed"


async def test_scan_target_returns_immediately_not_after_polling(patched_scan_dir):
    """scan_target must not block - it must return before the scan finishes, even if we poll for status."""
    import time
    from app.mcp_server import scan_target

    # with patch ("app.mcp_server.asyncio.ensure_future"):
    #     start_time = time.time()
    #     result     = await scan_target(target_url="https://example.com")
    #     end_time   = time.time() - start_time

    # # Must return in well under 1 second - not after polling for status which can take several seconds.
    # assert end_time < 2.0, f"scan_target took too long to return: {end_time:.2f} seconds - should return immediately, not after polling for status"

    start_time = time.time()
    result = await scan_target(target_url="https://example.com")
    end_time = time.time() - start_time

    assert end_time < 1.0, f"scan_target took too long to return: {end_time:.1f} seconds - should return immediately, not after polling for status"
    response = json.loads(result)
    assert response["status"] == "in_progress"


# ─── get_scan_status tests ────────────────────────────────────────────────────

async def test_get_scan_status_unknown_id_returns_not_found(patched_scan_dir):
    """Unknown scan_id must return error — not crash."""
    from app.mcp_server import get_scan_status
    result   = await get_scan_status(scan_id="nonexistent-id")
    response = json.loads(result)
    assert "error"   in response
    assert "not found" in response["error"].lower()


async def test_get_scan_status_returns_correct_data(patched_scan_dir, use_in_memory_storage):
    """get_scan_status must return all fields for an existing scan."""
    from app.mcp_server import get_scan_status

    # Seed directly into the in_memory_storage to avoid waiting for an actual scan to complete.
    use_in_memory_storage["mcp-test-scan"] = {
        "scan_id":   "mcp-test-scan",
        "target":    "https://example.com",
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   [{"template-id": "CVE-2024-0001", "severity": "critical"}]
    }

    result   = await get_scan_status(scan_id="mcp-test-scan")
    response = json.loads(result)

    assert response["scan_id"]        == "mcp-test-scan"
    assert response["status"]         == "completed"
    assert response["findings_count"] == 1
    assert response["findings"][0]["severity"] == "critical"


async def test_get_scan_status_empty_scan_id():
    """Calling with empty scan_id must return clear error."""
    from app.mcp_server import get_scan_status
    result   = await get_scan_status(scan_id="")
    response = json.loads(result)
    assert "error" in response


async def test_get_scan_status_response_is_valid_json(patched_scan_dir):
    """Every response from get_scan_status must be valid JSON."""
    from app.mcp_server import get_scan_status
    result = await get_scan_status(scan_id="any-id")
    try:
        json.loads(result)
    except json.JSONDecodeError:
        pytest.fail("get_scan_status returned invalid JSON")

async def test_get_scan_status_in_progress_suggest_polling(patched_scan_dir, use_in_memory_storage):
    """If scan is in progress, get_scan_status should suggest polling again later.
    /rather tell claude to keep polling until it's done, instead of giving up immediately."""

    from app.mcp_server import get_scan_status

    use_in_memory_storage["polling-test"] = {
        "scan_id":   "polling-test",
        "target":    "https://example.com",
        "status":    "in_progress",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   []
    }

    result = await get_scan_status(scan_id="polling-test")
    response = json.loads(result)

    assert response["status"] == "in_progress"
    assert "poll" in response["message"].lower() or "try again later" in response["message"].lower()
    assert "30 seconds" in response["message"].lower() or "few seconds" in response["message"].lower()


async def test_get_scan_status_completed_includes_findings(patched_scan_dir, use_in_memory_storage):
    """If scan is completed, get_scan_status should include findings in the response."""

    from app.mcp_server import get_scan_status

    # Seed directly into the in_memory_storage to avoid waiting for an actual scan to complete.
    use_in_memory_storage["completed-mcp"] = {
        "scan_id":   "completed-mcp",
        "target":    "https://example.com",
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   [{"template-id": "CVE-2024-0001", "severity": "critical"}]
    }

    result = await get_scan_status(scan_id="completed-mcp")
    response = json.loads(result)

    assert response["status"] == "completed"
    assert response["findings_count"] == 1
    assert "findings" in response
    assert "message" in response

async def test_get_scan_status_failed_scan_preserves_error_message(patched_scan_dir, use_in_memory_storage):
    """If scan failed, get_scan_status should include the error message in the response."""

    from app.mcp_server import get_scan_status

    # Seed directly into the in_memory_storage to avoid waiting for an actual scan to complete.
    use_in_memory_storage["mcp-failed-mcp"] = {
        "scan_id":   "mcp-failed-mcp",
        "target":    "https://example.com",
        "status":    "failed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     "Scanner crashed due to unexpected input.",
        "results":   []
    }

    result = await get_scan_status(scan_id="mcp-failed-mcp")
    response = json.loads(result)

    assert response["status"] == "failed"
    assert response["findings_count"] == 0
    assert "timed out" in response["error"].lower() or "crashed" in response["error"].lower() or "unexpected input" in response["error"].lower()
